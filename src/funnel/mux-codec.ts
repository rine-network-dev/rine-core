// Binary MUX wire codec for the control WebSocket (REQ-TUN-05/06/07), the relay
// (client) side of the Rust broker's codec. It MUST match broker/src/mux.rs
// byte-for-byte — the test vectors here are the same vectors as
// broker/tests/mux_codec.rs.
//
//   Frame: [type:u8][conn_id:u32 BE][len:u32 BE][payload:len]   (header = 9 bytes)
//   OPEN=0x01 DATA=0x02 CLOSE=0x03 RESET=0x04 BIND=0x10 BIND_ACK=0x11 BIND_NAK=0x12
//   WINDOW=0x07 is RESERVED (v2 flow control) — a v1 receiver rejects it as
//   unknown, and the relay can never ENCODE it (the type table has no entry).
//   conn_id=0 is the control plane (BIND*); data frames use conn_id>=1.

/** Fixed mux header size: type(1) + conn_id(4) + len(4). */
export const HEADER_LEN = 9;

/** conn_id 0 is reserved for the control plane (BIND and keepalive). */
export const CONTROL_CONN_ID = 0;

/** Frame type discriminants. WINDOW (0x07) is intentionally absent. */
export const FrameType = {
	OPEN: 0x01,
	DATA: 0x02,
	CLOSE: 0x03,
	RESET: 0x04,
	BIND: 0x10,
	BIND_ACK: 0x11,
	BIND_NAK: 0x12,
} as const;

export type FrameType = (typeof FrameType)[keyof typeof FrameType];

const KNOWN_TYPES: ReadonlySet<number> = new Set(Object.values(FrameType));

function isControl(t: number): boolean {
	return (
		t === FrameType.BIND || t === FrameType.BIND_ACK || t === FrameType.BIND_NAK
	);
}

export interface Frame {
	frameType: FrameType;
	connId: number;
	payload: Uint8Array;
}

/** A framing/protocol fault. The broker maps these to WS close codes (1002/1009). */
export class FrameError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "FrameError";
	}
}

/**
 * Encode a frame into one WS-binary message body. Rejects an over-`maxFrameBytes`
 * payload and any type the codec does not know (so the relay can never put a
 * WINDOW/0x07 frame on the wire) before allocating.
 */
export function encodeFrame(frame: Frame, maxFrameBytes: number): Uint8Array {
	if (!KNOWN_TYPES.has(frame.frameType)) {
		throw new FrameError(
			`refusing to encode unknown frame type 0x${frame.frameType.toString(16)}`,
		);
	}
	const len = frame.payload.length;
	if (len > maxFrameBytes) {
		throw new FrameError(
			`frame payload ${len} exceeds max_frame_bytes ${maxFrameBytes}`,
		);
	}
	const out = new Uint8Array(HEADER_LEN + len);
	const view = new DataView(out.buffer);
	out[0] = frame.frameType;
	view.setUint32(1, frame.connId, false); // big-endian
	view.setUint32(5, len, false); // big-endian
	out.set(frame.payload, HEADER_LEN);
	return out;
}

/**
 * Decode one WS-binary message body into a Frame, enforcing every REQ-TUN-05
 * rule: unknown/reserved type (incl. WINDOW 0x07), short header, declared-len
 * mismatch, conn_id=0 on a data frame, non-zero conn_id on a control frame, and
 * an over-`maxFrameBytes` payload.
 */
export function decodeFrame(buf: Uint8Array, maxFrameBytes: number): Frame {
	if (buf.length < HEADER_LEN) {
		throw new FrameError(
			`frame shorter than ${HEADER_LEN}-byte header: ${buf.length} bytes`,
		);
	}
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	const typeByte = buf[0] as number;
	if (!KNOWN_TYPES.has(typeByte)) {
		throw new FrameError(`unknown frame type byte: 0x${typeByte.toString(16)}`);
	}
	const frameType = typeByte as FrameType;
	const connId = view.getUint32(1, false);
	const declared = view.getUint32(5, false);

	const body = buf.subarray(HEADER_LEN);
	if (declared !== body.length) {
		throw new FrameError(
			`declared len ${declared} != actual payload ${body.length}`,
		);
	}
	if (isControl(frameType)) {
		if (connId !== CONTROL_CONN_ID) {
			throw new FrameError(`control frame must use conn_id=0, got ${connId}`);
		}
	} else if (connId === CONTROL_CONN_ID) {
		throw new FrameError(
			"conn_id=0 reserved for control plane, not valid on a data-plane frame",
		);
	}
	if (body.length > maxFrameBytes) {
		throw new FrameError(
			`frame payload ${body.length} exceeds max_frame_bytes ${maxFrameBytes}`,
		);
	}
	return { frameType, connId, payload: body.slice() };
}
