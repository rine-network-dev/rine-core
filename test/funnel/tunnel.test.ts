// The mux WebSocket client living
// in rine-core `src/funnel/tunnel.ts`. The relay is the mux CLIENT; the Rust
// broker is the server. The wire codec MUST match the broker byte-for-byte:
// the test vectors below are the SAME vectors as broker/tests/mux_codec.rs.
//
//   Frame: [type:u8][conn_id:u32 BE][len:u32 BE][payload:len]  (header = 9 bytes)
//   OPEN=0x01 DATA=0x02 CLOSE=0x03 RESET=0x04 BIND=0x10 BIND_ACK=0x11 BIND_NAK=0x12
//   WINDOW=0x07 is RESERVED (v2) — a v1 receiver MUST reject it as unknown.
//   conn_id=0 is the control plane (BIND*/keepalive); data frames use conn_id>=1.
//
// FROZEN-CONTRACT: the relay client SENDS no WINDOW frame; backpressure is the
// per-conn 256 KiB in-flight cap (pause-on-cap). On WS drop the client RESETs
// all conns and reconnects (backoff+jitter capped 30s) — no Last-Event-ID/resume.
//
// All externals are MOCKED — there is NO real WebSocket and NO real broker. The
// module under test does NOT exist yet (Track E creates it); these MUST fail now
// for the right reason (missing module / missing export).

import { describe, expect, it } from "vitest";
// Module under test — does NOT exist yet.
import {
	CONTROL_CONN_ID,
	FrameType,
	HEADER_LEN,
	decodeFrame,
	encodeFrame,
} from "../../src/funnel/tunnel.js";

const MAX_FRAME = 65_536;

/** Hand-build a wire frame (decode tests stay independent of encode). */
function wire(
	typeByte: number,
	connId: number,
	declaredLen: number,
	payload: Uint8Array,
): Uint8Array {
	const out = new Uint8Array(HEADER_LEN + payload.length);
	const view = new DataView(out.buffer);
	out[0] = typeByte;
	view.setUint32(1, connId, false); // big-endian
	view.setUint32(5, declaredLen, false); // big-endian
	out.set(payload, HEADER_LEN);
	return out;
}

// ── Wire codec, byte-for-byte vs the broker ─────────────────────

describe("mux codec — wire layout (matches broker/tests/mux_codec.rs)", () => {
	it("fixed header is nine bytes", () => {
		expect(HEADER_LEN).toBe(9);
	});

	it("type bytes match the spec table exactly", () => {
		expect(FrameType.OPEN).toBe(0x01);
		expect(FrameType.DATA).toBe(0x02);
		expect(FrameType.CLOSE).toBe(0x03);
		expect(FrameType.RESET).toBe(0x04);
		expect(FrameType.BIND).toBe(0x10);
		expect(FrameType.BIND_ACK).toBe(0x11);
		expect(FrameType.BIND_NAK).toBe(0x12);
	});

	it("encode uses big-endian for conn_id and len (broker vector)", () => {
		// conn_id = 0x01020304, payload "ab" (len 2) — identical to the Rust test.
		const bytes = encodeFrame(
			{
				frameType: FrameType.DATA,
				connId: 0x0102_0304,
				payload: new TextEncoder().encode("ab"),
			},
			MAX_FRAME,
		);
		expect(bytes[0]).toBe(0x02); // type
		expect(Array.from(bytes.slice(1, 5))).toEqual([0x01, 0x02, 0x03, 0x04]); // conn_id BE
		expect(Array.from(bytes.slice(5, 9))).toEqual([0x00, 0x00, 0x00, 0x02]); // len BE
		expect(new TextDecoder().decode(bytes.slice(9))).toBe("ab");
	});

	it("a data frame round-trips through encode→decode (broker vector)", () => {
		const payload = new TextEncoder().encode("\x16\x03\x01opaque-tls-records");
		const bytes = encodeFrame(
			{ frameType: FrameType.DATA, connId: 7, payload },
			MAX_FRAME,
		);
		const decoded = decodeFrame(bytes, MAX_FRAME);
		expect(decoded.frameType).toBe(FrameType.DATA);
		expect(decoded.connId).toBe(7);
		expect(new TextDecoder().decode(decoded.payload)).toBe(
			"\x16\x03\x01opaque-tls-records",
		);
	});

	it("a control frame round-trips with conn_id=0", () => {
		const bytes = encodeFrame(
			{
				frameType: FrameType.BIND,
				connId: CONTROL_CONN_ID,
				payload: new TextEncoder().encode('{"v":1}'),
			},
			MAX_FRAME,
		);
		const decoded = decodeFrame(bytes, MAX_FRAME);
		expect(decoded.connId).toBe(CONTROL_CONN_ID);
		expect(decoded.frameType).toBe(FrameType.BIND);
	});

	it("an empty control payload round-trips with len=0", () => {
		const bytes = encodeFrame(
			{ frameType: FrameType.BIND_ACK, connId: 0, payload: new Uint8Array(0) },
			MAX_FRAME,
		);
		expect(Array.from(bytes.slice(5, 9))).toEqual([0, 0, 0, 0]);
		const decoded = decodeFrame(bytes, MAX_FRAME);
		expect(decoded.payload.length).toBe(0);
	});

	it("a payload exactly at max is accepted (boundary)", () => {
		const bytes = encodeFrame(
			{ frameType: FrameType.DATA, connId: 1, payload: new Uint8Array(16) },
			16,
		);
		const decoded = decodeFrame(bytes, 16);
		expect(decoded.payload.length).toBe(16);
	});
});

describe("mux codec — decode rejections", () => {
	it("rejects an unknown type byte", () => {
		expect(() =>
			decodeFrame(wire(0x99, 1, 0, new Uint8Array(0)), MAX_FRAME),
		).toThrow();
	});

	it("rejects the reserved WINDOW (0x07) frame as unknown", () => {
		expect(() =>
			decodeFrame(wire(0x07, 1, 0, new Uint8Array(0)), MAX_FRAME),
		).toThrow();
	});

	it("rejects conn_id=0 on every data-plane frame type", () => {
		for (const t of [0x01, 0x02, 0x03, 0x04]) {
			expect(() =>
				decodeFrame(wire(t, 0, 0, new Uint8Array(0)), MAX_FRAME),
			).toThrow();
		}
	});

	it("rejects a non-zero conn_id on a control frame", () => {
		expect(() =>
			decodeFrame(wire(0x10, 5, 0, new Uint8Array(0)), MAX_FRAME),
		).toThrow();
	});

	it("rejects a declared len that does not match the body length", () => {
		expect(() =>
			decodeFrame(wire(0x02, 1, 10, new TextEncoder().encode("ab")), MAX_FRAME),
		).toThrow();
	});

	it("rejects a body shorter than the 9-byte header", () => {
		expect(() =>
			decodeFrame(new Uint8Array([0x02, 0x00, 0x00]), MAX_FRAME),
		).toThrow();
	});

	it("rejects an over-max payload on decode and on encode", () => {
		const big = new Uint8Array(17);
		expect(() => decodeFrame(wire(0x02, 1, 17, big), 16)).toThrow();
		expect(() =>
			encodeFrame({ frameType: FrameType.DATA, connId: 1, payload: big }, 16),
		).toThrow();
	});

	it("NEVER produces a WINDOW (0x07) frame on the wire (relay sends none)", () => {
		// The relay client must not even be able to encode a 0x07 frame.
		expect(() =>
			encodeFrame(
				{ frameType: 0x07 as FrameType, connId: 1, payload: new Uint8Array(0) },
				MAX_FRAME,
			),
		).toThrow();
	});
});

// ── Control-frame JSON payloads (BIND / BIND_ACK / BIND_NAK) ────

describe("mux control payloads — BIND/BIND_ACK/BIND_NAK", () => {
	it("encodes a BIND frame whose JSON payload is {v,agent_id,hostname}", () => {
		const bind = {
			frameType: FrameType.BIND,
			connId: 0,
			payload: new TextEncoder().encode(
				JSON.stringify({
					v: 1,
					agent_id: "11111111-1111-1111-1111-111111111111",
					hostname: "github--bot.hook.rine.network",
				}),
			),
		};
		const bytes = encodeFrame(bind, MAX_FRAME);
		const decoded = decodeFrame(bytes, MAX_FRAME);
		const json = JSON.parse(new TextDecoder().decode(decoded.payload));
		expect(json).toEqual({
			v: 1,
			agent_id: "11111111-1111-1111-1111-111111111111",
			hostname: "github--bot.hook.rine.network",
		});
	});

	it("decodes a BIND_ACK caps payload from the broker", () => {
		const caps = {
			caps: {
				max_conns: 32,
				per_conn_inflight_bytes: 262144,
				max_frame_bytes: 65536,
				heartbeat_secs: 30,
			},
		};
		const bytes = wire(0x11, 0, 0, new Uint8Array(0));
		// (Shape proof: the relay must parse this JSON from a BIND_ACK frame.)
		const ackFrame = encodeFrame(
			{
				frameType: FrameType.BIND_ACK,
				connId: 0,
				payload: new TextEncoder().encode(JSON.stringify(caps)),
			},
			MAX_FRAME,
		);
		const decoded = decodeFrame(ackFrame, MAX_FRAME);
		expect(
			JSON.parse(new TextDecoder().decode(decoded.payload)).caps
				.per_conn_inflight_bytes,
		).toBe(262144);
		expect(bytes[0]).toBe(0x11);
	});
});

// ── Client driver (OPEN→pipe→DATA→teardown, reconnect) ───────

describe("mux client driver — connection multiplexing", () => {
	function makeFakeWs() {
		const sent: Uint8Array[] = [];
		let onMessage: ((data: Uint8Array) => void) | undefined;
		return {
			sent,
			send: (data: Uint8Array) => {
				sent.push(data);
			},
			onBinary: (cb: (data: Uint8Array) => void) => {
				onMessage = cb;
			},
			deliver: (data: Uint8Array) => onMessage?.(data),
			close: () => {},
		};
	}

	it("on OPEN it opens a local pipe and forwards broker DATA into it", async () => {
		const { createMuxClient } = await import("../../src/funnel/tunnel.js");
		const ws = makeFakeWs();
		const localData: Uint8Array[] = [];
		const client = createMuxClient({
			ws,
			openLocalPipe: () => ({
				write: (b: Uint8Array) => {
					localData.push(b);
				},
				onData: () => {},
				close: () => {},
			}),
		});
		client.start();

		ws.deliver(
			encodeFrame(
				{
					frameType: FrameType.OPEN,
					connId: 7,
					payload: new TextEncoder().encode(
						JSON.stringify({
							sni: "github--bot.hook.rine.network",
							peer_ip: "203.0.113.7",
							opened_at: 1,
						}),
					),
				},
				MAX_FRAME,
			),
		);
		const tls = new Uint8Array([0x16, 0x03, 0x01, 0xaa]);
		ws.deliver(
			encodeFrame(
				{ frameType: FrameType.DATA, connId: 7, payload: tls },
				MAX_FRAME,
			),
		);

		expect(localData.length).toBeGreaterThan(0);
		expect(Array.from(localData[0] ?? [])).toEqual(Array.from(tls));
	});

	it("local response bytes are sent back to the broker as relay→broker DATA on the same conn_id", async () => {
		const { createMuxClient } = await import("../../src/funnel/tunnel.js");
		const ws = makeFakeWs();
		let pipeOnData: ((b: Uint8Array) => void) | undefined;
		const client = createMuxClient({
			ws,
			openLocalPipe: () => ({
				write: () => {},
				onData: (cb: (b: Uint8Array) => void) => {
					pipeOnData = cb;
				},
				close: () => {},
			}),
		});
		client.start();
		ws.deliver(
			encodeFrame(
				{
					frameType: FrameType.OPEN,
					connId: 9,
					payload: new TextEncoder().encode("{}"),
				},
				MAX_FRAME,
			),
		);

		const resp = new Uint8Array([0x17, 0x03, 0x03]);
		pipeOnData?.(resp);

		const dataFrame = ws.sent
			.map((b) => decodeFrame(b, MAX_FRAME))
			.find((f) => f.frameType === FrameType.DATA);
		expect(dataFrame).toBeDefined();
		expect(dataFrame?.connId).toBe(9);
		expect(Array.from(dataFrame?.payload ?? [])).toEqual(Array.from(resp));
	});

	it("tears down the local pipe on a broker CLOSE/RESET for that conn_id", async () => {
		const { createMuxClient } = await import("../../src/funnel/tunnel.js");
		const ws = makeFakeWs();
		const closed: number[] = [];
		let connSeq = 0;
		const client = createMuxClient({
			ws,
			openLocalPipe: () => {
				const id = ++connSeq;
				return {
					write: () => {},
					onData: () => {},
					close: () => {
						closed.push(id);
					},
				};
			},
		});
		client.start();
		ws.deliver(
			encodeFrame(
				{
					frameType: FrameType.OPEN,
					connId: 7,
					payload: new TextEncoder().encode("{}"),
				},
				MAX_FRAME,
			),
		);
		ws.deliver(
			encodeFrame(
				{
					frameType: FrameType.CLOSE,
					connId: 7,
					payload: new Uint8Array([0x00]),
				},
				MAX_FRAME,
			),
		);

		expect(closed).toContain(1);
	});

	it("pauses reading when a single conn's in-flight bytes exceed the 256 KiB cap", async () => {
		const { createMuxClient } = await import("../../src/funnel/tunnel.js");
		const ws = makeFakeWs();
		let paused = false;
		const client = createMuxClient({
			ws,
			openLocalPipe: () => ({
				write: () => {},
				onData: () => {},
				close: () => {},
				pause: () => {
					paused = true;
				},
				resume: () => {
					paused = false;
				},
			}),
		});
		client.start();
		ws.deliver(
			encodeFrame(
				{
					frameType: FrameType.OPEN,
					connId: 7,
					payload: new TextEncoder().encode("{}"),
				},
				MAX_FRAME,
			),
		);
		// Push > 256 KiB of DATA in 64 KiB chunks without the peer draining.
		const chunk = new Uint8Array(65_536);
		for (let i = 0; i < 5; i++) {
			ws.deliver(
				encodeFrame(
					{ frameType: FrameType.DATA, connId: 7, payload: chunk },
					MAX_FRAME,
				),
			);
		}
		expect(paused).toBe(true);
	});
});

describe("mux client driver — reconnect loop (modeled on stream.ts)", () => {
	it("computes jittered backoff capped at 30s with the same min(backoff*2,30) progression", async () => {
		const { nextReconnectBackoffSeconds } = await import(
			"../../src/funnel/tunnel.js"
		);
		const { jitteredDelayMs } = await import("../../src/timing.js");
		// Progression: 1 → 2 → 4 → 8 → 16 → 30 (cap), never above 30.
		expect(nextReconnectBackoffSeconds(1)).toBe(2);
		expect(nextReconnectBackoffSeconds(16)).toBe(30);
		expect(nextReconnectBackoffSeconds(30)).toBe(30);
		// Jitter range for backoff=1 matches stream.ts: [500, 1500] ms.
		for (let i = 0; i < 50; i++) {
			const d = jitteredDelayMs(1);
			expect(d).toBeGreaterThanOrEqual(500);
			expect(d).toBeLessThanOrEqual(1500);
		}
	});

	it("on a WS drop it RESETs all live conns locally (no replay, no resume)", async () => {
		const { createMuxClient } = await import("../../src/funnel/tunnel.js");
		let onClose: (() => void) | undefined;
		const ws = {
			sent: [] as Uint8Array[],
			send: () => {},
			onBinary: () => {},
			onClose: (cb: () => void) => {
				onClose = cb;
			},
			deliver: () => {},
			close: () => {},
		};
		const closed: number[] = [];
		let seq = 0;
		const client = createMuxClient({
			ws: ws as never,
			openLocalPipe: () => {
				const id = ++seq;
				return {
					write: () => {},
					onData: () => {},
					close: () => {
						closed.push(id);
					},
				};
			},
		});
		client.start();
		ws as unknown as { onBinary: (cb: (d: Uint8Array) => void) => void };
		// Open two conns, then drop the WS.
		client.handleFrame?.(
			decodeFrame(
				encodeFrame(
					{
						frameType: FrameType.OPEN,
						connId: 1,
						payload: new TextEncoder().encode("{}"),
					},
					MAX_FRAME,
				),
				MAX_FRAME,
			),
		);
		client.handleFrame?.(
			decodeFrame(
				encodeFrame(
					{
						frameType: FrameType.OPEN,
						connId: 2,
						payload: new TextEncoder().encode("{}"),
					},
					MAX_FRAME,
				),
				MAX_FRAME,
			),
		);
		onClose?.();

		expect(closed.sort()).toEqual([1, 2]);
	});
});
