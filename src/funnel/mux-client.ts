// rine Funnel mux CLIENT driver (REQ-TUN-13/14), the relay side of the broker's
// multiplexer. It demultiplexes the single control WebSocket into per-conn local
// pipes: OPEN → open a local pipe, broker DATA → write into it, local response →
// relay→broker DATA on the same conn_id, broker CLOSE/RESET → tear the pipe down.
// On a WS drop it RESETs every live conn locally (no replay, no resume) and the
// caller reconnects with the jittered backoff helpers below.
//
// FROZEN-CONTRACT: the client SENDS no WINDOW frame; backpressure is the per-conn
// 256 KiB in-flight cap (pause-on-cap). The broker never inspects DATA payloads —
// for *.hook conns they are opaque encrypted TLS records (E2EE invariant).

import {
	CONTROL_CONN_ID,
	type Frame,
	FrameType,
	decodeFrame,
	encodeFrame,
} from "./mux-codec.js";

/** Per-conn in-flight cap before the relay pauses reading from the broker. */
export const PER_CONN_INFLIGHT_CAP = 256 * 1024;

const DEFAULT_MAX_FRAME = 65_536;

/** A local byte pipe (the TLS-terminating listener conn) the relay drives. */
export interface LocalPipe {
	write(bytes: Uint8Array): void;
	onData(cb: (bytes: Uint8Array) => void): void;
	close(): void;
	pause?(): void;
	resume?(): void;
}

/** The minimal WS surface the driver needs (real WebSocket or a fake in tests). */
export interface MuxWs {
	send(data: Uint8Array): void;
	onBinary(cb: (data: Uint8Array) => void): void;
	onClose?(cb: () => void): void;
	close(): void;
}

export interface MuxClientArgs {
	ws: MuxWs;
	openLocalPipe(frame: Frame): LocalPipe;
	maxFrameBytes?: number;
}

export interface MuxClient {
	start(): void;
	handleFrame(frame: Frame): void;
}

/**
 * Build a mux client over `ws`. `start()` wires the WS binary + close callbacks;
 * `handleFrame` is exposed so a caller (and the unit tests) can drive a single
 * decoded frame directly.
 */
export function createMuxClient(args: MuxClientArgs): MuxClient {
	const { ws, openLocalPipe } = args;
	const maxFrame = args.maxFrameBytes ?? DEFAULT_MAX_FRAME;

	interface ConnState {
		pipe: LocalPipe;
		inflight: number;
		paused: boolean;
	}
	const conns = new Map<number, ConnState>();

	function sendData(connId: number, bytes: Uint8Array): void {
		ws.send(
			encodeFrame(
				{ frameType: FrameType.DATA, connId, payload: bytes },
				maxFrame,
			),
		);
	}

	function teardown(connId: number): void {
		const state = conns.get(connId);
		if (!state) return;
		conns.delete(connId);
		state.pipe.close();
	}

	function openConn(frame: Frame): void {
		const pipe = openLocalPipe(frame);
		const state: ConnState = { pipe, inflight: 0, paused: false };
		conns.set(frame.connId, state);
		// Local response bytes flow back to the broker on the same conn_id; once
		// they leave the relay the in-flight count drains, so we can resume.
		pipe.onData((bytes) => {
			sendData(frame.connId, bytes);
			state.inflight = Math.max(0, state.inflight - bytes.length);
			if (state.paused && state.inflight < PER_CONN_INFLIGHT_CAP) {
				state.paused = false;
				state.pipe.resume?.();
			}
		});
	}

	function onData(frame: Frame): void {
		const state = conns.get(frame.connId);
		if (!state) return;
		state.pipe.write(frame.payload);
		state.inflight += frame.payload.length;
		if (state.inflight > PER_CONN_INFLIGHT_CAP && !state.paused) {
			state.paused = true;
			state.pipe.pause?.();
		}
	}

	function handleFrame(frame: Frame): void {
		switch (frame.frameType) {
			case FrameType.OPEN:
				openConn(frame);
				break;
			case FrameType.DATA:
				onData(frame);
				break;
			case FrameType.CLOSE:
			case FrameType.RESET:
				teardown(frame.connId);
				break;
			default:
				// Control frames (BIND_ACK/BIND_NAK) are handled by the binding
				// handshake before the driver starts; ignore them here.
				break;
		}
	}

	function resetAllConns(): void {
		for (const connId of [...conns.keys()]) teardown(connId);
	}

	return {
		start() {
			ws.onBinary((data) => {
				const frame = decodeFrame(data, maxFrame);
				if (frame.connId === CONTROL_CONN_ID) return;
				handleFrame(frame);
			});
			ws.onClose?.(() => resetAllConns());
		},
		handleFrame,
	};
}

/**
 * Reconnect backoff progression, identical to stream.ts: double, capped at 30s.
 * `1 → 2 → 4 → 8 → 16 → 30 → 30`.
 */
export function nextReconnectBackoffSeconds(backoffSeconds: number): number {
	return Math.min(backoffSeconds * 2, 30);
}

/** Full jitter over the current backoff window — identical to stream.ts. */
export function jitteredDelayMs(backoffSeconds: number): number {
	return Math.round(backoffSeconds * (0.5 + Math.random()) * 1000);
}
