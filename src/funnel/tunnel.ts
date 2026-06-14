// rine Funnel control WebSocket + mux tunnel (REQ-TUN). This is the relay-facing
// barrel: it re-exports the wire codec (mux-codec.ts) and the mux client driver
// (mux-client.ts) so callers and the test suite import one module, and adds
// `connectTunnel` — the production WS connect + BIND handshake + driver wiring.
//
// Control WS: wss://funnel.rine.network/_funnel/v1, subprotocol rine.funnel.v1,
// Authorization: Bearer <org JWT> at the upgrade; then BIND {"v":1,"agent_id",
// "hostname"} → BIND_ACK{caps:{...}} or BIND_NAK{reason}+close. verify-binding
// (backend) validates the forwarded Bearer + the full org→agent→hostname chain,
// so the relay just needs a valid token + the correct agent_id + the
// server-returned hostname.

import { type LocalPipe, type MuxWs, createMuxClient } from "./mux-client.js";
import {
	CONTROL_CONN_ID,
	type Frame,
	FrameType,
	decodeFrame,
	encodeFrame,
} from "./mux-codec.js";

export * from "./mux-codec.js";
export * from "./mux-client.js";

const SUBPROTOCOL = "rine.funnel.v1";
const DEFAULT_MAX_FRAME = 65_536;

/** Negotiated per-tunnel caps the broker returns in BIND_ACK. */
export interface TunnelCaps {
	max_conns: number;
	per_conn_inflight_bytes: number;
	max_frame_bytes: number;
	heartbeat_secs: number;
}

/**
 * Why the control WS closed. `clean` (WS close 1000/1001 or a bare TCP drop with
 * no abnormal code) maps to an orderly broker close — the relay reconnects
 * immediately (REQ-TUN-14). Any other / abnormal code (1002/1009/1011/…) is an
 * error and gets the jittered backoff.
 */
export interface TunnelClose {
	code: number;
	clean: boolean;
}

const CLEAN_CLOSE_CODES = new Set([0, 1000, 1001, 1005]);

function classifyClose(ev: { code?: number; wasClean?: boolean }): TunnelClose {
	const code = ev.code ?? 1005; // 1005 = no status code present (bare drop)
	return { code, clean: ev.wasClean === true || CLEAN_CLOSE_CODES.has(code) };
}

/** A bind rejection (BIND_NAK / ownership failure). `revoked` stops the relay. */
export class TunnelBindError extends Error {
	readonly revoked = true;
	constructor(reason: string) {
		super(`funnel binding rejected: ${reason}`);
		this.name = "TunnelBindError";
	}
}

export interface ConnectTunnelArgs {
	controlWsUrl: string;
	token: string;
	agentId: string;
	hostname: string;
	openLocalPipe(frame: Frame): LocalPipe;
}

export interface TunnelHandle {
	caps: TunnelCaps;
	close(): void;
	/** The callback receives the classified close so the relay can pick its reconnect policy. */
	onClose(cb: (close: TunnelClose) => void): void;
}

/**
 * Adapt a Node 24 global WebSocket to the minimal MuxWs surface. The close
 * callback receives the classified close (code + clean flag); the mux driver
 * (MuxWs.onClose) ignores the arg and just resets its conns.
 */
function adaptWs(
	ws: WebSocket,
): MuxWs & { onClose(cb: (close: TunnelClose) => void): void } {
	ws.binaryType = "arraybuffer";
	return {
		send: (data) => ws.send(data),
		onBinary: (cb) => {
			ws.addEventListener("message", (ev) => {
				if (ev.data instanceof ArrayBuffer) cb(new Uint8Array(ev.data));
			});
		},
		onClose: (cb) =>
			ws.addEventListener("close", (ev) => cb(classifyClose(ev as CloseEvent))),
		close: () => ws.close(),
	};
}

function sendBind(ws: MuxWs, agentId: string, hostname: string): void {
	const payload = new TextEncoder().encode(
		JSON.stringify({ v: 1, agent_id: agentId, hostname }),
	);
	ws.send(
		encodeFrame(
			{ frameType: FrameType.BIND, connId: CONTROL_CONN_ID, payload },
			DEFAULT_MAX_FRAME,
		),
	);
}

/**
 * Open the control WS (Bearer at the upgrade — Node 24's global WebSocket takes
 * a `{protocols, headers}` options object), perform the BIND handshake, and wire
 * the mux driver. The returned handle resolves once BIND_ACK arrives; a BIND_NAK
 * rejects with a TunnelBindError (the relay treats it as revoked and stops).
 */
export function connectTunnel(args: ConnectTunnelArgs): Promise<TunnelHandle> {
	const { controlWsUrl, token, agentId, hostname, openLocalPipe } = args;
	return new Promise<TunnelHandle>((resolve, reject) => {
		const ws = new WebSocket(controlWsUrl, {
			protocols: [SUBPROTOCOL],
			headers: { Authorization: `Bearer ${token}` },
		} as unknown as string[]);
		const adapted = adaptWs(ws);
		let bound = false;

		ws.addEventListener("open", () => sendBind(adapted, agentId, hostname));
		ws.addEventListener("error", () => {
			if (!bound) reject(new Error("control WS connect failed"));
		});

		adapted.onBinary((data) => {
			const frame = decodeFrame(data, DEFAULT_MAX_FRAME);
			if (frame.connId !== CONTROL_CONN_ID) return;
			if (frame.frameType === FrameType.BIND_ACK) {
				bound = true;
				const caps = (
					JSON.parse(new TextDecoder().decode(frame.payload)) as {
						caps: TunnelCaps;
					}
				).caps;
				const client = createMuxClient({
					ws: adapted,
					openLocalPipe,
					maxFrameBytes: caps.max_frame_bytes,
				});
				client.start();
				resolve({
					caps,
					close: () => ws.close(),
					onClose: (cb) => adapted.onClose(cb),
				});
			} else if (frame.frameType === FrameType.BIND_NAK) {
				const reason = (
					JSON.parse(new TextDecoder().decode(frame.payload)) as {
						reason?: string;
					}
				).reason;
				ws.close();
				reject(new TunnelBindError(reason ?? "unknown"));
			}
		});
	});
}
