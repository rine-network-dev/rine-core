// rine Funnel local TLS-terminating listener (REQ-CLI-07 step 3). The broker
// shovels the GitHub→edge TLS records raw down the mux (passthrough, E2EE
// invariant); the relay terminates that TLS HERE on loopback using the cert whose
// private key never left the box (D4). Each terminated request's RAW body is
// handed to the relay adapter (HMAC-verify → encrypt → self-send).
//
// `openLocalPipe(frame)` returns the mux-client's LocalPipe for one conn: it
// opens a loopback TCP socket to this listener, writing the broker's TLS bytes in
// and streaming the TLS response bytes back to the broker on the same conn_id.

import { connect } from "node:net";
import { type Server, type TLSSocket, createServer } from "node:tls";
import type { LocalPipe } from "./mux-client.js";
import type { Frame } from "./mux-codec.js";
import type { WebhookRequest } from "./relay-adapter.js";

export interface TlsListener {
	port: number;
	close(): void;
	/** A LocalPipe factory for the mux client — one loopback conn per mux OPEN. */
	openLocalPipe(frame: Frame): LocalPipe;
}

export interface TlsListenerArgs {
	port: number;
	certPem: string;
	keyPem: string;
	/** Handle one decoded request; resolves when the relay is done with it. */
	onRequest(req: WebhookRequest): Promise<void>;
}

/**
 * Stand up the loopback TLS listener. Each accepted socket is one webhook
 * delivery: parse the HTTP request head + body, hand the RAW body to `onRequest`,
 * then write a minimal 204/400 response and close (GitHub only needs a 2xx).
 */
export async function startTlsListener(
	args: TlsListenerArgs,
): Promise<TlsListener> {
	const { certPem, keyPem, onRequest } = args;
	const server: Server = createServer(
		{ cert: certPem, key: keyPem },
		(socket) => handleConnection(socket, onRequest),
	);
	const port = await new Promise<number>((resolve, reject) => {
		server.once("error", reject);
		server.listen(args.port, "127.0.0.1", () => {
			const addr = server.address();
			resolve(typeof addr === "object" && addr ? addr.port : args.port);
		});
	});
	return {
		port,
		close: () => server.close(),
		openLocalPipe: () => openLoopbackPipe(port),
	};
}

// The HTTP/1.1 response lines the relay writes back for the three outcomes.
// Centralized so the loopback-TLS path here AND the plaintext edge-pipe path
// (edge-pipe.ts, Phase B) synthesize byte-identical responses (AUD-C3).
export const HTTP_204 = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
export const HTTP_400 = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
export const HTTP_500 =
	"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";

/**
 * The transport-agnostic outcome of feeding a chunk into `parseHttpRequest`:
 * `"pending"` — head + a Content-Length-worth of body has NOT arrived yet (wait
 * for more bytes, or for EOF on a body-less / chunked / EOF-terminated request);
 * `"bad"` — the client EOF'd before a complete head (a 400); `WebhookRequest` —
 * one complete request is framed and ready to dispatch. The parser dispatches the
 * MOMENT the body is complete, never on EOF, because a real HTTP/1.1 client
 * (GitHub) sends the request then BLOCKS on the response WITHOUT half-closing —
 * waiting for EOF would deadlock every real delivery.
 */
export type ParseResult = WebhookRequest | "pending" | "bad";

/**
 * A stateful, transport-agnostic HTTP/1.1 request framer. `feed(chunk, eof)`
 * accumulates bytes and returns a `ParseResult`; the FIRST non-`"pending"` result
 * is the parse outcome (call sites stop feeding once they get a `WebhookRequest`
 * or `"bad"`). It owns ONLY the head/Content-Length/EOF framing — the writing of
 * the 204/400/500 response and the loopback/plaintext transport bridge stay in
 * the caller — so BOTH the ZT loopback-TLS listener and the SE plaintext mux pipe
 * (Phase B's edge-pipe) share this one framer with no duplicated CL/EOF logic.
 */
export function parseHttpRequest(): {
	feed(chunk: Buffer, eof: boolean): ParseResult;
} {
	const chunks: Buffer[] = [];
	let done = false;
	return {
		feed(chunk: Buffer, eof: boolean): ParseResult {
			if (done) return "pending";
			if (chunk.length > 0) chunks.push(chunk);
			const raw = Buffer.concat(chunks);
			const sep = raw.indexOf("\r\n\r\n");
			if (sep < 0) {
				// Head not fully received yet — wait for more unless the client EOF'd.
				if (eof) {
					done = true;
					return "bad";
				}
				return "pending";
			}
			const headers = parseHeaders(raw.subarray(0, sep).toString("latin1"));
			const body = raw.subarray(sep + 4);
			const declared = Number(headers["content-length"]);
			// With a Content-Length, hold until the whole body lands; without one,
			// only a client EOF tells us the body is complete.
			if (Number.isInteger(declared) && declared >= 0) {
				if (body.length < declared && !eof) return "pending";
			} else if (!eof) {
				return "pending";
			}
			done = true;
			const rawBody =
				Number.isInteger(declared) && declared >= 0
					? body.subarray(0, declared)
					: body;
			return { headers, rawBody };
		},
	};
}

/**
 * Drive `parseHttpRequest` over one TLS socket: frame one request, hand it to
 * `onRequest`, then write a minimal 204/400/500 response and close. A real
 * HTTP/1.1 client (GitHub) blocks on the response WITHOUT half-closing, so the
 * framer dispatches the moment the body is complete (never on `"end"`/EOF).
 */
export function handleConnection(
	socket: TLSSocket,
	onRequest: TlsListenerArgs["onRequest"],
): void {
	const parser = parseHttpRequest();
	let handled = false;

	const dispatch = async (chunk: Buffer, eof: boolean): Promise<void> => {
		if (handled) return;
		const result = parser.feed(chunk, eof);
		if (result === "pending") return;
		handled = true;
		if (result === "bad") {
			socket.end(HTTP_400);
			return;
		}
		try {
			await onRequest(result);
			socket.end(HTTP_204);
		} catch {
			socket.end(HTTP_500);
		}
	};

	socket.on("data", (c: Buffer) => void dispatch(c, false));
	socket.on("error", () => socket.destroy());
	socket.on("end", () => void dispatch(Buffer.alloc(0), true));
}

/** Parse a CRLF-delimited HTTP head into a lowercased header map (skip the request line). */
function parseHeaders(head: string): Record<string, string> {
	const out: Record<string, string> = {};
	const lines = head.split("\r\n");
	for (const line of lines.slice(1)) {
		const idx = line.indexOf(":");
		if (idx > 0)
			out[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
	}
	return out;
}

/** One mux conn → one loopback TCP socket bridging broker bytes ↔ TLS listener. */
function openLoopbackPipe(port: number): LocalPipe {
	const sock = connect(port, "127.0.0.1");
	let dataCb: ((bytes: Uint8Array) => void) | undefined;
	sock.on("data", (c: Buffer) => dataCb?.(new Uint8Array(c)));
	sock.on("error", () => sock.destroy());
	return {
		write: (bytes) => sock.write(bytes),
		onData: (cb) => {
			dataCb = cb;
		},
		close: () => sock.destroy(),
		pause: () => sock.pause(),
		resume: () => sock.resume(),
	};
}
