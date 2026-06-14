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

/**
 * Buffer one HTTP request off the TLS socket and dispatch as soon as the full
 * body has arrived. A real HTTP/1.1 client (GitHub) sends the request then BLOCKS
 * on the response WITHOUT half-closing, so triggering on the socket `"end"` (EOF)
 * deadlocks until the client's own timeout. Instead we dispatch the moment we have
 * the head plus a `Content-Length`-worth of body; `"end"` stays a fallback for the
 * no-body / chunked / EOF-terminated cases. `handled` guards single dispatch.
 */
export function handleConnection(
	socket: TLSSocket,
	onRequest: TlsListenerArgs["onRequest"],
): void {
	const chunks: Buffer[] = [];
	let handled = false;

	const dispatch = async (eof: boolean): Promise<void> => {
		if (handled) return;
		const raw = Buffer.concat(chunks);
		const sep = raw.indexOf("\r\n\r\n");
		if (sep < 0) {
			// Head not fully received yet — wait for more unless the client EOF'd.
			if (eof) {
				handled = true;
				socket.end("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
			}
			return;
		}
		const headers = parseHeaders(raw.subarray(0, sep).toString("latin1"));
		const body = raw.subarray(sep + 4);
		const declared = Number(headers["content-length"]);
		// With a Content-Length, hold until the whole body lands; without one, only
		// a client EOF tells us the body is complete.
		if (Number.isInteger(declared) && declared >= 0) {
			if (body.length < declared && !eof) return;
		} else if (!eof) {
			return;
		}
		handled = true;
		const rawBody =
			Number.isInteger(declared) && declared >= 0
				? body.subarray(0, declared)
				: body;
		try {
			await onRequest({ headers, rawBody });
			socket.end("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
		} catch {
			socket.end(
				"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
			);
		}
	};

	socket.on("data", (c: Buffer) => {
		chunks.push(c);
		void dispatch(false);
	});
	socket.on("error", () => socket.destroy());
	socket.on("end", () => void dispatch(true));
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
