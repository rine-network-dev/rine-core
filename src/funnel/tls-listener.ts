// rine Funnel local TLS-terminating listener. The broker
// shovels the GitHub→edge TLS records raw down the mux (passthrough, E2EE
// invariant); the relay terminates that TLS HERE on loopback using the cert whose
// private key never left the box. Each terminated request's RAW body is
// handed to the relay adapter (HMAC-verify → encrypt → self-send).
//
// `openLocalPipe(frame)` returns the mux-client's LocalPipe for one conn: it
// opens a loopback TCP socket to this listener, writing the broker's TLS bytes in
// and streaming the TLS response bytes back to the broker on the same conn_id.

import { connect } from "node:net";
import { type Server, type TLSSocket, createServer } from "node:tls";
import { FRAMING_REFUSAL, HTTP_500, parseHttpRequest, relayResponse } from "./http-frame.js";
import type { LocalPipe } from "./mux-client.js";
import type { Frame } from "./mux-codec.js";
import type { RelayResult, WebhookRequest } from "./relay-adapter.js";

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
	/** Handle one decoded request; resolves with the relay's outcome, which picks the response. */
	onRequest(req: WebhookRequest): Promise<RelayResult>;
}

/**
 * Stand up the loopback TLS listener. Each accepted socket is one webhook
 * delivery: parse the HTTP request head + body, hand the RAW body to `onRequest`,
 * then write a minimal response (204, or 400/413/502 when it cannot be relayed) and close (GitHub only needs a 2xx).
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
 * Drive `parseHttpRequest` over one TLS socket: frame one request, hand it to
 * `onRequest`, then write a minimal 204/400/413/500/502 response and close. A real
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
		if (typeof result === "string") {
			// Destroy once the refusal is flushed: a peer that keeps sending must not hold the socket.
			socket.end(FRAMING_REFUSAL[result], () => socket.destroy());
			return;
		}
		try {
			socket.end(relayResponse(await onRequest(result)));
		} catch {
			socket.end(HTTP_500);
		}
	};

	socket.on("data", (c: Buffer) => void dispatch(c, false));
	socket.on("error", () => socket.destroy());
	socket.on("end", () => void dispatch(Buffer.alloc(0), true));
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
