// rine Funnel SHARED-EDGE relay pipe (Phase B). The sibling of tls-listener.ts's
// loopback pipe, for the tier where the BROKER terminates TLS and forwards the
// DECRYPTED HTTP request down the mux as plaintext. The relay no longer terminates
// TLS or runs a local listener here — it just parses the forwarded request, runs
// the SAME per-request adapter (HMAC-verify → hpke-v1 self-send), and synthesizes
// the 204/400/500 response to copy back over the tunnel.
//
// FROZEN-CONTRACT: the trust boundary is UNCHANGED from zero-trust at REST — the
// relay still HMAC-verifies (the secret never left the relay) and HPKE-seals
// (`hpke-v1`, NO new encryption_version). Only the inbound bytes arrive as
// plaintext over the mux instead of as raw TLS records (the broker decrypted
// them). Same `handleWebhookRequest`, same response strings.

import type { LocalPipe } from "./mux-client.js";
import type { Frame } from "./mux-codec.js";
import type { WebhookRequest } from "./relay-adapter.js";
import { HTTP_204, HTTP_400, HTTP_500, parseHttpRequest } from "./tls-listener.js";

export interface EdgePipeArgs {
	/** Handle one decoded request; resolves when the relay is done with it. */
	onRequest(req: WebhookRequest): Promise<void>;
}

/**
 * Build the shared-edge `openLocalPipe` factory the mux client calls per OPEN.
 * Unlike the zero-trust loopback factory it opens NO socket and needs NO cert —
 * the broker already terminated the TLS and FRAMED exactly one request, so the
 * forwarded bytes feed straight into the shared HTTP framer.
 */
export function makeEdgePipeFactory(
	args: EdgePipeArgs,
): (frame: Frame) => LocalPipe {
	return () => openEdgePipe(args.onRequest);
}

/**
 * One mux conn as a plaintext pipe. `write` accumulates the broker-forwarded
 * request bytes into the SHARED framer (`parseHttpRequest`); the broker already
 * frames a COMPLETE request bounded by Content-Length, so the framer
 * dispatches on that boundary and NEVER waits for EOF. On a complete request it
 * runs `onRequest` then pushes the synthesized 204/400/500 back as response bytes
 * and CLOSEs the conn (the relay has nothing else to send, so closing lets the
 * broker shut its terminated TLS stream promptly — onClose, mux-client.ts).
 */
function openEdgePipe(
	onRequest: (req: WebhookRequest) => Promise<void>,
): LocalPipe {
	const parser = parseHttpRequest();
	let dataCb: ((bytes: Uint8Array) => void) | undefined;
	let closeCb: (() => void) | undefined;
	let handled = false;

	const respond = (response: string): void => {
		dataCb?.(new TextEncoder().encode(response));
		// We have nothing more to send on this conn — close it so the broker shuts
		// the terminated TLS stream (GitHub gets the response + close_notify).
		closeCb?.();
	};

	const dispatch = (chunk: Buffer): void => {
		if (handled) return;
		// `eof: false` always — the broker FRAMED the request by Content-Length, so
		// the framer completes on that boundary; an EOF wait would deadlock against a
		// client (GitHub) that blocks on the response without half-closing.
		const result = parser.feed(chunk, false);
		if (result === "pending") return;
		handled = true;
		if (result === "bad") {
			respond(HTTP_400);
			return;
		}
		onRequest(result)
			.then(() => respond(HTTP_204))
			.catch(() => respond(HTTP_500));
	};

	return {
		write: (bytes) => dispatch(Buffer.from(bytes)),
		onData: (cb) => {
			dataCb = cb;
		},
		onClose: (cb) => {
			closeCb = cb;
		},
		close: () => {},
	};
}
