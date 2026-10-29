// The HTTP/1.1 request framer and response lines shared by the loopback-TLS
// listener (tls-listener.ts, zero-trust) and the plaintext edge pipe
// (edge-pipe.ts, shared-edge): one framer, one set of byte-identical responses.

import type { RelayResult, WebhookRequest } from "./relay-adapter.js";

// The HTTP/1.1 response lines the relay writes back.
export const HTTP_204 = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
export const HTTP_400 = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
export const HTTP_413 =
	"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n";
export const HTTP_500 =
	"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
export const HTTP_502 = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

/**
 * The response for a delivery the relay handled. A verified delivery that could not be
 * sealed or posted is a 502, so the sender records the failure and can redeliver instead
 * of believing it arrived. A replay (already relayed) and an HMAC rejection stay 204:
 * the first is the acknowledgement the sender needs, the second gives a caller without
 * the secret nothing to tell it from success.
 */
export function relayResponse(result: RelayResult): string {
	return result.verified && !result.relayed && !result.duplicate ? HTTP_502 : HTTP_204;
}

/** Largest request head (request line + headers) the framer accepts: the broker's `EDGE_MAX_HEAD_BYTES`. */
const MAX_HEAD_BYTES = 16 * 1024;

/**
 * `_ENCRYPTED_PAYLOAD_SIZE_LIMIT` in `src/rine/api/schemas_message.py`: the longest
 * `encrypted_payload` (base64url characters) the server accepts for a message.
 */
export const SERVER_ENCRYPTED_PAYLOAD_LIMIT = 131_072;

/**
 * Bytes of the server limit reserved for what sealing adds around the webhook body: the
 * KEM encapsulation and version byte (1 + 32 + 1088), the AEAD tag (16), the envelope's
 * kid length byte and signature (1 + 64), a signing kid of at most 255 bytes, and the two
 * quotes `JSON.stringify` puts around a body that is not JSON: 1459 bytes in all. The
 * remaining 589 bytes absorb the characters JSON re-encoding escapes in such a body.
 * Request headers are not sealed, so the head size does not enter.
 */
const SEAL_ALLOWANCE_BYTES = 2 * 1024;

/**
 * Largest request body the framer accepts: the largest webhook the relay can seal and post
 * (the server limit is on the base64url text, which is 4/3 the sealed bytes). A body over
 * it could never be relayed, so it is refused with a 413 instead of being acknowledged and
 * lost. Applies to both tiers; on the shared-edge pipe the broker's own cap
 * (`BROKER_EDGE_MAX_REQUEST_BYTES`, 128 KiB by default) cuts a larger body off first.
 */
export const MAX_BODY_BYTES =
	Math.floor((SERVER_ENCRYPTED_PAYLOAD_LIMIT * 3) / 4) - SEAL_ALLOWANCE_BYTES;

/**
 * The outcome of feeding a chunk into `parseHttpRequest`: `"pending"` — head + a
 * Content-Length-worth of body has not arrived yet; `"bad"` — the client EOF'd
 * before a complete head, or the head outgrew its cap (a 400); `"too-large"` — the
 * body outgrew its cap (a 413); `WebhookRequest` — one complete request is framed. It
 * dispatches the MOMENT the body is complete, never on EOF: a real HTTP/1.1 client
 * (GitHub) sends the request then BLOCKS on the response WITHOUT half-closing.
 */
export type ParseResult = WebhookRequest | "pending" | "bad" | "too-large";

/** The response line for each way the framer refuses a request. */
export const FRAMING_REFUSAL = { bad: HTTP_400, "too-large": HTTP_413 } as const;

/**
 * A stateful, transport-agnostic HTTP/1.1 request framer: `feed(chunk, eof)`
 * returns a `ParseResult`, and the FIRST non-`"pending"` result is the outcome.
 * It owns only the head/Content-Length/EOF framing, so the loopback-TLS listener
 * and the plaintext edge pipe share one framer with no duplicated logic.
 */
export function parseHttpRequest(): {
	feed(chunk: Buffer, eof: boolean): ParseResult;
} {
	let head = Buffer.alloc(0);
	let headers: Record<string, string> | undefined;
	let declared = Number.NaN;
	const body: Buffer[] = [];
	let bodyLength = 0;
	let done = false;

	return {
		feed(chunk: Buffer, eof: boolean): ParseResult {
			if (done) return "pending";
			const refuse = (why: "bad" | "too-large"): ParseResult => {
				done = true;
				return why;
			};
			if (headers === undefined) {
				// Head phase: capped, so re-joining per chunk is bounded by
				// MAX_HEAD_BYTES, never by what the peer chooses to send.
				head = Buffer.concat([head, chunk]);
				const sep = head.indexOf("\r\n\r\n");
				// A terminator that starts past the cap is bad however the bytes were chunked.
				if (sep < 0) return head.length >= MAX_HEAD_BYTES + 4 || eof ? refuse("bad") : "pending";
				if (sep > MAX_HEAD_BYTES) return refuse("bad");
				headers = parseHeaders(head.subarray(0, sep).toString("latin1"));
				declared = Number(headers["content-length"]);
				if (declared > MAX_BODY_BYTES) return refuse("too-large");
				chunk = head.subarray(sep + 4);
			}
			// Body phase: collect the chunks and join them once, on completion. With a
			// Content-Length, bytes past it belong to no request and are dropped uncounted.
			const sized = Number.isInteger(declared) && declared >= 0;
			if (sized) chunk = chunk.subarray(0, declared - bodyLength);
			body.push(chunk);
			bodyLength += chunk.length;
			if (bodyLength > MAX_BODY_BYTES) return refuse("too-large");
			// Without a Content-Length only a client EOF tells us the body is complete.
			if (!(eof || (sized && bodyLength >= declared))) return "pending";
			done = true;
			return { headers, rawBody: Buffer.concat(body) };
		},
	};
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
