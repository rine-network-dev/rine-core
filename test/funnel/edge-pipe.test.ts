// rine Funnel SHARED-EDGE relay pipe.
//
// The sibling of tls-listener.test.ts, for the tier where the BROKER terminates
// TLS and forwards the DECRYPTED request down the mux as plaintext. The relay's
// `edge-pipe` parses that forwarded request with the SAME shared framer
// (`parseHttpRequest`) WITHOUT a TLS socket, runs the SAME per-request adapter
// (here a stub `onRequest`), and synthesizes the 204/500 response to copy back over
// the tunnel — then signals completion (`onClose`) so the broker shuts its
// terminated TLS stream promptly.
//
// Contract note: the broker frames EXACTLY one request by Content-Length
// and holds the conn open for the response WITHOUT half-closing, so `edge-pipe`
// feeds the framer `eof:false` always. The reachable outcomes are therefore a
// COMPLETE request (→204, or →500 if the adapter throws) or `"pending"` while a
// multi-frame request is still arriving — never the framer's EOF-only `"bad"`
// (that branch exists only because the framer is shared with the EOF-driven
// tls-listener; it cannot fire here).

import { describe, expect, it } from "vitest";
import { type EdgePipeArgs, makeEdgePipeFactory } from "../../src/funnel/edge-pipe.js";
import { MAX_BODY_BYTES } from "../../src/funnel/http-frame.js";
import { type Frame, FrameType } from "../../src/funnel/mux-codec.js";
import type { LocalPipe } from "../../src/funnel/mux-client.js";
import type { WebhookRequest } from "../../src/funnel/relay-adapter.js";
import { RELAYED, RELAY_FAILED, REPLAYED, REJECTED } from "./relay-outcomes.js";

/** A minimal OPEN frame — `openEdgePipe` ignores the frame, so any will do. */
const OPEN: Frame = {
	frameType: FrameType.OPEN,
	connId: 1,
	payload: new Uint8Array(),
};

/** Flush pending microtasks/timers so `onRequest().then(respond)` settles. */
const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

/** Drive one edge pipe; collect the response bytes + the onClose signal. */
function drive(onRequest: EdgePipeArgs["onRequest"]): {
	pipe: LocalPipe;
	response: () => string;
	closed: () => boolean;
} {
	const pipe = makeEdgePipeFactory({ onRequest })(OPEN);
	const out: Uint8Array[] = [];
	let closed = false;
	pipe.onData((b) => out.push(b));
	pipe.onClose?.(() => {
		closed = true;
	});
	return {
		pipe,
		response: () =>
			Buffer.concat(out.map((u) => Buffer.from(u))).toString("latin1"),
		closed: () => closed,
	};
}

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

describe("funnel shared-edge edge-pipe", () => {
	it("dispatches a Content-Length request, runs the adapter, replies 204, and closes", async () => {
		let received: WebhookRequest | undefined;
		const h = drive(async (req) => {
			received = req;
			return RELAYED;
		});
		h.pipe.write(
			enc("POST /h HTTP/1.1\r\nHost: x--a.edge.rine.network\r\nContent-Length: 5\r\n\r\nhello"),
		);
		await flush();

		expect(received).toBeDefined();
		expect(received?.rawBody.toString()).toBe("hello");
		expect(h.response()).toContain("204");
		expect(h.closed()).toBe(true);
	});

	it("frames a request split across MULTIPLE writes (mux DATA chunks)", async () => {
		let received: WebhookRequest | undefined;
		const h = drive(async (req) => {
			received = req;
			return RELAYED;
		});
		// Head in one write, body in another — the broker may split a large request
		// into <= max_frame DATA frames; the framer holds until the body completes.
		h.pipe.write(enc("POST /h HTTP/1.1\r\nContent-Length: 11\r\n\r\n"));
		await flush();
		expect(received, "must NOT dispatch before the body is complete").toBeUndefined();

		h.pipe.write(enc('{"ok":true}'));
		await flush();
		expect(received?.rawBody.toString()).toBe('{"ok":true}');
		expect(h.response()).toContain("204");
		expect(h.closed()).toBe(true);
	});

	it("replies 500 when the adapter (HMAC verify / encrypt) throws", async () => {
		const h = drive(async () => {
			throw new Error("bad signature");
		});
		h.pipe.write(enc("POST /h HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi"));
		await flush();

		expect(h.response()).toContain("500");
		expect(h.closed()).toBe(true);
	});

	it.each([
		["a relayed delivery gets 204", RELAYED, "204"],
		["a replayed delivery gets 204", REPLAYED, "204"],
		["an HMAC rejection gets 204", REJECTED, "204"],
		["a verified delivery the relay could not post gets 502", RELAY_FAILED, "502"],
	])("%s", async (_name, outcome, status) => {
		const h = drive(async () => outcome);
		h.pipe.write(enc("POST /h HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi"));
		await flush();

		expect(h.response()).toContain(status);
		expect(h.closed()).toBe(true);
	});

	it("replies 413 and never calls the adapter for a body over the relayable cap", async () => {
		let calls = 0;
		const h = drive(async () => {
			calls += 1;
			return RELAYED;
		});
		h.pipe.write(enc(`POST /h HTTP/1.1\r\nContent-Length: ${MAX_BODY_BYTES + 1}\r\n\r\n`));
		await flush();

		expect(h.response()).toContain("413 Payload Too Large");
		expect(h.closed()).toBe(true);
		expect(calls).toBe(0);
	});

	it("dispatches exactly once — a second write after completion is ignored", async () => {
		let calls = 0;
		const h = drive(async () => {
			calls += 1;
			return RELAYED;
		});
		h.pipe.write(enc("POST /h HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi"));
		await flush();
		// Any trailing bytes (e.g. a pipelined extra) must not re-trigger the adapter.
		h.pipe.write(enc("POST /next HTTP/1.1\r\nContent-Length: 0\r\n\r\n"));
		await flush();

		expect(calls).toBe(1);
	});
});
