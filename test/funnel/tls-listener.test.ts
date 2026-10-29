// Regression coverage for the relay's local TLS-terminating listener
// (tls-listener.ts). The shipped bug: handleConnection dispatched only on the
// socket "end" (EOF) event, so a real HTTP/1.1 client (GitHub) — which sends the
// request then BLOCKS on the response without half-closing — deadlocked until its
// own timeout. The fix dispatches as soon as the head + a Content-Length-worth of
// body has arrived. These tests exercise that purely through the socket event
// surface handleConnection uses, with NO TLS/network (a stub Duplex), mirroring
// the in-memory-stream pattern used by the control-WS tests.

import { EventEmitter } from "node:events";
import type { TLSSocket } from "node:tls";
import { describe, expect, it } from "vitest";
import type { WebhookRequest } from "../../src/funnel/relay-adapter.js";
import { MAX_BODY_BYTES } from "../../src/funnel/http-frame.js";
import { handleConnection } from "../../src/funnel/tls-listener.js";
import { RELAYED, RELAY_FAILED, REPLAYED, REJECTED } from "./relay-outcomes.js";

/** A minimal stand-in for the data/end/error + end()/destroy() surface used. */
class StubSocket extends EventEmitter {
	written: string | undefined;
	destroyed = false;
	end(data?: string, flushed?: () => void): void {
		this.written = data;
		this.emit("_ended");
		flushed?.();
	}
	destroy(): void {
		this.destroyed = true;
	}
	feed(buf: Buffer): void {
		this.emit("data", buf);
	}
	eof(): void {
		this.emit("end");
	}
}

/** Resolve once the handler has written its response (the `end()` call). */
function onResponse(sock: StubSocket): Promise<string | undefined> {
	return new Promise((resolve) =>
		sock.once("_ended", () => resolve(sock.written)),
	);
}

function request(body: string, contentLength = body.length): Buffer {
	return Buffer.from(
		`POST /prodtest HTTP/1.1\r\nHost: h\r\nX-Hub-Signature-256: sha256=x\r\nContent-Length: ${contentLength}\r\n\r\n${body}`,
	);
}

describe("handleConnection", () => {
	it("dispatches on a complete Content-Length body WITHOUT waiting for EOF", async () => {
		const sock = new StubSocket();
		let received: WebhookRequest | undefined;
		handleConnection(sock as unknown as TLSSocket, async (req) => {
			received = req;
			return RELAYED;
		});
		const done = onResponse(sock);
		sock.feed(request('{"ok":true}'));
		// No sock.eof() — a real client holds the connection open for the response.
		const written = await done;
		expect(received).toBeDefined();
		expect(received?.rawBody.toString()).toBe('{"ok":true}');
		expect(received?.headers["x-hub-signature-256"]).toBe("sha256=x");
		expect(written).toContain("204 No Content");
	});

	it("waits for the full body when it arrives in multiple chunks", async () => {
		const sock = new StubSocket();
		let calls = 0;
		let body = "";
		handleConnection(sock as unknown as TLSSocket, async (req) => {
			calls++;
			body = req.rawBody.toString();
			return RELAYED;
		});
		const head = Buffer.from(
			"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nhel",
		);
		sock.feed(head);
		expect(calls).toBe(0); // only 3/10 body bytes so far
		const done = onResponse(sock);
		sock.feed(Buffer.from("loworld")); // completes 10 bytes
		await done;
		expect(calls).toBe(1);
		expect(body).toBe("helloworld");
	});

	it("dispatches a body-less / no-Content-Length request only on EOF", async () => {
		const sock = new StubSocket();
		let calls = 0;
		handleConnection(sock as unknown as TLSSocket, async () => {
			calls++;
			return RELAYED;
		});
		sock.feed(Buffer.from("POST / HTTP/1.1\r\nHost: h\r\n\r\n"));
		expect(calls).toBe(0); // no Content-Length → wait for EOF
		const done = onResponse(sock);
		sock.eof();
		await done;
		expect(calls).toBe(1);
	});

	it("dispatches exactly once even if EOF follows a completed body", async () => {
		const sock = new StubSocket();
		let calls = 0;
		handleConnection(sock as unknown as TLSSocket, async () => {
			calls++;
			return RELAYED;
		});
		const done = onResponse(sock);
		sock.feed(request("hi"));
		await done;
		sock.eof(); // late EOF must not re-dispatch
		await new Promise((r) => setTimeout(r, 0));
		expect(calls).toBe(1);
	});

	it("400s a malformed (headerless) request on EOF", async () => {
		const sock = new StubSocket();
		handleConnection(sock as unknown as TLSSocket, async () => RELAYED);
		const done = onResponse(sock);
		sock.feed(Buffer.from("garbage-no-crlfcrlf"));
		sock.eof();
		const written = await done;
		expect(written).toContain("400 Bad Request");
	});

	describe("response for the relay outcome", () => {
		it.each([
			["a relayed delivery gets 204", RELAYED, "204 No Content"],
			["a replayed delivery gets 204", REPLAYED, "204 No Content"],
			["an HMAC rejection gets 204", REJECTED, "204 No Content"],
			["a verified delivery the relay could not post gets 502", RELAY_FAILED, "502 Bad Gateway"],
		])("%s", async (_name, outcome, status) => {
			const sock = new StubSocket();
			handleConnection(sock as unknown as TLSSocket, async () => outcome);
			const done = onResponse(sock);
			sock.feed(request("hi"));
			expect(await done).toContain(status);
		});
	});

	describe("size caps", () => {
		/** The largest body the relay can seal and post: 94 KiB, see MAX_BODY_BYTES. */
		const BODY_LIMIT = MAX_BODY_BYTES;

		async function drive(feed: (sock: StubSocket) => void) {
			const sock = new StubSocket();
			let calls = 0;
			let rawBody: Uint8Array | undefined;
			handleConnection(sock as unknown as TLSSocket, async (req) => {
				calls++;
				rawBody = req.rawBody;
				return RELAYED;
			});
			const done = onResponse(sock);
			feed(sock);
			return { written: await done, calls, rawBody };
		}

		it("400s a head that outgrows 16 KiB without ever finishing, before EOF", async () => {
			const { written, calls } = await drive((sock) => {
				sock.feed(Buffer.from("POST /x HTTP/1.1\r\n"));
				for (let i = 0; i < 20; i++) sock.feed(Buffer.alloc(1024, 0x61));
			});
			expect(written).toContain("400 Bad Request");
			expect(calls).toBe(0);
		});

		it("413s a declared Content-Length one byte above the body cap without reading the body", async () => {
			const { written, calls } = await drive((sock) => {
				sock.feed(request("", BODY_LIMIT + 1));
			});
			expect(written).toContain("413 Payload Too Large");
			expect(calls).toBe(0);
		});

		it("413s a body one byte over the body cap when no Content-Length bounds it", async () => {
			const { written, calls } = await drive((sock) => {
				sock.feed(Buffer.from("POST /x HTTP/1.1\r\nHost: h\r\n\r\n"));
				sock.feed(Buffer.alloc(BODY_LIMIT, 0x62));
				sock.feed(Buffer.alloc(1, 0x62));
			});
			expect(written).toContain("413 Payload Too Large");
			expect(calls).toBe(0);
		});

		it("still accepts a body of exactly the body cap delivered in small chunks", async () => {
			const body = "c".repeat(BODY_LIMIT);
			const { written, calls, rawBody } = await drive((sock) => {
				const bytes = request(body);
				for (let at = 0; at < bytes.length; at += 4096) {
					sock.feed(Buffer.from(bytes.subarray(at, at + 4096)));
				}
			});
			expect(written).toContain("204 No Content");
			expect(calls).toBe(1);
			expect(rawBody?.length).toBe(BODY_LIMIT);
		});

		/** A body-less request whose head terminator starts at byte `sep`. */
		const headEndingAt = (sep: number) =>
			Buffer.from(`POST / HTTP/1.1\r\nContent-Length: 0\r\nX: ${"a".repeat(sep - 39)}\r\n\r\n`);

		it.each([
			["one chunk", (b: Buffer) => [b]],
			["terminator split across chunks", (b: Buffer) => [b.subarray(0, b.length - 2), b.subarray(b.length - 2)]],
			["one byte at a time", (b: Buffer) => Array.from(b, (_, i) => b.subarray(i, i + 1))],
		])("accepts a head whose terminator starts at exactly 16 KiB (%s)", async (_name, chunks) => {
			const { written, calls } = await drive((sock) => {
				for (const c of chunks(headEndingAt(16 * 1024))) sock.feed(Buffer.from(c));
			});
			expect(written).toContain("204 No Content");
			expect(calls).toBe(1);
		});

		it.each([
			["one chunk", (b: Buffer) => [b]],
			["terminator split across chunks", (b: Buffer) => [b.subarray(0, b.length - 2), b.subarray(b.length - 2)]],
			["one byte at a time", (b: Buffer) => Array.from(b, (_, i) => b.subarray(i, i + 1))],
		])("400s a head whose terminator starts one byte past 16 KiB (%s)", async (_name, chunks) => {
			const { written, calls } = await drive((sock) => {
				for (const c of chunks(headEndingAt(16 * 1024 + 1))) sock.feed(Buffer.from(c));
			});
			expect(written).toContain("400 Bad Request");
			expect(calls).toBe(0);
		});

		it("dispatches a complete request and drops trailing bytes past its Content-Length", async () => {
			const { written, calls, rawBody } = await drive((sock) => {
				sock.feed(Buffer.concat([request("hello"), Buffer.alloc(200 * 1024, 0x64)]));
			});
			expect(written).toContain("204 No Content");
			expect(calls).toBe(1);
			expect(Buffer.from(rawBody ?? []).toString()).toBe("hello");
		});

		it("destroys the socket after the 413 so a peer that keeps sending cannot hold it", async () => {
			const sock = new StubSocket();
			handleConnection(sock as unknown as TLSSocket, async () => RELAYED);
			const done = onResponse(sock);
			sock.feed(request("", BODY_LIMIT + 1));
			await done;
			expect(sock.destroyed).toBe(true);
		});
	});
});
