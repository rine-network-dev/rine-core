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
import { handleConnection } from "../../src/funnel/tls-listener.js";

/** A minimal stand-in for the data/end/error + end()/destroy() surface used. */
class StubSocket extends EventEmitter {
	written: string | undefined;
	destroyed = false;
	end(data?: string): void {
		this.written = data;
		this.emit("_ended");
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
		handleConnection(sock as unknown as TLSSocket, async () => {});
		const done = onResponse(sock);
		sock.feed(Buffer.from("garbage-no-crlfcrlf"));
		sock.eof();
		const written = await done;
		expect(written).toContain("400 Bad Request");
	});
});
