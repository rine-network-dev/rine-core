// The per-request relay adapter in
// rine-core `src/funnel/relay-adapter.ts`. Given the plaintext HTTP request that
// the local TLS listener produced from one mux conn, the adapter:
//   (a) HMAC-verifies the RAW body (X-Hub-Signature-256 "sha256=<hex>" OR the
//       generic X-Hook-Signature) using crypto.timingSafeEqual over equal-length
//       buffers (length-mismatch fails SAFELY, no timing leak);
//   (b) on success: sealForAgent (hpke-hybrid-v2) → self-send
//       POST /messages with type "rine.v1.webhook" + metadata["rine.hook_name"]
//       (NO conversation_id — MessageCreate has no such field);
//   (c) on failure: drops the conn (verify_failed) — rine never saw cleartext.
//
// FROZEN-CONTRACT (a violation is a build defect):
//  - The relay uses the EXISTING client send path: sealForAgent + POST /messages.
//    encryption_version stays "hpke-hybrid-v2" — NO new encryption_version,
//    NO server-sealed-v1, NO server crypto. type is EXACTLY "rine.v1.webhook".
//    The relay self-addresses (from==to==agentId), so the message verifies as
//    the agent (self-send exception, type-literal).
//  - No-body-log: the relay NEVER logs the raw body, the decrypted payload, the
//    HMAC secret, or the signature value — only verify outcome + counters/IDs.
//
// All externals are MOCKED (the HTTP client, the rine-core crypto path). The
// module under test does NOT exist yet (Track E creates it); these MUST fail now
// for the right reason (missing module / missing export).

import { createHmac, randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import * as message from "../../src/crypto/message.js";
// Module under test — does NOT exist yet.
import { handleWebhookRequest } from "../../src/funnel/relay-adapter.js";

const AGENT_ID = "11111111-1111-1111-1111-111111111111";
const HOOK_NAME = "github";
// A stable, recognizable sentinel secret + body for the no-body-log proof.
const SECRET = "f".repeat(64);
const SENTINEL_BODY = '{"action":"opened","SENTINEL_SECRET_BODY_MARKER":true}';

function sign(secret: string, body: string): string {
	return `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
}

function fakeClient(): {
	post: ReturnType<typeof vi.fn>;
	get: ReturnType<typeof vi.fn>;
} {
	return { post: vi.fn().mockResolvedValue({ id: "msg-1" }), get: vi.fn() };
}

function makeDeps(over: Record<string, unknown> = {}) {
	return {
		configDir: "/tmp/relay-cfg",
		agentId: AGENT_ID,
		hookName: HOOK_NAME,
		secret: SECRET,
		client: fakeClient(),
		...over,
	};
}

beforeEach(() => {
	vi.spyOn(message, "sealForAgent").mockResolvedValue({
		encrypted_payload: "BASE64URL_OPAQUE_CIPHERTEXT",
		encryption_version: "hpke-hybrid-v2",
		sender_signing_kid: `rine:${AGENT_ID}#0`,
	} as never);
});

afterEach(() => {
	vi.restoreAllMocks();
});

// ── HMAC verify → encrypt → self-send ───────────────────────────

describe("relay adapter — verify success path", () => {
	it("verifies X-Hub-Signature-256 over the raw body, then self-sends hpke-hybrid-v2", async () => {
		const deps = makeDeps();
		await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign(SECRET, SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});

		expect(message.sealForAgent).toHaveBeenCalledTimes(1);
		expect(deps.client.post).toHaveBeenCalledTimes(1);
		const [path, body] = deps.client.post.mock.calls[0] ?? [];
		expect(path).toBe("/messages");
		expect((body as Record<string, unknown>).encryption_version).toBe(
			"hpke-hybrid-v2",
		);
		// No new encryption_version / no server-sealed branch ever.
		expect((body as Record<string, unknown>).encryption_version).not.toMatch(
			/server-sealed/,
		);
	});

	it("accepts the generic X-Hook-Signature header as an alternative", async () => {
		const deps = makeDeps();
		await handleWebhookRequest(deps, {
			headers: { "x-hook-signature": sign(SECRET, SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		expect(deps.client.post).toHaveBeenCalledTimes(1);
	});

	it("computes the HMAC over the EXACT raw bytes (no JSON re-serialization)", async () => {
		// A body with whitespace that JSON.stringify would normalize away — the
		// signature only matches if the relay hashes the raw bytes verbatim.
		const rawSpacey = '{ "a" :  1 }';
		const deps = makeDeps();
		await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign(SECRET, rawSpacey) },
			rawBody: Buffer.from(rawSpacey),
		});
		expect(deps.client.post).toHaveBeenCalledTimes(1);
	});

	it("addresses the agent itself (self-send) so it verifies as the agent", async () => {
		const deps = makeDeps();
		await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign(SECRET, SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		const body = deps.client.post.mock.calls[0]?.[1] as Record<string, unknown>;
		expect(body.to_agent_id ?? body.to).toBe(AGENT_ID);
		// The seal names the same agent as sender and recipient (self-send).
		expect(message.sealForAgent).toHaveBeenCalledWith(
			deps.client,
			deps.configDir,
			{ senderAgentId: AGENT_ID, recipientAgentId: AGENT_ID },
			expect.anything(),
		);
	});
});

// ── Envelope metadata + type ────────────────────────────────────

describe("relay adapter — message envelope metadata", () => {
	it("sets type=rine.v1.webhook and metadata[rine.hook_name]", async () => {
		const deps = makeDeps();
		await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign(SECRET, SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		const body = deps.client.post.mock.calls[0]?.[1] as Record<string, unknown>;
		expect(body.type).toBe("rine.v1.webhook");
		expect((body.metadata as Record<string, unknown>)["rine.hook_name"]).toBe(
			HOOK_NAME,
		);
	});

	it("does NOT carry a conversation_id (MessageCreate has no such field)", async () => {
		const deps = makeDeps();
		await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign(SECRET, SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		const body = deps.client.post.mock.calls[0]?.[1] as Record<string, unknown>;
		expect("conversation_id" in body).toBe(false);
	});
});

// ── Failure paths: constant-time, drop, no post ──────────────────

describe("relay adapter — verify failure path", () => {
	it("drops the conn and does NOT post when the HMAC is wrong", async () => {
		const deps = makeDeps();
		const result = await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign("wrong-secret", SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		expect(deps.client.post).not.toHaveBeenCalled();
		expect(message.sealForAgent).not.toHaveBeenCalled();
		expect(result.verified).toBe(false);
	});

	it("treats a missing signature header as a verify failure (drop)", async () => {
		const deps = makeDeps();
		const result = await handleWebhookRequest(deps, {
			headers: {},
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		expect(deps.client.post).not.toHaveBeenCalled();
		expect(result.verified).toBe(false);
	});

	it("fails safely on a length-mismatched signature (no timing leak, no post)", async () => {
		const deps = makeDeps();
		// A digest of the wrong length must not crash timingSafeEqual and must fail.
		const result = await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": "sha256=deadbeef" },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		expect(deps.client.post).not.toHaveBeenCalled();
		expect(result.verified).toBe(false);
	});

	it("a seal failure drops the conn but does not throw out of the tunnel", async () => {
		vi.spyOn(message, "sealForAgent").mockRejectedValue(
			new Error("keys 404"),
		);
		const deps = makeDeps();
		const result = await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign(SECRET, SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		// Verify passed but the send failed: the conn is dropped, the tunnel survives.
		expect(deps.client.post).not.toHaveBeenCalled();
		expect(result.relayed).toBe(false);
	});
});

// ── Empty-secret fail-closed (forged HMAC("",body) must NOT verify) ──────

describe("relay adapter — empty-secret fail-closed", () => {
	it('rejects an attacker-forged sha256=HMAC("", body) when the secret is empty', async () => {
		// The attacker controls the body AND signs it with the empty key — the same
		// computation a fail-OPEN relay would do, so this must fail closed.
		const deps = makeDeps({ secret: "" });
		const result = await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign("", SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		expect(result.verified).toBe(false);
		expect(result.relayed).toBe(false);
		expect(deps.client.post).not.toHaveBeenCalled();
		expect(message.sealForAgent).not.toHaveBeenCalled();
	});

	it("rejects a bare X-Hook-Signature forged with the empty key", async () => {
		const deps = makeDeps({ secret: "" });
		const result = await handleWebhookRequest(deps, {
			headers: { "x-hook-signature": sign("", SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		expect(result.verified).toBe(false);
		expect(deps.client.post).not.toHaveBeenCalled();
	});
});

// ── Verified-sender, untrusted-content marker ────────────────────────────

describe("relay adapter — content-trust marker", () => {
	it("marks the relayed message as untrusted-external content alongside the hook name", async () => {
		const deps = makeDeps();
		await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign(SECRET, SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		const body = deps.client.post.mock.calls[0]?.[1] as Record<string, unknown>;
		const metadata = body.metadata as Record<string, unknown>;
		expect(metadata["rine.content_trust"]).toBe("untrusted-external");
		// The frozen contract is preserved: same type, self-addressed, hook_name kept.
		expect(body.type).toBe("rine.v1.webhook");
		expect(body.to_agent_id).toBe(AGENT_ID);
		expect(metadata["rine.hook_name"]).toBe(HOOK_NAME);
	});
});

// ── No-body-log behavioral proof ─────────────────────────────

describe("relay adapter — no-body-log", () => {
	function captureAllLogs(): {
		lines: string[];
		lifecycle: Record<string, unknown>[];
	} {
		const lines: string[] = [];
		const lifecycle: Record<string, unknown>[] = [];
		for (const m of ["log", "info", "warn", "error", "debug"] as const) {
			vi.spyOn(console, m).mockImplementation((...args: unknown[]) =>
				lines.push(
					args
						.map((a) => (typeof a === "string" ? a : JSON.stringify(a)))
						.join(" "),
				),
			);
		}
		return { lines, lifecycle };
	}

	function assertNoLeak(
		lines: string[],
		lifecycle: Record<string, unknown>[],
	): void {
		const haystack = [...lines, JSON.stringify(lifecycle)].join("\n");
		expect(haystack).not.toContain(SECRET);
		expect(haystack).not.toContain(SENTINEL_BODY);
		expect(haystack).not.toContain("SENTINEL_SECRET_BODY_MARKER");
	}

	it("verify-success never logs the raw body or the secret; lifecycle carries no body", async () => {
		const cap = captureAllLogs();
		const deps = makeDeps({
			emitLifecycle: (ev: Record<string, unknown>) => cap.lifecycle.push(ev),
		});
		await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign(SECRET, SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		assertNoLeak(cap.lines, cap.lifecycle);
		// A webhook_relayed lifecycle event may carry hook_name + message_id, NEVER body.
		const relayed = cap.lifecycle.find(
			(e) =>
				(e.data as Record<string, unknown>)?.state === "webhook_relayed" ||
				e.state === "webhook_relayed",
		);
		if (relayed) {
			const data = (relayed.data ?? relayed) as Record<string, unknown>;
			expect(data.hook_name).toBe(HOOK_NAME);
			expect("body" in data || "payload" in data || "raw" in data).toBe(false);
		}
	});

	it("bad-HMAC drop never logs the body, the secret, or the signature value", async () => {
		const cap = captureAllLogs();
		const badSig = sign("attacker-secret", SENTINEL_BODY);
		const deps = makeDeps({
			emitLifecycle: (ev: Record<string, unknown>) => cap.lifecycle.push(ev),
		});
		await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": badSig },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		assertNoLeak(cap.lines, cap.lifecycle);
		const haystack = [...cap.lines, JSON.stringify(cap.lifecycle)].join("\n");
		expect(haystack).not.toContain(badSig);
	});

	it("error-branch (seal fails after verify) never logs the body or secret", async () => {
		vi.spyOn(message, "sealForAgent").mockRejectedValue(
			new Error("keys 500"),
		);
		const cap = captureAllLogs();
		const deps = makeDeps({
			emitLifecycle: (ev: Record<string, unknown>) => cap.lifecycle.push(ev),
		});
		await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign(SECRET, SENTINEL_BODY) },
			rawBody: Buffer.from(SENTINEL_BODY),
		});
		assertNoLeak(cap.lines, cap.lifecycle);
	});

	it("a randomly-generated body+secret pair also never appears in any log", async () => {
		const cap = captureAllLogs();
		const secret = randomBytes(32).toString("hex");
		const body = JSON.stringify({ nonce: randomBytes(16).toString("hex") });
		const deps = makeDeps({
			secret,
			emitLifecycle: (ev: Record<string, unknown>) => cap.lifecycle.push(ev),
		});
		await handleWebhookRequest(deps, {
			headers: { "x-hub-signature-256": sign(secret, body) },
			rawBody: Buffer.from(body),
		});
		const haystack = [...cap.lines, JSON.stringify(cap.lifecycle)].join("\n");
		expect(haystack).not.toContain(secret);
		expect(haystack).not.toContain(body);
	});
});
