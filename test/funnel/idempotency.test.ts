// Relay-side webhook replay de-dup. Two layers:
//   (1) the bounded IdempotencyStore in isolation (LRU + TTL eviction, refresh);
//   (2) the relay adapter wired with a store: a replayed delivery (same
//       x-github-delivery, else identical body) is DROPPED after verify with no
//       second self-send, while a distinct delivery still relays.
// All externals (the HTTP client, the rine-core crypto path) are MOCKED — DB-free.

import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import * as message from "../../src/crypto/message.js";
import { IdempotencyStore } from "../../src/funnel/idempotency-store.js";
import {
	type WebhookRequest,
	handleWebhookRequest,
} from "../../src/funnel/relay-adapter.js";

const AGENT_ID = "11111111-1111-1111-1111-111111111111";
const HOOK_NAME = "github";
const SECRET = "f".repeat(64);

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

/** A signed request whose body+signature match SECRET. */
function signedReq(
	body: string,
	extraHeaders: Record<string, string> = {},
): WebhookRequest {
	return {
		headers: { "x-hub-signature-256": sign(SECRET, body), ...extraHeaders },
		rawBody: Buffer.from(body),
	};
}

beforeEach(() => {
	vi.spyOn(message, "sealForAgent").mockResolvedValue({
		encrypted_payload: "BASE64URL_OPAQUE_CIPHERTEXT",
		encryption_version: "hpke-hybrid-v2",
		sender_signing_kid: `rine:${AGENT_ID}`,
	} as never);
});

afterEach(() => {
	vi.restoreAllMocks();
});

// ── Layer 1: the bounded store in isolation ─────────────────────────────────

describe("IdempotencyStore — bounded TTL/LRU set", () => {
	it("reports a first sighting as new and the immediate re-sighting as a duplicate", () => {
		const store = new IdempotencyStore();
		expect(store.seen("k1")).toBe(false);
		expect(store.seen("k1")).toBe(true);
		expect(store.seen("k2")).toBe(false);
	});

	it("treats an entry whose TTL has elapsed as absent again (no false duplicate)", () => {
		let clock = 1_000_000;
		const store = new IdempotencyStore({ ttlMs: 1000, now: () => clock });
		expect(store.seen("k")).toBe(false);
		clock += 999; // still inside the window
		expect(store.seen("k")).toBe(true);
		clock += 1001; // now past TTL relative to the refresh above
		expect(store.seen("k")).toBe(false);
	});

	it("evicts the oldest key when the live set exceeds maxEntries (LRU bound)", () => {
		const store = new IdempotencyStore({ maxEntries: 3 });
		expect(store.seen("a")).toBe(false);
		expect(store.seen("b")).toBe(false);
		expect(store.seen("c")).toBe(false);
		expect(store.seen("d")).toBe(false); // overflow → evicts "a"
		expect(store.size).toBe(3);
		// "a" was evicted, so it is admitted as new again; "b"/"c"/"d" still hit.
		expect(store.seen("a")).toBe(false);
		expect(store.seen("c")).toBe(true);
	});

	it("re-seeing a live key refreshes its recency so it survives overflow (hot key)", () => {
		const store = new IdempotencyStore({ maxEntries: 3 });
		store.seen("a");
		store.seen("b");
		store.seen("c");
		expect(store.seen("a")).toBe(true); // touch "a" → now newest; "b" is oldest
		store.seen("d"); // overflow → evicts "b", not the refreshed "a"
		expect(store.seen("a")).toBe(true);
		expect(store.seen("b")).toBe(false); // "b" was the one evicted
	});

	it("never grows beyond maxEntries under a flood of distinct keys", () => {
		const store = new IdempotencyStore({ maxEntries: 8 });
		for (let i = 0; i < 1000; i++) store.seen(`flood-${i}`);
		expect(store.size).toBe(8);
	});
});

// ── Layer 2: the adapter wired with a store ─────────────────────────────────

describe("relay adapter — replay de-dup", () => {
	const DELIVERY = "1f2e3d4c-5b6a-7980-1a2b-3c4d5e6f7a8b";
	const BODY = '{"action":"opened","number":1}';

	it("relays the first delivery, then DROPS a replay of the same delivery-id (no second self-send)", async () => {
		const idempotency = new IdempotencyStore();
		const deps = makeDeps({ idempotency });
		const req = signedReq(BODY, { "x-github-delivery": DELIVERY });

		const first = await handleWebhookRequest(deps, req);
		expect(first).toMatchObject({
			verified: true,
			relayed: true,
			duplicate: false,
		});
		expect(deps.client.post).toHaveBeenCalledTimes(1);

		const replay = await handleWebhookRequest(deps, req);
		expect(replay).toMatchObject({
			verified: true,
			relayed: false,
			duplicate: true,
		});
		// No SECOND post and no SECOND encrypt — the duplicate never mints a message.
		expect(deps.client.post).toHaveBeenCalledTimes(1);
		expect(message.sealForAgent).toHaveBeenCalledTimes(1);
	});

	it("drops a body-identical replay even without a delivery-id header (body-hash key)", async () => {
		const idempotency = new IdempotencyStore();
		const deps = makeDeps({ idempotency });
		const req = signedReq(BODY); // no x-github-delivery → falls back to body hash

		await handleWebhookRequest(deps, req);
		const replay = await handleWebhookRequest(deps, req);
		expect(replay.duplicate).toBe(true);
		expect(deps.client.post).toHaveBeenCalledTimes(1);
	});

	it("lets DISTINCT deliveries through (different delivery-id → both relay)", async () => {
		const idempotency = new IdempotencyStore();
		const deps = makeDeps({ idempotency });

		const a = await handleWebhookRequest(
			deps,
			signedReq(BODY, { "x-github-delivery": `${DELIVERY}-a` }),
		);
		const b = await handleWebhookRequest(
			deps,
			signedReq(BODY, { "x-github-delivery": `${DELIVERY}-b` }),
		);
		expect(a.relayed).toBe(true);
		expect(b.relayed).toBe(true);
		expect(b.duplicate).toBe(false);
		expect(deps.client.post).toHaveBeenCalledTimes(2);
	});

	it("treats distinct bodies as distinct deliveries when no delivery-id is present", async () => {
		const idempotency = new IdempotencyStore();
		const deps = makeDeps({ idempotency });

		await handleWebhookRequest(deps, signedReq('{"x":1}'));
		const second = await handleWebhookRequest(deps, signedReq('{"x":2}'));
		expect(second.duplicate).toBe(false);
		expect(deps.client.post).toHaveBeenCalledTimes(2);
	});

	it("without a store, behaviour is unchanged — replays still relay (de-dup is opt-in)", async () => {
		const deps = makeDeps(); // no idempotency store
		const req = signedReq(BODY, { "x-github-delivery": DELIVERY });
		await handleWebhookRequest(deps, req);
		const replay = await handleWebhookRequest(deps, req);
		expect(replay.duplicate).toBe(false);
		expect(replay.relayed).toBe(true);
		expect(deps.client.post).toHaveBeenCalledTimes(2);
	});

	it("a verify FAILURE never records an idempotency key (a later valid delivery still relays)", async () => {
		const idempotency = new IdempotencyStore();
		const deps = makeDeps({ idempotency });
		const body = '{"action":"closed"}';

		// Forged signature → dropped at verify, no de-dup key stored.
		const forged: WebhookRequest = {
			headers: {
				"x-hub-signature-256": sign("attacker", body),
				"x-github-delivery": "forged-delivery",
			},
			rawBody: Buffer.from(body),
		};
		const bad = await handleWebhookRequest(deps, forged);
		expect(bad.verified).toBe(false);
		expect(deps.client.post).not.toHaveBeenCalled();

		// Same delivery-id, now correctly signed → must NOT be mistaken for a replay.
		const good = signedReq(body, { "x-github-delivery": "forged-delivery" });
		const ok = await handleWebhookRequest(deps, good);
		expect(ok.relayed).toBe(true);
		expect(ok.duplicate).toBe(false);
	});

	it("never leaks the raw body into the idempotency store's keyspace", async () => {
		const idempotency = new IdempotencyStore();
		const deps = makeDeps({ idempotency });
		const marker = "SENTINEL_BODY_MARKER";
		const body = `{"secret":"${marker}"}`;
		await handleWebhookRequest(deps, signedReq(body)); // body-hash path
		// The store keys on a sha256 hex digest, never the plaintext body.
		// biome-ignore lint/suspicious/noExplicitAny: white-box reach into private map for a leak proof.
		const keys = [...(idempotency as any).entries.keys()] as string[];
		expect(keys.join("\n")).not.toContain(marker);
		expect(keys[0]).toMatch(/^body:[0-9a-f]{64}$/);
	});
});
