import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bytesToHex } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentKeysResponse } from "../../src/api-types.js";
import { TtlCache } from "../../src/cache.js";
import { fetchRecipientKeys } from "../../src/crypto/agent-keys.js";
import {
	type AgentKeys,
	generateAgentKeys,
	saveAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
} from "../../src/crypto/keys.js";
import { decryptMessage, encryptMessage } from "../../src/crypto/message.js";
import { HttpClient } from "../../src/http.js";

const SENDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const RECIPIENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";

function keysResponse(agentId: string, keys: AgentKeys): AgentKeysResponse {
	return {
		agent_id: agentId,
		signing_public_key: signingPublicKeyToJWK(keys.signing.publicKey),
		encryption_public_key: {
			kty: "OKP",
			crv: "X25519",
			x: toBase64Url(keys.encryption.publicKey),
		},
	};
}

/** Derived independently of the implementation, straight from the raw key. */
function fingerprint(keys: AgentKeys): string {
	return bytesToHex(sha256(keys.signing.publicKey));
}

describe("per-client key cache", () => {
	let dir: string;
	let recipientKeys: AgentKeys;
	let senderKeys: AgentKeys;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-keycache-test-"));
		senderKeys = generateAgentKeys();
		recipientKeys = generateAgentKeys();
		saveAgentKeys(dir, SENDER_ID, senderKeys);
		saveAgentKeys(dir, RECIPIENT_ID, recipientKeys);
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
	});

	it("serves a cache hit without touching the network", async () => {
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ m: "hi" },
		);
		const cache = new TtlCache<AgentKeysResponse>();
		cache.set(SENDER_ID, keysResponse(SENDER_ID, senderKeys));
		const get = vi.fn();
		const client = { get, post: vi.fn(), keyCache: cache };

		const result = await decryptMessage(
			dir,
			RECIPIENT_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);
		expect(result.verified).toBe(true);
		expect(result.verificationStatus).toBe("verified");
		expect(get).not.toHaveBeenCalled();
	});

	it("verifies twice off one fetch on a client given no explicit cache", async () => {
		// Every client builds a cache for itself. Without that default the whole
		// verify-side cache — and the rotation refetch it gates — is unreachable in
		// production, because no caller passes one in.
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ m: "hi" },
		);
		const body = JSON.stringify(keysResponse(SENDER_ID, senderKeys));
		const fetchSpy = vi.fn(
			async () =>
				new Response(body, {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
		);
		vi.stubGlobal("fetch", fetchSpy);
		const client = new HttpClient({
			apiUrl: "https://api.test",
			tokenFn: async () => "token",
		});

		for (let i = 0; i < 2; i++) {
			const result = await decryptMessage(
				dir,
				RECIPIENT_ID,
				encrypted.encrypted_payload,
				client,
				SENDER_ID,
			);
			expect(result.verified).toBe(true);
		}
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});

	it("refetches once past a stale cached key, then verifies and reports the change", async () => {
		// The sender rotated: it signs with the CURRENT on-disk key, but the cache
		// still holds a stale (different) signing key.
		const stale = generateAgentKeys();
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ m: "rotated" },
		);
		const cache = new TtlCache<AgentKeysResponse>();
		cache.set(SENDER_ID, keysResponse(SENDER_ID, stale));
		const get = vi.fn().mockResolvedValue(keysResponse(SENDER_ID, senderKeys));
		const client = { get, post: vi.fn(), keyCache: cache };

		const result = await decryptMessage(
			dir,
			RECIPIENT_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);
		expect(result.verified).toBe(true);
		expect(result.verificationStatus).toBe("verified");
		expect(result.keyChanged).toEqual({
			agentId: SENDER_ID,
			previousFingerprint: fingerprint(stale),
			currentFingerprint: fingerprint(senderKeys),
		});
		expect(get).toHaveBeenCalledTimes(1); // exactly one bypass refetch
		// Cache refreshed to the current key.
		expect(cache.get(SENDER_ID)).toEqual(keysResponse(SENDER_ID, senderKeys));
	});

	it("reports the key change even when the replacement key also fails", async () => {
		// A rotation that does not rescue the signature is still a rotation the
		// recipient should be told about — the signal is about the key, not the
		// verdict.
		const cached = generateAgentKeys();
		const replacement = generateAgentKeys();
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ m: "spoof" },
		);
		const cache = new TtlCache<AgentKeysResponse>();
		cache.set(SENDER_ID, keysResponse(SENDER_ID, cached));
		const get = vi.fn().mockResolvedValue(keysResponse(SENDER_ID, replacement));
		const client = { get, post: vi.fn(), keyCache: cache };

		const result = await decryptMessage(
			dir,
			RECIPIENT_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);
		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("invalid");
		expect(result.keyChanged).toEqual({
			agentId: SENDER_ID,
			previousFingerprint: fingerprint(cached),
			currentFingerprint: fingerprint(replacement),
		});
		expect(get).toHaveBeenCalledTimes(1);
	});

	it("reports no change, and stops, when the refetch returns the same key", async () => {
		const imposter = generateAgentKeys();
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ m: "spoof" },
		);
		const cache = new TtlCache<AgentKeysResponse>();
		cache.set(SENDER_ID, keysResponse(SENDER_ID, imposter));
		const get = vi.fn().mockResolvedValue(keysResponse(SENDER_ID, imposter));
		const client = { get, post: vi.fn(), keyCache: cache };

		const result = await decryptMessage(
			dir,
			RECIPIENT_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);
		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("invalid");
		expect(result.keyChanged).toBeUndefined();
		// One bounded refetch and then it stops: retrying until something verifies
		// would let whoever answers the key endpoint keep guessing.
		expect(get).toHaveBeenCalledTimes(1);
	});

	it("does not double-fetch when a freshly-fetched key is genuinely wrong", async () => {
		const imposter = generateAgentKeys();
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ m: "spoof" },
		);
		const get = vi.fn().mockResolvedValue(keysResponse(SENDER_ID, imposter));
		const client = {
			get,
			post: vi.fn(),
			keyCache: new TtlCache<AgentKeysResponse>(),
		};

		const result = await decryptMessage(
			dir,
			RECIPIENT_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);
		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("invalid");
		expect(result.keyChanged).toBeUndefined();
		expect(get).toHaveBeenCalledTimes(1); // fresh miss → fetched once, not refetched
	});

	it("keeps the send path off the cache, so a peer's rotation is sealed to at once", async () => {
		// A seal has no failure signal that could correct it later, so it must never
		// reuse a cached key. This is the asymmetry with the verify path above.
		const stale = generateAgentKeys();
		const cache = new TtlCache<AgentKeysResponse>();
		cache.set(RECIPIENT_ID, keysResponse(RECIPIENT_ID, stale));
		const get = vi
			.fn()
			.mockResolvedValue(keysResponse(RECIPIENT_ID, recipientKeys));
		const client = { get, post: vi.fn(), keyCache: cache };

		const first = await fetchRecipientKeys(client as never, RECIPIENT_ID);
		const second = await fetchRecipientKeys(client as never, RECIPIENT_ID);

		expect(first.encryption).toEqual(recipientKeys.encryption.publicKey);
		expect(second.encryption).toEqual(recipientKeys.encryption.publicKey);
		expect(get).toHaveBeenCalledTimes(2);
		// It does not write the cache either — the verify-side entry is untouched.
		expect(cache.get(RECIPIENT_ID)).toEqual(keysResponse(RECIPIENT_ID, stale));
	});
});
