import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

describe("per-client key cache (REQ-TS-04, D-5)", () => {
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
		);
		expect(result.verified).toBe(true);
		expect(result.verificationStatus).toBe("verified");
		expect(get).not.toHaveBeenCalled();
	});

	it("refetches once past the cache when a stale key fails verification, then verifies", async () => {
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
		);
		expect(result.verified).toBe(true);
		expect(result.verificationStatus).toBe("verified");
		expect(get).toHaveBeenCalledTimes(1); // exactly one bypass refetch
		// Cache refreshed to the current key.
		expect(cache.get(SENDER_ID)).toEqual(keysResponse(SENDER_ID, senderKeys));
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
		);
		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("invalid");
		expect(get).toHaveBeenCalledTimes(1); // fresh miss → fetched once, not refetched
	});

	it("fetchRecipientKeys reuses the cached entry across calls", async () => {
		const cache = new TtlCache<AgentKeysResponse>();
		const get = vi
			.fn()
			.mockResolvedValue(keysResponse(RECIPIENT_ID, recipientKeys));
		const client = { get, post: vi.fn(), keyCache: cache };

		const first = await fetchRecipientKeys(client as never, RECIPIENT_ID);
		const second = await fetchRecipientKeys(client as never, RECIPIENT_ID);
		expect(get).toHaveBeenCalledTimes(1);
		expect(second.encryption).toEqual(first.encryption);
	});
});
