import * as fs from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	decryptGroupMessage,
	decryptMessage,
	encryptGroupMessage,
	encryptMessage,
	getAgentPublicKeys,
} from "../../src/crypto/message.js";
import { generateAgentKeys, saveAgentKeys, signingPublicKeyToJWK, toBase64Url } from "../../src/crypto/keys.js";
import { generateSenderKey } from "../../src/crypto/sender-keys.js";
import type { AgentKeys } from "../../src/crypto/keys.js";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-msg-test-"));
}

const SENDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const RECIPIENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

function setupAgent(dir: string, agentId: string): AgentKeys {
	const keys = generateAgentKeys();
	saveAgentKeys(dir, agentId, keys);
	return keys;
}

function mockClientWithKeys(keys: AgentKeys) {
	return {
		get: vi.fn().mockImplementation((path: string) => {
			if (path.includes("/keys")) {
				return Promise.resolve({
					agent_id: SENDER_ID,
					signing_public_key: signingPublicKeyToJWK(keys.signing.publicKey),
					encryption_public_key: {
						kty: "OKP",
						crv: "X25519",
						x: toBase64Url(keys.encryption.publicKey),
					},
				});
			}
			return Promise.reject(new Error(`Unexpected GET: ${path}`));
		}),
		post: vi.fn(),
	};
}

describe("DM encrypt/decrypt round-trip", () => {
	let dir: string;
	let senderKeys: AgentKeys;
	let recipientKeys: AgentKeys;

	beforeEach(() => {
		dir = makeTmpDir();
		senderKeys = setupAgent(dir, SENDER_ID);
		recipientKeys = setupAgent(dir, RECIPIENT_ID);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("encrypts and decrypts with verified signature", async () => {
		const payload = { task: "translate", text: "hello" };
		const encrypted = await encryptMessage(
			dir, SENDER_ID, recipientKeys.encryption.publicKey, payload,
		);

		expect(encrypted.encryption_version).toBe("hpke-v1");
		expect(encrypted.sender_signing_kid).toBe(`rine:${SENDER_ID}`);

		const client = mockClientWithKeys(senderKeys);
		const result = await decryptMessage(dir, RECIPIENT_ID, encrypted.encrypted_payload, client as never);

		expect(JSON.parse(result.plaintext)).toEqual(payload);
		expect(result.verified).toBe(true);
		expect(result.verificationStatus).toBe("verified");
		expect(result.senderKid).toBe(`rine:${SENDER_ID}`);
	});

	it("reports invalid when sender key doesn't match", async () => {
		const payload = { msg: "spoofed" };
		const encrypted = await encryptMessage(
			dir, SENDER_ID, recipientKeys.encryption.publicKey, payload,
		);

		// Return a different agent's signing key for verification
		const imposterKeys = generateAgentKeys();
		const client = mockClientWithKeys(imposterKeys);

		const result = await decryptMessage(dir, RECIPIENT_ID, encrypted.encrypted_payload, client as never);
		expect(JSON.parse(result.plaintext)).toEqual(payload);
		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("invalid");
	});

	it("reports unverifiable when key fetch fails", async () => {
		const payload = { msg: "test" };
		const encrypted = await encryptMessage(
			dir, SENDER_ID, recipientKeys.encryption.publicKey, payload,
		);

		const client = { get: vi.fn().mockRejectedValue(new Error("network error")), post: vi.fn() };
		const result = await decryptMessage(dir, RECIPIENT_ID, encrypted.encrypted_payload, client as never);
		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("unverifiable");
	});
});

describe("Group encrypt/decrypt round-trip", () => {
	let dir: string;
	let senderKeys: AgentKeys;

	beforeEach(() => {
		dir = makeTmpDir();
		senderKeys = setupAgent(dir, SENDER_ID);
		setupAgent(dir, RECIPIENT_ID);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("encrypts and decrypts group message", async () => {
		const senderState = generateSenderKey(GROUP_ID, SENDER_ID);
		const payload = { announcement: "meeting at 3pm" };

		const { result: encrypted, updatedState } = await encryptGroupMessage(
			dir, SENDER_ID, GROUP_ID, senderState, payload,
		);
		expect(encrypted.encryption_version).toBe("sender-key-v1");
		expect(updatedState.messageIndex).toBe(senderState.messageIndex + 1);

		// Recipient needs the sender's key state to decrypt
		// Simulate key distribution by writing sender state to recipient's store
		const { loadSenderKeyStates, saveSenderKeyState } = await import("../../src/crypto/sender-keys-helpers.js");
		saveSenderKeyState(dir, RECIPIENT_ID, GROUP_ID, [senderState]);

		const client = mockClientWithKeys(senderKeys);
		const decrypted = await decryptGroupMessage(
			dir, RECIPIENT_ID, GROUP_ID, encrypted.encrypted_payload, client as never,
		);

		expect(JSON.parse(decrypted.plaintext)).toEqual(payload);
		expect(decrypted.verified).toBe(true);
	});

	it("rejects group message with invalid signature", async () => {
		const senderState = generateSenderKey(GROUP_ID, SENDER_ID);
		const payload = { msg: "test" };

		const { result: encrypted } = await encryptGroupMessage(
			dir, SENDER_ID, GROUP_ID, senderState, payload,
		);

		const { saveSenderKeyState } = await import("../../src/crypto/sender-keys-helpers.js");
		saveSenderKeyState(dir, RECIPIENT_ID, GROUP_ID, [senderState]);

		// Return wrong keys — signature won't match
		const imposterKeys = generateAgentKeys();
		const client = mockClientWithKeys(imposterKeys);

		await expect(
			decryptGroupMessage(dir, RECIPIENT_ID, GROUP_ID, encrypted.encrypted_payload, client as never),
		).rejects.toThrow("Sender signature verification failed");
	});

	it("sender can decrypt own group message (self-read key)", async () => {
		const senderState = generateSenderKey(GROUP_ID, SENDER_ID);
		const payload = { self: "read" };

		const { result: encrypted } = await encryptGroupMessage(
			dir, SENDER_ID, GROUP_ID, senderState, payload,
		);

		// Sender decrypts their own message — uses cached self-read key
		const client = mockClientWithKeys(senderKeys);
		const decrypted = await decryptGroupMessage(
			dir, SENDER_ID, GROUP_ID, encrypted.encrypted_payload, client as never,
		);

		expect(JSON.parse(decrypted.plaintext)).toEqual(payload);
	});
});

describe("getAgentPublicKeys", () => {
	let dir: string;

	beforeEach(() => { dir = makeTmpDir(); });
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("returns JWK-formatted public keys", () => {
		const keys = setupAgent(dir, SENDER_ID);
		const pubKeys = getAgentPublicKeys(dir, SENDER_ID);

		expect(pubKeys.signing_public_key.kty).toBe("OKP");
		expect(pubKeys.signing_public_key.crv).toBe("Ed25519");
		expect(typeof pubKeys.signing_public_key.x).toBe("string");
		expect(pubKeys.encryption_public_key.kty).toBe("OKP");
		expect(pubKeys.encryption_public_key.crv).toBe("X25519");
		expect(typeof pubKeys.encryption_public_key.x).toBe("string");
	});
});
