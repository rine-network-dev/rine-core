import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VERSION_HYBRID, generatePqKeyPair } from "../../src/crypto/hybrid.js";
import {
	type AgentKeys,
	type KeyPair,
	fromBase64Url,
	generateAgentKeys,
	loadAgentKeys,
	pqPublicKeyToJWK,
	saveAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
} from "../../src/crypto/keys.js";
import {
	decryptMessage,
	encryptMessage,
	fetchRecipientKeys,
	getAgentPublicKeys,
} from "../../src/crypto/message.js";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-hybrid-test-"));
}

const SENDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const RECIPIENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";

function setupHybridAgent(dir: string, agentId: string): AgentKeys {
	const keys = generateAgentKeys();
	saveAgentKeys(dir, agentId, keys);
	return keys;
}

function setupClassicalAgent(dir: string, agentId: string): AgentKeys {
	const { pqEncryption: _, ...rest } = generateAgentKeys();
	const keys: AgentKeys = rest;
	saveAgentKeys(dir, agentId, keys);
	return keys;
}

function requirePq(keys: AgentKeys): KeyPair {
	if (!keys.pqEncryption) throw new Error("expected PQ key to be present");
	return keys.pqEncryption;
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
	return Buffer.from(a).equals(Buffer.from(b));
}

function mockClient(senderKeys: AgentKeys) {
	return {
		get: vi.fn().mockResolvedValue({
			agent_id: SENDER_ID,
			signing_public_key: signingPublicKeyToJWK(senderKeys.signing.publicKey),
			encryption_public_key: {
				kty: "OKP",
				crv: "X25519",
				x: toBase64Url(senderKeys.encryption.publicKey),
			},
		}),
		post: vi.fn(),
	};
}

describe("hybrid PQ disk key persistence", () => {
	let dir: string;
	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("saves and reloads the PQ key, deriving the matching public key", () => {
		const keys = setupHybridAgent(dir, SENDER_ID);
		expect(
			fs.existsSync(join(dir, "keys", SENDER_ID, "pq_encryption.key")),
		).toBe(true);

		const loaded = loadAgentKeys(dir, SENDER_ID);
		expect(loaded.pqEncryption).toBeDefined();
		expect(eq(requirePq(loaded).privateKey, requirePq(keys).privateKey)).toBe(
			true,
		);
		expect(eq(requirePq(loaded).publicKey, requirePq(keys).publicKey)).toBe(
			true,
		);
	});

	it("classical agents have no PQ key on disk or in memory", () => {
		setupClassicalAgent(dir, RECIPIENT_ID);
		expect(
			fs.existsSync(join(dir, "keys", RECIPIENT_ID, "pq_encryption.key")),
		).toBe(false);
		expect(loadAgentKeys(dir, RECIPIENT_ID).pqEncryption).toBeUndefined();
	});
});

describe("getAgentPublicKeys PQ exposure", () => {
	let dir: string;
	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("includes pq_encryption_public_key only when present", () => {
		setupHybridAgent(dir, SENDER_ID);
		setupClassicalAgent(dir, RECIPIENT_ID);

		const hybrid = getAgentPublicKeys(dir, SENDER_ID);
		expect(hybrid.pq_encryption_public_key).toBeDefined();
		expect(hybrid.pq_encryption_public_key?.kty).toBe("MLKEM");
		expect(hybrid.pq_encryption_public_key?.alg).toBe("ML-KEM-768");

		const classical = getAgentPublicKeys(dir, RECIPIENT_ID);
		expect(classical.pq_encryption_public_key).toBeUndefined();
	});
});

describe("fetchRecipientKeys negotiation", () => {
	it("decodes the PQ key when the server returns it", async () => {
		const pq = generatePqKeyPair();
		const client = {
			get: vi.fn().mockResolvedValue({
				agent_id: RECIPIENT_ID,
				signing_public_key: { kty: "OKP", crv: "Ed25519", x: "x" },
				encryption_public_key: {
					kty: "OKP",
					crv: "X25519",
					x: toBase64Url(generateAgentKeys().encryption.publicKey),
				},
				pq_encryption_public_key: pqPublicKeyToJWK(pq.publicKey),
			}),
			post: vi.fn(),
		};
		const keys = await fetchRecipientKeys(client as never, RECIPIENT_ID);
		const fetchedPq = keys.pqEncryption;
		expect(fetchedPq).toBeDefined();
		if (!fetchedPq) throw new Error("unreachable");
		expect(eq(fetchedPq, pq.publicKey)).toBe(true);
	});

	it("omits the PQ key for a classical-only recipient", async () => {
		const client = {
			get: vi.fn().mockResolvedValue({
				agent_id: RECIPIENT_ID,
				signing_public_key: { kty: "OKP", crv: "Ed25519", x: "x" },
				encryption_public_key: {
					kty: "OKP",
					crv: "X25519",
					x: toBase64Url(generateAgentKeys().encryption.publicKey),
				},
			}),
			post: vi.fn(),
		};
		const keys = await fetchRecipientKeys(client as never, RECIPIENT_ID);
		expect(keys.pqEncryption).toBeUndefined();
	});
});

describe("encryptMessage auto-negotiation", () => {
	let dir: string;
	let senderKeys: AgentKeys;
	let recipientKeys: AgentKeys;

	beforeEach(() => {
		dir = makeTmpDir();
		senderKeys = setupClassicalAgent(dir, SENDER_ID);
		recipientKeys = setupHybridAgent(dir, RECIPIENT_ID);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("uses hpke-hybrid-v1 and roundtrips when the recipient has a PQ key", async () => {
		const payload = { task: "translate", text: "quantum-safe" };
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			payload,
			requirePq(recipientKeys).publicKey,
		);

		expect(encrypted.encryption_version).toBe("hpke-hybrid-v1");

		const client = mockClient(senderKeys);
		const result = await decryptMessage(
			dir,
			RECIPIENT_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);
		expect(JSON.parse(result.plaintext as string)).toEqual(payload);
		expect(result.verified).toBe(true);
	});

	it("falls back to hpke-v1 when no PQ key is supplied (backward compat)", async () => {
		const payload = { msg: "classical" };
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			payload,
		);
		expect(encrypted.encryption_version).toBe("hpke-v1");

		const client = mockClient(senderKeys);
		const result = await decryptMessage(
			dir,
			RECIPIENT_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);
		expect(JSON.parse(result.plaintext as string)).toEqual(payload);
	});

	it("treats an empty PQ key as classical (no false hybrid)", async () => {
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ msg: "x" },
			new Uint8Array(0),
		);
		expect(encrypted.encryption_version).toBe("hpke-v1");
	});
});

describe("self-seal negotiation (independent of recipient)", () => {
	let dir: string;
	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("a PQ-capable sender produces a HYBRID self-blob", async () => {
		setupHybridAgent(dir, SENDER_ID);
		const recipientKeys = setupHybridAgent(dir, RECIPIENT_ID);
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ msg: "pq" },
			requirePq(recipientKeys).publicKey,
		);
		expect(encrypted.self_encrypted_payload).toBeDefined();
		const selfBytes = fromBase64Url(encrypted.self_encrypted_payload as string);
		expect(selfBytes[0]).toBe(VERSION_HYBRID);
	});

	it("a classical sender produces a CLASSICAL self-blob", async () => {
		setupClassicalAgent(dir, SENDER_ID);
		const recipientKeys = setupHybridAgent(dir, RECIPIENT_ID);
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ msg: "classical" },
			requirePq(recipientKeys).publicKey,
		);
		expect(encrypted.self_encrypted_payload).toBeDefined();
		const selfBytes = fromBase64Url(encrypted.self_encrypted_payload as string);
		expect(selfBytes[0]).not.toBe(VERSION_HYBRID);
	});

	it("PQ sender → classical recipient: recipient is hpke-v1, self-blob is hybrid", async () => {
		const senderKeys = setupHybridAgent(dir, SENDER_ID);
		const recipientKeys = setupClassicalAgent(dir, RECIPIENT_ID);
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ msg: "asymmetric" },
			// recipient has no PQ key → classical recipient negotiation
		);
		// Recipient blob negotiates on the recipient: classical → hpke-v1.
		expect(encrypted.encryption_version).toBe("hpke-v1");
		// Self-blob negotiates on the SENDER: PQ-capable → hybrid.
		const selfBytes = fromBase64Url(encrypted.self_encrypted_payload as string);
		expect(selfBytes[0]).toBe(VERSION_HYBRID);

		// And the hybrid self-blob round-trips for the PQ-capable sender.
		const client = mockClient(senderKeys);
		const result = await decryptMessage(
			dir,
			SENDER_ID,
			encrypted.self_encrypted_payload as string,
			client as never,
			SENDER_ID,
		);
		expect(JSON.parse(result.plaintext as string)).toEqual({ msg: "asymmetric" });
		expect(result.verified).toBe(true);
	});

	it("hybrid self-read round-trips for a PQ-capable sender", async () => {
		const senderKeys = setupHybridAgent(dir, SENDER_ID);
		const recipientKeys = setupHybridAgent(dir, RECIPIENT_ID);
		const payload = { recall: "turn-1-fact" };
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			payload,
			requirePq(recipientKeys).publicKey,
		);
		const client = mockClient(senderKeys);
		const result = await decryptMessage(
			dir,
			SENDER_ID,
			encrypted.self_encrypted_payload as string,
			client as never,
			SENDER_ID,
		);
		expect(JSON.parse(result.plaintext as string)).toEqual(payload);
		expect(result.verified).toBe(true);
		expect(result.verificationStatus).toBe("verified");
	});
});

describe("decryptMessage version dispatch", () => {
	let dir: string;
	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("rejects a hybrid message when the recipient has no PQ key", async () => {
		const senderKeys = setupClassicalAgent(dir, SENDER_ID);
		const recipientKeys = setupHybridAgent(dir, RECIPIENT_ID);

		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ msg: "hi" },
			requirePq(recipientKeys).publicKey,
		);

		// Re-save the recipient without a PQ key to simulate a classical-only client.
		fs.rmSync(join(dir, "keys", RECIPIENT_ID), { recursive: true });
		saveAgentKeys(dir, RECIPIENT_ID, {
			signing: recipientKeys.signing,
			encryption: recipientKeys.encryption,
		});

		const client = mockClient(senderKeys);
		await expect(
			decryptMessage(
				dir,
				RECIPIENT_ID,
				encrypted.encrypted_payload,
				client as never,
				SENDER_ID,
			),
		).rejects.toThrow("no PQ encryption key");
	});
});
