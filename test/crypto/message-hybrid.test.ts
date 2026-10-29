import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fetchRecipientKeys } from "../../src/crypto/agent-keys.js";
import { VERSION_HYBRID_V2 } from "../../src/crypto/hybrid.js";
import { fromBase64Url, loadAgentKeys } from "../../src/crypto/keys.js";
import { decryptMessage, encryptMessage } from "../../src/crypto/message.js";
import { World, type WorldAgent } from "./world.js";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-hybrid-test-"));
}

const SENDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const RECIPIENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";

function eq(a: Uint8Array, b: Uint8Array): boolean {
	return Buffer.from(a).equals(Buffer.from(b));
}

/** The recipient's chain-verified encryption keys, as `fetchRecipientKeys` returns them. */
function recipientKeysOf(agent: WorldAgent) {
	return {
		encryption: agent.derived.x25519.publicKey,
		pqEncryption: agent.derived.mlKem768.publicKey,
	};
}

describe("hybrid PQ disk key persistence", () => {
	let dir: string;
	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("saves and reloads the PQ key, deriving the matching public key", () => {
		const world = new World();
		const agent = world.addAgent({ id: SENDER_ID });
		world.save(dir, agent);
		expect(
			fs.existsSync(join(dir, "keys", SENDER_ID, "pq_encryption.key")),
		).toBe(true);

		const loaded = loadAgentKeys(dir, SENDER_ID);
		expect(loaded.pqEncryption).toBeDefined();
		// The stored seed is the derived ML-KEM seed; the expanded secret key is
		// re-derived from it on load.
		expect(eq(loaded.pqEncryption.seed, agent.derived.mlKem768.privateKey)).toBe(
			true,
		);
		expect(eq(loaded.pqEncryption.publicKey, agent.derived.mlKem768.publicKey)).toBe(
			true,
		);
	});
});

describe("fetchRecipientKeys negotiation", () => {
	it("decodes the PQ key when the server returns it", async () => {
		const world = new World();
		const recipient = world.addAgent({ id: RECIPIENT_ID });
		const client = world.client();

		const keys = await fetchRecipientKeys(client, RECIPIENT_ID);

		expect(eq(keys.encryption, recipient.derived.x25519.publicKey)).toBe(true);
		expect(eq(keys.pqEncryption, recipient.derived.mlKem768.publicKey)).toBe(true);
	});
});

describe("encryptMessage hybrid sealing", () => {
	let dir: string;
	let world: World;
	let recipient: WorldAgent;

	beforeEach(() => {
		dir = makeTmpDir();
		world = new World();
		world.save(dir, world.addAgent({ id: SENDER_ID }));
		recipient = world.addAgent({ id: RECIPIENT_ID });
		world.save(dir, recipient);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("uses hpke-hybrid-v2 and roundtrips when the recipient has a PQ key", async () => {
		const payload = { task: "translate", text: "quantum-safe" };
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			RECIPIENT_ID,
			recipientKeysOf(recipient),
			payload,
		);

		expect(encrypted.encryption_version).toBe("hpke-hybrid-v2");

		const client = world.client();
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
});

describe("self-seal negotiation (independent of recipient)", () => {
	let dir: string;
	let world: World;
	let recipient: WorldAgent;

	beforeEach(() => {
		dir = makeTmpDir();
		world = new World();
		world.save(dir, world.addAgent({ id: SENDER_ID }));
		recipient = world.addAgent({ id: RECIPIENT_ID });
		world.save(dir, recipient);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("a PQ-capable sender produces a HYBRID self-blob", async () => {
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			RECIPIENT_ID,
			recipientKeysOf(recipient),
			{ msg: "pq" },
		);
		expect(encrypted.self_encrypted_payload).toBeDefined();
		const selfBytes = fromBase64Url(encrypted.self_encrypted_payload as string);
		expect(selfBytes[0]).toBe(VERSION_HYBRID_V2);
	});

	it("hybrid self-read round-trips for a PQ-capable sender", async () => {
		const payload = { recall: "turn-1-fact" };
		const encrypted = await encryptMessage(
			dir,
			SENDER_ID,
			RECIPIENT_ID,
			recipientKeysOf(recipient),
			payload,
		);
		const client = world.client();
		const result = await decryptMessage(
			dir,
			SENDER_ID,
			encrypted.self_encrypted_payload as string,
			client as never,
			SENDER_ID,
			RECIPIENT_ID,
		);
		expect(JSON.parse(result.plaintext as string)).toEqual(payload);
		expect(result.verified).toBe(true);
		expect(result.verificationStatus).toBe("verified");
	});
});
