import * as fs from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { openHybrid } from "../../src/crypto/hybrid.js";
import { fromBase64Url, loadAgentKeys } from "../../src/crypto/keys.js";
import {
	decryptMessage,
	encryptMessage,
	sealForAgent,
} from "../../src/crypto/message.js";
import { encryptGroupMessage } from "../../src/crypto/sender-key-seal.js";
import { decryptGroupMessage } from "../../src/message-group.js";
import { saveSenderKeyState } from "../../src/crypto/sender-keys-helpers.js";
import { generateSenderKey } from "../../src/crypto/sender-keys.js";
import { World, type WorldAgent } from "./world.js";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-msg-test-"));
}

const SENDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const RECIPIENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

/** The recipient's chain-verified encryption keys, as `fetchRecipientKeys` returns them. */
function recipientKeysOf(agent: WorldAgent) {
	return {
		encryption: agent.derived.x25519.publicKey,
		pqEncryption: agent.derived.mlKem768.publicKey,
	};
}

describe("DM encrypt/decrypt round-trip", () => {
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

	it("encrypts and decrypts with verified signature", async () => {
		const payload = { task: "translate", text: "hello" };
		const encrypted = await encryptMessage(
			dir, SENDER_ID, RECIPIENT_ID, recipientKeysOf(recipient), payload,
		);

		expect(encrypted.encryption_version).toBe("hpke-hybrid-v2");
		expect(encrypted.sender_signing_kid).toBe(`rine:${SENDER_ID}#0`);

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
		expect(result.verificationStatus).toBe("verified");
		expect(result.senderKid).toBe(`rine:${SENDER_ID}#0`);
	});

	it("test_seal_for_agent_when_opened_by_the_recipient_then_verified", async () => {
		const payload = { task: "translate", text: "fetched keys" };
		const client = world.client();
		const encrypted = await sealForAgent(
			client as never,
			dir,
			{ senderAgentId: SENDER_ID, recipientAgentId: RECIPIENT_ID },
			payload,
		);
		expect(encrypted.encryption_version).toBe("hpke-hybrid-v2");

		const result = await decryptMessage(
			dir,
			RECIPIENT_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);

		expect(JSON.parse(result.plaintext as string)).toEqual(payload);
		expect(result.verificationStatus).toBe("verified");
	});

	it("produces a self-seal blob for the sender", async () => {
		const encrypted = await encryptMessage(
			dir, SENDER_ID, RECIPIENT_ID, recipientKeysOf(recipient), { hi: "self" },
		);
		expect(typeof encrypted.self_encrypted_payload).toBe("string");
		expect(encrypted.self_encrypted_payload?.length).toBeGreaterThan(0);
	});

	it("self-blob round-trips: the sender can decrypt its own message", async () => {
		const payload = { secret: "codeword-banana", turn: 1 };
		const encrypted = await encryptMessage(
			dir, SENDER_ID, RECIPIENT_ID, recipientKeysOf(recipient), payload,
		);
		expect(encrypted.self_encrypted_payload).toBeDefined();

		// Self-read = decrypt with the SENDER's own id + the self-blob, against the
		// recipient the signature is scoped to.
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

	it("seals one envelope to both copies, so they decrypt to identical bytes", async () => {
		const encrypted = await encryptMessage(
			dir, SENDER_ID, RECIPIENT_ID, recipientKeysOf(recipient), { once: true },
		);
		const sender = loadAgentKeys(dir, SENDER_ID);
		const receiver = loadAgentKeys(dir, RECIPIENT_ID);
		const asRecipient = openHybrid(
			receiver.encryption.privateKey,
			receiver.pqEncryption.privateKey,
			fromBase64Url(encrypted.encrypted_payload),
			{ kind: "AgentMessage", recipientAgentId: RECIPIENT_ID },
		);
		const asSender = openHybrid(
			sender.encryption.privateKey,
			sender.pqEncryption.privateKey,
			fromBase64Url(encrypted.self_encrypted_payload as string),
			{ kind: "AgentMessage", recipientAgentId: SENDER_ID },
		);
		expect(Buffer.from(asSender).equals(Buffer.from(asRecipient))).toBe(true);
	});

	it("a self-read scoped to the sender itself is refused: the signature names the recipient", async () => {
		const encrypted = await encryptMessage(
			dir, SENDER_ID, RECIPIENT_ID, recipientKeysOf(recipient), { once: true },
		);
		const result = await decryptMessage(
			dir,
			SENDER_ID,
			encrypted.self_encrypted_payload as string,
			world.client() as never,
			SENDER_ID,
		);
		expect(result.verificationStatus).toBe("invalid");
		expect(result.plaintext).toBeUndefined();
	});

	it("hpke-hybrid-v2 recipient output stays valid (self-blob is additive)", async () => {
		const payload = { msg: "recipient-still-works" };
		const encrypted = await encryptMessage(
			dir, SENDER_ID, RECIPIENT_ID, recipientKeysOf(recipient), payload,
		);
		// Recipient path is unchanged: still hpke-hybrid-v2, still opens for the recipient.
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

	it("withholds the text when the sender key doesn't match", async () => {
		const payload = { msg: "spoofed" };
		const encrypted = await encryptMessage(
			dir, SENDER_ID, RECIPIENT_ID, recipientKeysOf(recipient), payload,
		);

		// A chain-valid response for the same agent id, but a different signing key.
		const imposterWorld = new World();
		imposterWorld.addAgent({ id: SENDER_ID });
		const client = imposterWorld.client();

		const result = await decryptMessage(
			dir,
			RECIPIENT_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);
		// An authenticity failure comes back as the verdict, never as content.
		expect(result.plaintext).toBeUndefined();
		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("invalid");
	});

	it("reports unverifiable when key fetch fails", async () => {
		const payload = { msg: "test" };
		const encrypted = await encryptMessage(
			dir, SENDER_ID, RECIPIENT_ID, recipientKeysOf(recipient), payload,
		);

		const client = { get: vi.fn().mockRejectedValue(new Error("network error")), post: vi.fn() };
		const result = await decryptMessage(
			dir,
			RECIPIENT_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);
		expect(result.verified).toBe(false);
		expect(result.verificationStatus).toBe("unverifiable");
	});
});

describe("Group encrypt/decrypt round-trip", () => {
	let dir: string;
	let world: World;

	beforeEach(() => {
		dir = makeTmpDir();
		world = new World();
		world.save(dir, world.addAgent({ id: SENDER_ID }));
		world.save(dir, world.addAgent({ id: RECIPIENT_ID }));
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("encrypts and decrypts group message", async () => {
		const senderState = generateSenderKey(GROUP_ID, SENDER_ID);
		const payload = { announcement: "meeting at 3pm" };
		// The sender's own copy, which `encryptGroupMessage` advances in place. A
		// stand-in sender needs it as much as a real one does: the tail refuses a
		// state that is on no disk at all rather than discarding the advance.
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [senderState]);

		const { result: encrypted, updatedState } = await encryptGroupMessage(
			dir, SENDER_ID, GROUP_ID, senderState, payload,
		);
		expect(encrypted.encryption_version).toBe("sender-key-v1");
		expect(updatedState.messageIndex).toBe(senderState.messageIndex + 1);

		// Recipient needs the sender's key state to decrypt
		// Simulate key distribution by writing sender state to recipient's store
		saveSenderKeyState(dir, RECIPIENT_ID, GROUP_ID, [senderState]);

		const client = world.client();
		const decrypted = await decryptGroupMessage(
			dir,
			RECIPIENT_ID,
			GROUP_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);

		expect(JSON.parse(decrypted.plaintext)).toEqual(payload);
		expect(decrypted.verified).toBe(true);
	});

	it("group encrypt produces NO self-blob (groups self-read via cache)", async () => {
		const senderState = generateSenderKey(GROUP_ID, SENDER_ID);
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [senderState]);
		const { result: encrypted } = await encryptGroupMessage(
			dir, SENDER_ID, GROUP_ID, senderState, { announcement: "x" },
		);
		expect(encrypted.self_encrypted_payload).toBeUndefined();
	});

	it("rejects group message with invalid signature", async () => {
		const senderState = generateSenderKey(GROUP_ID, SENDER_ID);
		const payload = { msg: "test" };
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [senderState]);

		const { result: encrypted } = await encryptGroupMessage(
			dir, SENDER_ID, GROUP_ID, senderState, payload,
		);

		saveSenderKeyState(dir, RECIPIENT_ID, GROUP_ID, [senderState]);

		// A chain-valid response for the same agent id, but a different signing key.
		const imposterWorld = new World();
		imposterWorld.addAgent({ id: SENDER_ID });
		const client = imposterWorld.client();

		await expect(
			decryptGroupMessage(
				dir,
				RECIPIENT_ID,
				GROUP_ID,
				encrypted.encrypted_payload,
				client as never,
				SENDER_ID,
			),
		).rejects.toThrow("Sender signature verification failed");
	});

	it("sender can decrypt own group message (self-read key)", async () => {
		const senderState = generateSenderKey(GROUP_ID, SENDER_ID);
		const payload = { self: "read" };

		// The state is persisted FIRST because that is what every caller does:
		// all three of them (`rine-cli`, `rine-mcp`, `rine-ts-sdk`) take it from
		// `getOrCreateSenderKey`, whose every return path has already saved it —
		// the rotation branch writes before returning, and the other branch
		// returns a row it loaded from disk. `encryptGroupMessage`'s tail now
		// writes this agent's row back only where the file still HAS it, so that
		// precondition is load-bearing rather than incidental: an unsaved state
		// is indistinguishable from one a concurrent rotation retired, and the
		// tail must not put the retired one back. Handing it an unpersisted
		// state, as this test used to, exercised a shape no caller produces.
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [senderState]);

		const { result: encrypted } = await encryptGroupMessage(
			dir, SENDER_ID, GROUP_ID, senderState, payload,
		);

		// Sender decrypts their own message — uses cached self-read key
		const client = world.client();
		const decrypted = await decryptGroupMessage(
			dir,
			SENDER_ID,
			GROUP_ID,
			encrypted.encrypted_payload,
			client as never,
			SENDER_ID,
		);

		expect(JSON.parse(decrypted.plaintext)).toEqual(payload);
	});
});
