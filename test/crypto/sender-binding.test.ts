/**
 * The envelope's claim of authorship is checked against the sender the server
 * authenticated for the row.
 *
 * The inner Ed25519 signature covers the plaintext only — not the recipient — so
 * a signed envelope stays valid after somebody else re-seals it to a new victim
 * and posts it under their own name. These tests drive that shape through the
 * public decrypt functions: the SAME ciphertext is opened twice, once claiming
 * the true signer as the row's sender and once claiming a third agent, and only
 * the first is trusted.
 */

import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	decryptMessage,
	encryptMessage,
	isAuthenticityFailure,
} from "../../src/crypto/message.js";
import { encryptGroupMessage } from "../../src/crypto/sender-key-seal.js";
import { decryptGroupMessage } from "../../src/message-group.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
} from "../../src/crypto/sender-keys-helpers.js";
import { generateSenderKey } from "../../src/crypto/sender-keys.js";
import { World, type WorldAgent } from "./world.js";

/** The agent that genuinely signed the envelope. */
const SIGNER_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
/** The agent the ciphertext is sealed to. */
const VICTIM_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
/** The agent the server authenticated as the sender of the row. */
const RESEALER_ID = "cccccccc-3333-4333-8333-cccccccccccc";
const GROUP_ID = "dddddddd-4444-4444-8444-dddddddddddd";

const MISMATCH = "Envelope sender does not match the message sender";

/** The recipient's chain-verified encryption keys, as `fetchRecipientKeys` returns them. */
function recipientKeysOf(agent: WorldAgent) {
	return {
		encryption: agent.derived.x25519.publicKey,
		pqEncryption: agent.derived.mlKem768.publicKey,
	};
}

/** A world client whose `get` is a spy, so a test can count key lookups. */
function spiedClient(world: World) {
	const base = world.client();
	return { ...base, get: vi.fn(base.get) };
}

describe("sender binding on the 1:1 path", () => {
	let dir: string;
	let world: World;
	let signer: WorldAgent;
	let victim: WorldAgent;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-binding-"));
		world = new World();
		signer = world.addAgent({ id: SIGNER_ID });
		victim = world.addAgent({ id: VICTIM_ID });
		world.save(dir, signer);
		world.save(dir, victim);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	/** An envelope genuinely signed by the signer, sealed to the victim. */
	async function sealedToVictim(): Promise<string> {
		const enc = await encryptMessage(
			dir,
			SIGNER_ID,
			VICTIM_ID,
			recipientKeysOf(victim),
			{ text: "release the funds" },
		);
		return enc.encrypted_payload;
	}

	it("test_decrypt_when_kid_names_a_different_agent_then_rejects", async () => {
		const client = spiedClient(world);

		const result = await decryptMessage(
			dir,
			VICTIM_ID,
			await sealedToVictim(),
			client as never,
			RESEALER_ID,
		);

		expect(result.verificationStatus).toBe("sender-mismatch");
		expect(result.verified).toBe(false);
		expect(isAuthenticityFailure(result.verificationStatus)).toBe(true);
		// The text is withheld, exactly as the group path refuses it: content the
		// resealer is credited with never becomes readable.
		expect(result.plaintext).toBeUndefined();
	});

	it("test_decrypt_when_the_signature_does_not_check_out_then_withholds_text", async () => {
		// The other authenticity failure, refused identically: the kid names the
		// row's sender, but the signature does not check out against the key that
		// agent publishes, so the bytes are not its word either.
		const imposterWorld = new World();
		imposterWorld.addAgent({ id: SIGNER_ID });
		const client = imposterWorld.client();

		const result = await decryptMessage(
			dir,
			VICTIM_ID,
			await sealedToVictim(),
			client as never,
			SIGNER_ID,
		);

		expect(result.verificationStatus).toBe("invalid");
		expect(result.verified).toBe(false);
		expect(result.plaintext).toBeUndefined();
	});

	it("test_decrypt_when_the_key_lookup_fails_then_still_returns_the_text", async () => {
		// `unverifiable` is not a verdict on the author — the check could not run —
		// so a key endpoint that is briefly unreachable must not start discarding
		// readable content.
		const client = {
			get: vi.fn().mockRejectedValue(new Error("keys unreachable")),
			post: vi.fn(),
		};

		const result = await decryptMessage(
			dir,
			VICTIM_ID,
			await sealedToVictim(),
			client as never,
			SIGNER_ID,
		);

		expect(result.verificationStatus).toBe("unverifiable");
		expect(JSON.parse(result.plaintext as string)).toEqual({
			text: "release the funds",
		});
	});

	it("test_decrypt_when_kid_names_a_different_agent_then_fetches_no_keys", async () => {
		// Whether the kid names the row's sender is not a question the key endpoint
		// can answer, so a mismatch must cost zero requests.
		const client = spiedClient(world);

		await decryptMessage(
			dir,
			VICTIM_ID,
			await sealedToVictim(),
			client as never,
			RESEALER_ID,
		);

		expect(client.get).not.toHaveBeenCalled();
	});

	it("test_decrypt_when_kid_names_the_rows_sender_then_verifies", async () => {
		// False-positive guard: the identical envelope, attributed correctly, is
		// trusted. Without this the suite would pass on a check that rejects all.
		const client = spiedClient(world);

		const result = await decryptMessage(
			dir,
			VICTIM_ID,
			await sealedToVictim(),
			client as never,
			SIGNER_ID,
		);

		expect(result.verified).toBe(true);
		expect(result.verificationStatus).toBe("verified");
		expect(client.get).toHaveBeenCalledTimes(1);
	});

	it("test_decrypt_when_sender_id_differs_in_case_then_verifies", async () => {
		// Both sides are server-issued UUIDs, but a caller may hold a differently
		// cased copy; a case-sensitive compare would refuse an honest message.
		const client = spiedClient(world);

		const result = await decryptMessage(
			dir,
			VICTIM_ID,
			await sealedToVictim(),
			client as never,
			SIGNER_ID.toUpperCase(),
		);

		expect(result.verified).toBe(true);
	});

	it("test_decrypt_when_agent_sends_to_itself_then_verifies", async () => {
		// The funnel and self-addressed sends put one agent on both ends: sender,
		// recipient and kid are all the same agent.
		const enc = await encryptMessage(
			dir,
			SIGNER_ID,
			SIGNER_ID,
			recipientKeysOf(signer),
			{ text: "note to self" },
		);
		const client = spiedClient(world);

		const result = await decryptMessage(
			dir,
			SIGNER_ID,
			enc.encrypted_payload,
			client as never,
			SIGNER_ID,
		);

		expect(result.verified).toBe(true);
		expect(result.verificationStatus).toBe("verified");
	});
});

describe("sender binding on the sender-key group path", () => {
	let dir: string;
	let world: World;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-binding-group-"));
		world = new World();
		world.save(dir, world.addAgent({ id: SIGNER_ID }));
		world.save(dir, world.addAgent({ id: VICTIM_ID }));
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	/** A group message from the signer, with its key distributed to the victim. */
	async function groupMessageFromSigner(): Promise<string> {
		const state = generateSenderKey(GROUP_ID, SIGNER_ID);
		// The signer's own copy, which `encryptGroupMessage` advances in place. A
		// stand-in sender needs it as much as a real one does: the tail refuses a
		// state that is on no disk at all rather than discarding the advance.
		saveSenderKeyState(dir, SIGNER_ID, GROUP_ID, [state]);
		const { result } = await encryptGroupMessage(
			dir,
			SIGNER_ID,
			GROUP_ID,
			state,
			{ text: "approve the transfer" },
		);
		saveSenderKeyState(dir, VICTIM_ID, GROUP_ID, [state]);
		return result.encrypted_payload;
	}

	function victimIndexes(): number[] {
		return loadSenderKeyStates(dir, VICTIM_ID, GROUP_ID).map(
			(s) => s.messageIndex,
		);
	}

	it("test_group_decrypt_when_kid_names_a_different_agent_then_throws", async () => {
		const ciphertext = await groupMessageFromSigner();
		const client = world.client();

		await expect(
			decryptGroupMessage(
				dir,
				VICTIM_ID,
				GROUP_ID,
				ciphertext,
				client as never,
				RESEALER_ID,
			),
		).rejects.toThrow(MISMATCH);
	});

	it("test_group_decrypt_when_kid_names_a_different_agent_then_keeps_ratchet", async () => {
		const ciphertext = await groupMessageFromSigner();
		const client = world.client();
		const before = victimIndexes();

		await expect(
			decryptGroupMessage(
				dir,
				VICTIM_ID,
				GROUP_ID,
				ciphertext,
				client as never,
				RESEALER_ID,
			),
		).rejects.toThrow(MISMATCH);

		// Refused before the state write, so the ratchet is exactly where it was and
		// the honest next message still opens.
		expect(victimIndexes()).toEqual(before);
	});

	it("test_group_decrypt_when_kid_names_the_rows_sender_then_verifies", async () => {
		const ciphertext = await groupMessageFromSigner();
		const client = world.client();
		const before = victimIndexes();

		const result = await decryptGroupMessage(
			dir,
			VICTIM_ID,
			GROUP_ID,
			ciphertext,
			client as never,
			SIGNER_ID,
		);

		expect(result.verified).toBe(true);
		expect(JSON.parse(result.plaintext as string)).toEqual({
			text: "approve the transfer",
		});
		// An accepted message DOES advance the ratchet.
		expect(victimIndexes()).not.toEqual(before);
	});
});
