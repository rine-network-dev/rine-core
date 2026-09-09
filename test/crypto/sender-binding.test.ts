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
	type AgentKeys,
	generateAgentKeys,
	saveAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
} from "../../src/crypto/keys.js";
import {
	decryptGroupMessage,
	decryptMessage,
	encryptGroupMessage,
	encryptMessage,
	isAuthenticityFailure,
} from "../../src/crypto/message.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
} from "../../src/crypto/sender-keys-helpers.js";
import { generateSenderKey } from "../../src/crypto/sender-keys.js";

/** The agent that genuinely signed the envelope. */
const SIGNER_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
/** The agent the ciphertext is sealed to. */
const VICTIM_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
/** The agent the server authenticated as the sender of the row. */
const RESEALER_ID = "cccccccc-3333-4333-8333-cccccccccccc";
const GROUP_ID = "dddddddd-4444-4444-8444-dddddddddddd";

const MISMATCH = "Envelope sender does not match the message sender";

/** Answers `GET /agents/{id}/keys` for the agents it was given, and no others. */
function keyServer(published: Record<string, AgentKeys>) {
	const get = vi.fn(async (path: string) => {
		const match = /^\/agents\/([^/]+)\/keys$/.exec(path);
		const keys = match ? published[match[1] as string] : undefined;
		if (!match || !keys) throw new Error(`unexpected GET ${path}`);
		return {
			agent_id: match[1],
			signing_public_key: signingPublicKeyToJWK(keys.signing.publicKey),
			encryption_public_key: {
				kty: "OKP",
				crv: "X25519",
				x: toBase64Url(keys.encryption.publicKey),
			},
		};
	});
	return { get, post: vi.fn() };
}

describe("sender binding on the 1:1 path", () => {
	let dir: string;
	let signer: AgentKeys;
	let victim: AgentKeys;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-binding-"));
		signer = generateAgentKeys();
		victim = generateAgentKeys();
		saveAgentKeys(dir, SIGNER_ID, signer);
		saveAgentKeys(dir, VICTIM_ID, victim);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	/** An envelope genuinely signed by the signer, sealed to the victim. */
	async function sealedToVictim(): Promise<string> {
		const enc = await encryptMessage(
			dir,
			SIGNER_ID,
			victim.encryption.publicKey,
			{ text: "release the funds" },
		);
		return enc.encrypted_payload;
	}

	it("test_decrypt_when_kid_names_a_different_agent_then_rejects", async () => {
		const client = keyServer({ [SIGNER_ID]: signer });

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
		const client = keyServer({ [SIGNER_ID]: generateAgentKeys() });

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
		const client = keyServer({ [SIGNER_ID]: signer });

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
		const client = keyServer({ [SIGNER_ID]: signer });

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
		const client = keyServer({ [SIGNER_ID]: signer });

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
			signer.encryption.publicKey,
			{ text: "note to self" },
		);
		const client = keyServer({ [SIGNER_ID]: signer });

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
	let signer: AgentKeys;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-binding-group-"));
		signer = generateAgentKeys();
		saveAgentKeys(dir, SIGNER_ID, signer);
		saveAgentKeys(dir, VICTIM_ID, generateAgentKeys());
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
		const client = keyServer({ [SIGNER_ID]: signer });

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
		const client = keyServer({ [SIGNER_ID]: signer });
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
		const client = keyServer({ [SIGNER_ID]: signer });
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
