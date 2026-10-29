/**
 * The largest escrow a group can produce, sealed by this package, against the
 * server's cap on a sealed blob. The native core's own test asserts the
 * plaintext size and hard-codes the seal overhead; this is the half that fixes
 * the overhead to what the TypeScript sealer really adds.
 */
import { describe, expect, it } from "vitest";
import { deriveAgent, deriveBranch, deriveOrg } from "../../src/crypto/derive.js";
import {
	ESCROW_CIPHER_SUITE,
	type EscrowSlot,
	type EscrowUploader,
	MAX_ESCROW_CONTEXT_LENGTH,
	type VerifiedEscrowKey,
	sealEscrow,
} from "../../src/crypto/escrow.js";

/** The server's `MAX_SEALED_BYTES` (`src/rine/api/mls_escrow_schemas.py`). */
const SERVER_MAX_SEALED_BYTES = 40960;
/** `hpke-hybrid-v2`: version byte, X25519 key, ML-KEM-768 ciphertext, GCM tag. */
const SEAL_OVERHEAD = 1 + 32 + 1088 + 16;
const FIXED_LEN = 71;
const LEAF_ENTRY_LEN = 36;
const MAX_LEAVES = 1000;

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const org = deriveOrg(new Uint8Array(32).fill(9));
const branch = deriveBranch(org, "main");
const key: VerifiedEscrowKey = {
	orgId: org.orgId,
	branch: "main",
	x25519: branch.escrowX25519.publicKey,
	mlKem: branch.escrowMlKem768.publicKey,
};
const slot: EscrowSlot = {
	groupId: "c3d4e5f6-a7b8-9012-cdef-123456789012",
	epoch: 7,
	fp: new Uint8Array(16).fill(1),
};
const uploader: EscrowUploader = {
	agentId: AGENT,
	keyGen: 0,
	signingPrivateKey: deriveAgent(branch, AGENT, 0).ed25519.privateKey,
};

/** An EpochReadSecrets v1 plaintext of the given context and leaf counts. */
function plaintextOf(contextLen: number, leaves: number): Uint8Array {
	const out = new Uint8Array(FIXED_LEN + 4 + contextLen + 4 + LEAF_ENTRY_LEN * leaves);
	const view = new DataView(out.buffer);
	out[0] = 1;
	view.setUint16(1, ESCROW_CIPHER_SUITE);
	view.setUint32(3, 1024);
	view.setUint32(FIXED_LEN, contextLen);
	view.setUint32(FIXED_LEN + 4 + contextLen, leaves);
	return out;
}

describe("the worst-case escrow", () => {
	it("test_seal_escrow_when_the_tree_is_full_and_the_context_maximal_then_the_sealed_blob_fits_the_server_bound", () => {
		const plaintext = plaintextOf(MAX_ESCROW_CONTEXT_LENGTH, MAX_LEAVES);

		const { sealed } = sealEscrow(key, slot, uploader, plaintext);

		expect(sealed.length).toBe(plaintext.length + SEAL_OVERHEAD);
		expect(sealed.length).toBe(38240);
		expect(sealed.length).toBeLessThanOrEqual(SERVER_MAX_SEALED_BYTES);
	});

	it("test_seal_escrow_when_the_tree_holds_one_leaf_too_many_then_it_is_refused", () => {
		expect(() =>
			sealEscrow(key, slot, uploader, plaintextOf(MAX_ESCROW_CONTEXT_LENGTH, MAX_LEAVES + 1)),
		).toThrow("too many leaves");
	});

	it.each([0, 3, 4096, 0xffffffff])(
		"test_seal_escrow_when_the_tree_size_is_%i_then_it_is_refused",
		(treeLeaves) => {
			const plaintext = plaintextOf(0, 1);
			new DataView(plaintext.buffer).setUint32(3, treeLeaves);

			expect(() => sealEscrow(key, slot, uploader, plaintext)).toThrow("tree size");
		},
	);
});
