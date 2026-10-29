import { describe, expect, it } from "vitest";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { concat, u32be } from "../../src/crypto/bytes.js";
import { deriveAgent, deriveBranch, deriveOrg } from "../../src/crypto/derive.js";
import {
	type EscrowSlot,
	type EscrowUploader,
	type VerifiedEscrowKey,
	assertEpochReadSecrets,
	escrowSealContext,
	escrowSigningInput,
	sealEscrow,
	sealEscrowWith,
	verifyEscrowUploaderSig,
} from "../../src/crypto/escrow.js";
import { openHybrid, sealContextAad } from "../../src/crypto/hybrid.js";
import { hex, kat, unhex } from "./kat-fixture.js";

const escrow = kat.mls_escrow;
const root = kat.roots.roots[escrow.uploader.root];
const org = deriveOrg(unhex(root.entropy));
const branch = deriveBranch(org, escrow.seal.escrow_branch);
const uploaderDerived = deriveAgent(branch, escrow.uploader.agent_id, escrow.uploader.gen);

const key: VerifiedEscrowKey = {
	orgId: escrow.slot.org_id,
	branch: escrow.slot.branch,
	x25519: branch.escrowX25519.publicKey,
	mlKem: branch.escrowMlKem768.publicKey,
};

const slot: EscrowSlot = {
	groupId: escrow.slot.group_id,
	epoch: escrow.slot.epoch,
	fp: unhex(escrow.slot.fp),
};

const uploader: EscrowUploader = {
	agentId: escrow.uploader.agent_id,
	keyGen: escrow.uploader.gen,
	signingPrivateKey: uploaderDerived.ed25519.privateKey,
};

const plaintext = unhex(escrow.plaintext.bytes);
const sealed = unhex(escrow.seal.sealed);
const signature = unhex(escrow.uploader_sig.signature);

const CONTEXT_LEN_OFFSET = 71;
const contextLen = new DataView(
	plaintext.buffer,
	plaintext.byteOffset,
	plaintext.byteLength,
).getUint32(CONTEXT_LEN_OFFSET);
const LEAF_COUNT_OFFSET = CONTEXT_LEN_OFFSET + 4 + contextLen;

function withLeafCount(count: number): Uint8Array {
	const mutated = plaintext.slice();
	new DataView(mutated.buffer).setUint32(LEAF_COUNT_OFFSET, count);
	return mutated;
}

/** The golden plaintext re-cut to carry exactly `count` leaf entries, each distinct. */
function withLeaves(count: number): Uint8Array {
	const head = plaintext.slice(0, LEAF_COUNT_OFFSET + 4);
	new DataView(head.buffer).setUint32(LEAF_COUNT_OFFSET, count);
	const leaves = new Uint8Array(count * 36);
	for (let index = 0; index < count; index++) {
		new DataView(leaves.buffer).setUint32(index * 36, index + 1);
	}
	return Uint8Array.from([...head, ...leaves]);
}

describe("assertEpochReadSecrets", () => {
	it("accepts the golden plaintext", () => {
		expect(() => assertEpochReadSecrets(plaintext)).not.toThrow();
	});

	it("refuses the golden bad plaintexts", () => {
		for (const entry of escrow.negatives.bad_plaintexts) {
			expect(() => assertEpochReadSecrets(unhex(entry.plaintext))).toThrow(
				"escrow:",
			);
		}
	});

	it("refuses truncated, extended and short plaintexts", () => {
		const variants = [
			plaintext.slice(0, -1),
			concat(plaintext, new Uint8Array(1)),
			plaintext.slice(0, 40),
		];
		for (const variant of variants) {
			expect(() => assertEpochReadSecrets(variant)).toThrow("escrow:");
		}
	});

	it("refuses an oversized group context", () => {
		const oversized = concat(
			plaintext.slice(0, CONTEXT_LEN_OFFSET),
			u32be(1025),
			new Uint8Array(1025),
			u32be(0),
		);
		expect(() => assertEpochReadSecrets(oversized)).toThrow("escrow:");
	});

	it("refuses a group context that runs past the end", () => {
		const mutated = plaintext.slice();
		new DataView(mutated.buffer).setUint32(CONTEXT_LEN_OFFSET, 1024);
		expect(() => assertEpochReadSecrets(mutated)).toThrow("escrow:");
	});

	it("refuses a leaf count that does not match the remaining bytes", () => {
		expect(() => assertEpochReadSecrets(withLeafCount(4))).toThrow("escrow:");
		expect(() => assertEpochReadSecrets(withLeafCount(2))).toThrow("escrow:");
	});

	it("accepts a tree at the leaf bound and refuses one leaf more", () => {
		expect(() => assertEpochReadSecrets(withLeaves(1000))).not.toThrow();
		expect(() => assertEpochReadSecrets(withLeaves(1001))).toThrow(
			"escrow: too many leaves",
		);
	});
});

describe("mls_escrow seal KAT", () => {
	const result = sealEscrowWith(
		key,
		slot,
		uploader,
		plaintext,
		unhex(escrow.seal.ephemeral_sk),
		unhex(escrow.seal.kem_msg),
	);

	it("reproduces the golden sealed bytes", () => {
		expect(hex(result.sealed)).toBe(escrow.seal.sealed);
	});

	it("reproduces the golden uploader signature and input", () => {
		expect(hex(result.uploaderSig)).toBe(escrow.uploader_sig.signature);
		expect(hex(escrowSigningInput(key, slot, uploader, result.sealed))).toBe(
			escrow.uploader_sig.input,
		);
		expect(result.uploaderKeyGen).toBe(escrow.uploader.gen);
	});

	it("binds the golden AAD", () => {
		expect(hex(sealContextAad(escrowSealContext(key, slot, uploader.agentId)))).toBe(
			escrow.seal.aad,
		);
	});
});

describe("escrowSigningInput ranges", () => {
	it("refuses a key generation outside an unsigned 32-bit integer", () => {
		for (const keyGen of [-1, 2 ** 32, 1.5]) {
			expect(() =>
				escrowSigningInput(key, slot, { ...uploader, keyGen }, sealed),
			).toThrow();
		}
	});
});

describe("verifyEscrowUploaderSig", () => {
	it("accepts the golden signature", () => {
		expect(
			verifyEscrowUploaderSig(
				uploaderDerived.ed25519.publicKey,
				key,
				slot,
				uploader,
				sealed,
				signature,
			),
		).toBe(true);
	});

	it("refuses the signature over the other slot", () => {
		const other = escrow.negatives.signature_over_other_slot;
		expect(hex(escrowSigningInput(key, slot, uploader, sealed))).toBe(other.input);
		expect(
			verifyEscrowUploaderSig(
				unhex(other.public_key),
				key,
				slot,
				uploader,
				sealed,
				unhex(other.signature),
			),
		).toBe(false);
		expect(
			verifyEscrowUploaderSig(
				uploaderDerived.ed25519.publicKey,
				key,
				{ ...slot, epoch: slot.epoch + 1 },
				uploader,
				sealed,
				signature,
			),
		).toBe(false);
	});

	it("refuses a changed group, epoch, fp, uploader, key_gen or sealed", () => {
		const flipped = slot.fp.slice();
		flipped[0] = (flipped[0] ?? 0) ^ 0x01;
		const changedSealed = sealed.slice();
		changedSealed[0] = (changedSealed[0] ?? 0) ^ 0x01;
		const cases: Array<[EscrowSlot, Pick<EscrowUploader, "agentId" | "keyGen">, Uint8Array]> = [
			[{ ...slot, groupId: "d5130b8a-0043-4eff-afaa-12d6a8e7a39f" }, uploader, sealed],
			[{ ...slot, epoch: slot.epoch + 1 }, uploader, sealed],
			[{ ...slot, fp: flipped }, uploader, sealed],
			[slot, { ...uploader, agentId: "6f3a9056-250e-4ae3-baf5-6a5cc54533a5" }, sealed],
			[slot, { ...uploader, keyGen: uploader.keyGen + 1 }, sealed],
			[slot, uploader, changedSealed],
		];
		for (const [changedSlot, changedUploader, changedSealedBytes] of cases) {
			expect(
				verifyEscrowUploaderSig(
					uploaderDerived.ed25519.publicKey,
					key,
					changedSlot,
					changedUploader,
					changedSealedBytes,
					signature,
				),
			).toBe(false);
		}
	});
});

describe("sealEscrow round trip", () => {
	it("opens with the escrow secret key and returns the plaintext", () => {
		const result = sealEscrow(key, slot, uploader, plaintext);
		expect(result.sealed.length).toBe(plaintext.length + 1137);
		expect(result.uploaderKeyGen).toBe(uploader.keyGen);
		const escrowMlKemSk = ml_kem768.keygen(branch.escrowMlKem768.privateKey).secretKey;
		const opened = openHybrid(
			branch.escrowX25519.privateKey,
			escrowMlKemSk,
			result.sealed,
			escrowSealContext(key, slot, uploader.agentId),
		);
		expect(hex(opened)).toBe(escrow.plaintext.bytes);
		expect(
			verifyEscrowUploaderSig(
				uploaderDerived.ed25519.publicKey,
				key,
				slot,
				uploader,
				result.sealed,
				result.uploaderSig,
			),
		).toBe(true);
	});

	it("refuses to seal a bad plaintext", () => {
		expect(() => sealEscrow(key, slot, uploader, withLeafCount(4))).toThrow("escrow:");
	});
});
