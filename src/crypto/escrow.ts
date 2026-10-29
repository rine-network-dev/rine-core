import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ascii, concat, u32be, u64be } from "./bytes.js";
import { assertBranchName, canonicalUuid } from "./derive.js";
import { verifyEd25519Strict } from "./ed25519-strict.js";
import { type SealContext, sealHybrid, sealHybridWith } from "./hybrid.js";
import { MLS_CIPHER_SUITE_XWING } from "./mls.js";

// MLS read escrow: the EpochReadSecrets v1 plaintext, its hpke-hybrid-v2 seal
// under the branch escrow key and the uploader's Ed25519 signature over the slot.
export const ESCROW_CIPHER_SUITE = MLS_CIPHER_SUITE_XWING;
export const EPOCH_READ_SECRETS_VERSION = 1;
export const MAX_ESCROW_CONTEXT_LENGTH = 1024;

const MAX_ESCROW_LEAVES = 1000;
/** Twice the power of two holding {@link MAX_ESCROW_LEAVES}: the widest tree a reader will size. */
const MAX_ESCROW_TREE_LEAVES = 2048;
const TREE_LEAF_COUNT_OFFSET = 3;

const ESCROW_SIG_DOMAIN = "rine.v1.mls-escrow-sig";
const SEP = new Uint8Array(1);
const LEAF_ENTRY_SIZE = 36;
// version(1) + cipher_suite(2) + leaf_count(4) + sender_data_secret(32) + encryption_secret(32)
const FIXED_PART_SIZE = 71;

/** A branch escrow key verified under the own-org and own-branch pin. */
export interface VerifiedEscrowKey {
	orgId: string;
	branch: string;
	x25519: Uint8Array;
	mlKem: Uint8Array;
}

/** The slot an escrow belongs to: group, epoch and fork fingerprint. */
export interface EscrowSlot {
	groupId: string;
	epoch: number;
	fp: Uint8Array;
}

export interface EscrowUploader {
	agentId: string;
	keyGen: number;
	signingPrivateKey: Uint8Array;
}

export interface SealedEscrow {
	sealed: Uint8Array;
	uploaderSig: Uint8Array;
	uploaderKeyGen: number;
}

function assertEpoch(epoch: number): void {
	if (!Number.isSafeInteger(epoch) || epoch < 0) {
		throw new Error("escrow: epoch must be a non-negative safe integer");
	}
}

function assertKeyGen(keyGen: number): void {
	if (!Number.isInteger(keyGen) || keyGen < 0 || keyGen >= 2 ** 32) {
		throw new Error("escrow: key generation must be an unsigned 32-bit integer");
	}
}

/** The `SealContext.MlsEscrow` binding org, branch, group, epoch, uploader and `fp`. */
export function escrowSealContext(
	key: Pick<VerifiedEscrowKey, "orgId" | "branch">,
	slot: EscrowSlot,
	uploaderAgentId: string,
): SealContext {
	assertEpoch(slot.epoch);
	return {
		kind: "MlsEscrow",
		orgId: key.orgId,
		branch: key.branch,
		groupId: slot.groupId,
		epoch: slot.epoch,
		uploaderAgentId,
		fp: slot.fp,
	};
}

/**
 * `"rine.v1.mls-escrow-sig" || 0 || org_id || 0 || branch || 0 || group_id || 0 || u64be(epoch) ||
 * fp || uploader_agent_id || 0 || u32be(key_gen) || SHA-256(sealed)`.
 */
export function escrowSigningInput(
	key: Pick<VerifiedEscrowKey, "orgId" | "branch">,
	slot: EscrowSlot,
	uploader: Pick<EscrowUploader, "agentId" | "keyGen">,
	sealed: Uint8Array,
): Uint8Array {
	assertEpoch(slot.epoch);
	assertKeyGen(uploader.keyGen);
	return concat(
		ascii(ESCROW_SIG_DOMAIN),
		SEP,
		ascii(canonicalUuid(key.orgId, "org id")),
		SEP,
		ascii(assertBranchName(key.branch)),
		SEP,
		ascii(canonicalUuid(slot.groupId, "group id")),
		SEP,
		u64be(slot.epoch),
		slot.fp,
		ascii(canonicalUuid(uploader.agentId, "uploader agent id")),
		SEP,
		u32be(uploader.keyGen),
		sha256(sealed),
	);
}

/**
 * The seal-side gate: only EpochReadSecrets v1 with cipher suite 0xF057, a group context of at
 * most 1024 bytes, a tree of a power-of-two leaf count up to 2048 and a leaf tail of exactly
 * `36·n` bytes (n ≤ 1000) is accepted. The group context itself is not parsed here.
 */
export function assertEpochReadSecrets(plaintext: Uint8Array): void {
	if (plaintext.length < FIXED_PART_SIZE + 4) {
		throw new Error("escrow: plaintext too short");
	}
	if (plaintext[0] !== EPOCH_READ_SECRETS_VERSION) {
		throw new Error("escrow: unsupported EpochReadSecrets version");
	}
	const suite = ((plaintext[1] ?? 0) << 8) | (plaintext[2] ?? 0);
	if (suite !== ESCROW_CIPHER_SUITE) {
		throw new Error("escrow: unsupported cipher suite");
	}
	const view = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);
	const treeLeaves = view.getUint32(TREE_LEAF_COUNT_OFFSET);
	if (
		treeLeaves === 0 ||
		treeLeaves > MAX_ESCROW_TREE_LEAVES ||
		(treeLeaves & (treeLeaves - 1)) !== 0
	) {
		throw new Error("escrow: tree size is not a power of two within the limit");
	}
	const contextLen = view.getUint32(FIXED_PART_SIZE);
	if (contextLen > MAX_ESCROW_CONTEXT_LENGTH) {
		throw new Error("escrow: group context too long");
	}
	const afterContext = FIXED_PART_SIZE + 4 + contextLen;
	if (afterContext + 4 > plaintext.length) {
		throw new Error("escrow: group context runs past the end");
	}
	const leafCount = view.getUint32(afterContext);
	if (leafCount > MAX_ESCROW_LEAVES) {
		throw new Error("escrow: too many leaves");
	}
	const tail = afterContext + 4 + LEAF_ENTRY_SIZE * leafCount;
	if (tail > plaintext.length) {
		throw new Error("escrow: leaf count does not match the plaintext length");
	}
	if (tail < plaintext.length) {
		throw new Error("escrow: trailing bytes");
	}
}

function signUploader(
	key: Pick<VerifiedEscrowKey, "orgId" | "branch">,
	slot: EscrowSlot,
	uploader: EscrowUploader,
	sealed: Uint8Array,
): Uint8Array {
	return ed25519.sign(
		escrowSigningInput(key, slot, uploader, sealed),
		uploader.signingPrivateKey,
	);
}

/** Seal with caller-supplied ephemeral randomness (test seam for the KAT). */
export function sealEscrowWith(
	key: VerifiedEscrowKey,
	slot: EscrowSlot,
	uploader: EscrowUploader,
	plaintext: Uint8Array,
	ephemeralSk: Uint8Array,
	kemMsg: Uint8Array,
): SealedEscrow {
	const sealed = sealHybridWith(
		key.x25519,
		key.mlKem,
		plaintext,
		escrowSealContext(key, slot, uploader.agentId),
		ephemeralSk,
		kemMsg,
	);
	return {
		sealed,
		uploaderSig: signUploader(key, slot, uploader, sealed),
		uploaderKeyGen: uploader.keyGen,
	};
}

/** Seal an EpochReadSecrets v1 plaintext to the branch escrow key and sign the slot. */
export function sealEscrow(
	key: VerifiedEscrowKey,
	slot: EscrowSlot,
	uploader: EscrowUploader,
	plaintext: Uint8Array,
): SealedEscrow {
	assertEpochReadSecrets(plaintext);
	const sealed = sealHybrid(
		key.x25519,
		key.mlKem,
		plaintext,
		escrowSealContext(key, slot, uploader.agentId),
	);
	return {
		sealed,
		uploaderSig: signUploader(key, slot, uploader, sealed),
		uploaderKeyGen: uploader.keyGen,
	};
}

/** Strict Ed25519 verification of the uploader signature over the slot. */
export function verifyEscrowUploaderSig(
	uploaderSigningPk: Uint8Array,
	key: Pick<VerifiedEscrowKey, "orgId" | "branch">,
	slot: EscrowSlot,
	uploader: Pick<EscrowUploader, "agentId" | "keyGen">,
	sealed: Uint8Array,
	sig: Uint8Array,
): boolean {
	return verifyEd25519Strict(
		uploaderSigningPk,
		escrowSigningInput(key, slot, uploader, sealed),
		sig,
	);
}
