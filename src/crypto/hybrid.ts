import { createCipheriv, createDecipheriv } from "node:crypto";
import { x25519 } from "@noble/curves/ed25519.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ascii, concat, u64be } from "./bytes.js";
import { assertBranchName, canonicalUuid } from "./derive.js";

// Post-quantum hybrid HPKE (hpke-hybrid-v2): X25519 + ML-KEM-768 combined with SHA3-256.
// Wire layout: 0x04 | x25519_enc(32) | mlkem_ciphertext(1088) | aead_ciphertext
export const VERSION_HYBRID_V2 = 0x04;
/** The `encryption_version` string a 1:1 message carries on the wire. */
export const ENCRYPTION_VERSION_HYBRID_V2 = "hpke-hybrid-v2";
export const MLKEM_CT_SIZE = 1088;

const EPH_PK_SIZE = 32;
const TAG_SIZE = 16;
const MIN_WIRE = 1 + EPH_PK_SIZE + MLKEM_CT_SIZE + TAG_SIZE;
const FP_SIZE = 16;

// The derived AEAD key is single-use (fresh ephemeral X25519 + ML-KEM encapsulation
// randomness per message), so a constant zero nonce is safe and keeps the wire layout
// free of a nonce field.
const GCM_NONCE = new Uint8Array(12);
const SEP = new Uint8Array(1);
const VERSION_BYTE = Uint8Array.of(VERSION_HYBRID_V2);

export type SealContext =
	| { kind: "AgentMessage"; recipientAgentId: string }
	| { kind: "BranchBundle"; orgId: string; branch: string }
	| {
			kind: "MlsEscrow";
			orgId: string;
			branch: string;
			groupId: string;
			epoch: number;
			uploaderAgentId: string;
			fp: Uint8Array;
	  };

/** Domain-separated AAD binding a seal to its context. */
export function sealContextAad(ctx: SealContext): Uint8Array {
	if (ctx.kind === "AgentMessage") {
		return concat(
			VERSION_BYTE,
			ascii(canonicalUuid(ctx.recipientAgentId, "recipient agent id")),
		);
	}
	if (ctx.kind === "BranchBundle") {
		return concat(
			VERSION_BYTE,
			ascii("rine.v1.branch-bundle"),
			SEP,
			ascii(canonicalUuid(ctx.orgId, "org id")),
			SEP,
			ascii(assertBranchName(ctx.branch)),
		);
	}
	if (ctx.kind === "MlsEscrow") {
		if (!Number.isSafeInteger(ctx.epoch) || ctx.epoch < 0) {
			throw new Error("seal: epoch must be a non-negative safe integer");
		}
		if (ctx.fp.length !== FP_SIZE) {
			throw new Error(`seal: fingerprint must be ${FP_SIZE} bytes`);
		}
		return concat(
			VERSION_BYTE,
			ascii("rine.v1.mls-escrow"),
			SEP,
			ascii(canonicalUuid(ctx.orgId, "org id")),
			SEP,
			ascii(assertBranchName(ctx.branch)),
			SEP,
			ascii(canonicalUuid(ctx.groupId, "group id")),
			SEP,
			u64be(ctx.epoch),
			SEP,
			ascii(canonicalUuid(ctx.uploaderAgentId, "uploader agent id")),
			SEP,
			ctx.fp,
		);
	}
	throw new Error(`seal: unknown context kind: ${(ctx as { kind: string }).kind}`);
}

/** SHA3-256 combiner over the hybrid shared secrets and both public keys. */
function deriveKey(
	ssMlKem: Uint8Array,
	ssX25519: Uint8Array,
	ephemeralPk: Uint8Array,
	recipientX25519Pk: Uint8Array,
): Uint8Array {
	return sha3_256(
		concat(
			ascii("rine.v1.hpke-hybrid-v2"),
			ssMlKem,
			ssX25519,
			ephemeralPk,
			recipientX25519Pk,
		),
	);
}

/** Seal with caller-supplied ephemeral randomness (test seam for the KAT). */
export function sealHybridWith(
	recipientX25519Pk: Uint8Array,
	recipientMlKemPk: Uint8Array,
	plaintext: Uint8Array,
	ctx: SealContext,
	ephemeralSk: Uint8Array,
	kemMsg: Uint8Array,
): Uint8Array {
	const aad = sealContextAad(ctx);
	const ephemeralPk = x25519.getPublicKey(ephemeralSk);
	const ssX25519 = x25519.getSharedSecret(ephemeralSk, recipientX25519Pk);
	let ssMlKem: Uint8Array | undefined;
	let key: Uint8Array | undefined;
	try {
		const encapsulated = ml_kem768.encapsulate(recipientMlKemPk, kemMsg);
		ssMlKem = encapsulated.sharedSecret;
		key = deriveKey(ssMlKem, ssX25519, ephemeralPk, recipientX25519Pk);
		const cipher = createCipheriv("aes-256-gcm", key, GCM_NONCE);
		cipher.setAAD(aad);
		const aead = concat(
			new Uint8Array(cipher.update(plaintext)),
			new Uint8Array(cipher.final()),
			new Uint8Array(cipher.getAuthTag()),
		);
		return concat(VERSION_BYTE, ephemeralPk, encapsulated.cipherText, aead);
	} finally {
		ssX25519.fill(0);
		ssMlKem?.fill(0);
		key?.fill(0);
	}
}

export function sealHybrid(
	recipientX25519Pk: Uint8Array,
	recipientMlKemPk: Uint8Array,
	plaintext: Uint8Array,
	ctx: SealContext,
): Uint8Array {
	const ephemeralSk = x25519.utils.randomSecretKey();
	const kemMsg = new Uint8Array(32);
	crypto.getRandomValues(kemMsg);
	try {
		return sealHybridWith(
			recipientX25519Pk,
			recipientMlKemPk,
			plaintext,
			ctx,
			ephemeralSk,
			kemMsg,
		);
	} finally {
		ephemeralSk.fill(0);
		kemMsg.fill(0);
	}
}

export function openHybrid(
	recipientX25519Sk: Uint8Array,
	recipientMlKemSk: Uint8Array,
	wire: Uint8Array,
	ctx: SealContext,
): Uint8Array {
	if (wire.length < MIN_WIRE) throw new Error("seal: wire too short");
	if (wire[0] !== VERSION_HYBRID_V2) {
		throw new Error("seal: unsupported version byte");
	}
	const ephemeralPk = wire.slice(1, 1 + EPH_PK_SIZE);
	const mlKemCiphertext = wire.slice(1 + EPH_PK_SIZE, 1 + EPH_PK_SIZE + MLKEM_CT_SIZE);
	const aead = wire.slice(1 + EPH_PK_SIZE + MLKEM_CT_SIZE);

	const aad = sealContextAad(ctx);
	const recipientX25519Pk = x25519.getPublicKey(recipientX25519Sk);
	const ssX25519 = x25519.getSharedSecret(recipientX25519Sk, ephemeralPk);
	let ssMlKem: Uint8Array | undefined;
	let key: Uint8Array | undefined;
	try {
		ssMlKem = ml_kem768.decapsulate(mlKemCiphertext, recipientMlKemSk);
		key = deriveKey(ssMlKem, ssX25519, ephemeralPk, recipientX25519Pk);
		const decipher = createDecipheriv("aes-256-gcm", key, GCM_NONCE);
		decipher.setAAD(aad);
		decipher.setAuthTag(aead.slice(aead.length - TAG_SIZE));
		const body = aead.slice(0, aead.length - TAG_SIZE);
		return concat(
			new Uint8Array(decipher.update(body)),
			new Uint8Array(decipher.final()),
		);
	} finally {
		ssX25519.fill(0);
		ssMlKem?.fill(0);
		key?.fill(0);
	}
}
