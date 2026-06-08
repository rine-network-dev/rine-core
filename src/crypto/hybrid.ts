import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import type { KeyPair } from "./keys.js";

// Post-quantum hybrid HPKE: X25519 + ML-KEM-768 combined via HKDF.
// Wire layout: 0x03 | x25519_enc(32) | mlkem_ciphertext(1088) | aead_ciphertext
const VERSION_HYBRID = 0x03;
const X25519_ENC_SIZE = 32;
const MLKEM_CT_SIZE = 1088;
const AES_KEY_SIZE = 32;
const HKDF_INFO = new TextEncoder().encode("rine.e2ee.v1.hpke-hybrid");

// The derived AEAD key is single-use (fresh ephemeral X25519 + ML-KEM encapsulation
// randomness per message), so a constant zero nonce is safe and keeps the wire layout
// free of a nonce field.
const GCM_NONCE = new Uint8Array(12);

export { VERSION_HYBRID, MLKEM_CT_SIZE };

/** Copy into a plain ArrayBuffer-backed Uint8Array (required by Web Crypto). */
function toPlainBuffer(src: Uint8Array): Uint8Array<ArrayBuffer> {
	const buf = new Uint8Array(src.length);
	buf.set(src);
	return buf;
}

/** Generate an ML-KEM-768 key pair for post-quantum key encapsulation. */
export function generatePqKeyPair(): KeyPair {
	const { publicKey, secretKey } = ml_kem768.keygen();
	return { publicKey, privateKey: secretKey };
}

/** HKDF-SHA256 over (classical || pq) shared secrets with hybrid domain separation. */
function combineSecrets(
	x25519Shared: Uint8Array,
	mlkemShared: Uint8Array,
): Uint8Array {
	const ikm = new Uint8Array(x25519Shared.length + mlkemShared.length);
	ikm.set(x25519Shared, 0);
	ikm.set(mlkemShared, x25519Shared.length);
	const key = hkdf(sha256, ikm, undefined, HKDF_INFO, AES_KEY_SIZE);
	ikm.fill(0);
	return key;
}

async function aesGcm(
	mode: "encrypt" | "decrypt",
	key: Uint8Array,
	data: Uint8Array,
	aad?: Uint8Array,
): Promise<Uint8Array> {
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		toPlainBuffer(key),
		"AES-GCM",
		false,
		[mode],
	);
	const params: AesGcmParams = { name: "AES-GCM", iv: GCM_NONCE };
	if (aad) params.additionalData = toPlainBuffer(aad);
	const buf = toPlainBuffer(data);
	const out =
		mode === "encrypt"
			? await crypto.subtle.encrypt(params, cryptoKey, buf)
			: await crypto.subtle.decrypt(params, cryptoKey, buf);
	return new Uint8Array(out);
}

export async function sealHybrid(
	recipientX25519Pk: Uint8Array,
	recipientMlKemPk: Uint8Array,
	innerEnvelope: Uint8Array,
	aad?: Uint8Array,
): Promise<Uint8Array> {
	const ephSk = x25519.utils.randomSecretKey();
	const ephPk = x25519.getPublicKey(ephSk);
	const x25519Shared = x25519.getSharedSecret(ephSk, recipientX25519Pk);
	const { cipherText: mlkemCt, sharedSecret: mlkemShared } =
		ml_kem768.encapsulate(recipientMlKemPk);

	const key = combineSecrets(x25519Shared, mlkemShared);
	x25519Shared.fill(0);
	mlkemShared.fill(0);
	ephSk.fill(0);

	const ciphertext = await aesGcm("encrypt", key, innerEnvelope, aad);
	key.fill(0);

	const out = new Uint8Array(
		1 + X25519_ENC_SIZE + MLKEM_CT_SIZE + ciphertext.length,
	);
	out[0] = VERSION_HYBRID;
	out.set(ephPk, 1);
	out.set(mlkemCt, 1 + X25519_ENC_SIZE);
	out.set(ciphertext, 1 + X25519_ENC_SIZE + MLKEM_CT_SIZE);
	return out;
}

export async function openHybrid(
	recipientX25519Sk: Uint8Array,
	recipientMlKemSk: Uint8Array,
	encryptedPayload: Uint8Array,
	aad?: Uint8Array,
): Promise<Uint8Array> {
	const headerSize = 1 + X25519_ENC_SIZE + MLKEM_CT_SIZE;
	if (encryptedPayload.length < headerSize + 1) {
		throw new Error("encrypted payload too short");
	}
	const version = encryptedPayload[0];
	if (version !== VERSION_HYBRID) {
		throw new Error(
			`unsupported version: 0x${version?.toString(16).padStart(2, "0")}`,
		);
	}

	const ephPk = encryptedPayload.slice(1, 1 + X25519_ENC_SIZE);
	const mlkemCt = encryptedPayload.slice(1 + X25519_ENC_SIZE, headerSize);
	const ciphertext = encryptedPayload.slice(headerSize);

	const x25519Shared = x25519.getSharedSecret(recipientX25519Sk, ephPk);
	const mlkemShared = ml_kem768.decapsulate(mlkemCt, recipientMlKemSk);

	const key = combineSecrets(x25519Shared, mlkemShared);
	x25519Shared.fill(0);
	mlkemShared.fill(0);

	try {
		return await aesGcm("decrypt", key, ciphertext, aad);
	} finally {
		key.fill(0);
	}
}
