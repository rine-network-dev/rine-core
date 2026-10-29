import * as fs from "node:fs";
import { join } from "node:path";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { writeAtomic } from "../config.js";
import { CANONICAL_UUID_RE, UUID_RE_ANY_CASE } from "../uuid.js";
import type { AgentDerivedKeys } from "./derive.js";
import { UPGRADE_DETAIL } from "./upgrade-detail.js";

export interface JWK {
	kty: string;
	crv: string;
	x: string;
	d?: string;
}

/** Public-key encoding for ML-KEM-768 (post-quantum). Not a standard OKP JWK. */
export interface PqJWK {
	kty: string;
	alg: string;
	x: string;
}

export interface KeyPair {
	privateKey: Uint8Array;
	publicKey: Uint8Array;
}

/** `seed` is the stored 64-byte `d‖z`; `privateKey` is the expanded 2400-byte key. */
export interface PqKeyPair extends KeyPair {
	seed: Uint8Array;
}

export interface AgentKeys {
	signing: KeyPair;
	encryption: KeyPair;
	pqEncryption: PqKeyPair;
	mls: KeyPair;
	keyGen: number;
}

const MLKEM_PUBLIC_KEY_SIZE = 1184;
const MLKEM_SECRET_KEY_SIZE = 2400;
const MLKEM_SEED_SIZE = 64;
const KEY_GEN_RE = /^(0|[1-9][0-9]*)$/;

export function toBase64Url(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64url");
}

export function fromBase64Url(s: string): Uint8Array {
	return new Uint8Array(Buffer.from(s, "base64url"));
}

export function pqKeyPairFromSeed(seed: Uint8Array): PqKeyPair {
	if (seed.length !== MLKEM_SEED_SIZE) {
		throw new Error(`Invalid PQ seed: expected ${MLKEM_SEED_SIZE} bytes, got ${seed.length}`);
	}
	const { publicKey, secretKey } = ml_kem768.keygen(seed);
	return { seed, privateKey: secretKey, publicKey };
}

/** The private halves of an agent's key set, as stored in its key files. */
export interface AgentPrivateKeys {
	signing: Uint8Array;
	encryption: Uint8Array;
	pqSeed: Uint8Array;
	mls: Uint8Array;
	keyGen: number;
}

/** The full key set the private halves stand for, public halves derived. */
export function agentKeysFromPrivate(priv: AgentPrivateKeys): AgentKeys {
	return {
		signing: { privateKey: priv.signing, publicKey: ed25519.getPublicKey(priv.signing) },
		encryption: { privateKey: priv.encryption, publicKey: x25519.getPublicKey(priv.encryption) },
		pqEncryption: pqKeyPairFromSeed(priv.pqSeed),
		mls: { privateKey: priv.mls, publicKey: ed25519.getPublicKey(priv.mls) },
		keyGen: priv.keyGen,
	};
}

export function agentKeysFromDerived(derived: AgentDerivedKeys): AgentKeys {
	return {
		signing: derived.ed25519,
		encryption: derived.x25519,
		pqEncryption: pqKeyPairFromSeed(derived.mlKem768.privateKey),
		mls: derived.mlsEd25519,
		keyGen: derived.gen,
	};
}

export function signingKid(agentId: string, keyGen: number): string {
	return `rine:${agentId}#${keyGen}`;
}

/** A signing kid that is not `rine:<canonical agent uuid>#<key_gen>`. */
export class InvalidSigningKidError extends Error {
	constructor(kid: string) {
		super(`Invalid sender KID format: ${kid}`);
		this.name = "InvalidSigningKidError";
	}
}

export function parseSigningKid(kid: string): { agentId: string; keyGen: number } {
	const parts = kid.split("#");
	const agentId = parts[0]?.startsWith("rine:") ? parts[0].slice(5) : "";
	const genText = parts.length === 2 ? parts[1]! : "";
	const keyGen = Number(genText);
	const valid =
		parts.length === 2 &&
		CANONICAL_UUID_RE.test(agentId) &&
		KEY_GEN_RE.test(genText) &&
		Number.isSafeInteger(keyGen);
	if (!valid) throw new InvalidSigningKidError(kid);
	return { agentId, keyGen };
}

export function signingPublicKeyToJWK(publicKey: Uint8Array): JWK {
	return { kty: "OKP", crv: "Ed25519", x: toBase64Url(publicKey) };
}

export function encryptionPublicKeyToJWK(publicKey: Uint8Array): JWK {
	return { kty: "OKP", crv: "X25519", x: toBase64Url(publicKey) };
}

export function jwkToPublicKey(jwk: JWK): Uint8Array {
	const key = fromBase64Url(jwk.x);
	if (key.length !== 32) {
		throw new Error(`Invalid public key: expected 32 bytes, got ${key.length}`);
	}
	return key;
}

export function pqPublicKeyToJWK(publicKey: Uint8Array): PqJWK {
	return { kty: "MLKEM", alg: "ML-KEM-768", x: toBase64Url(publicKey) };
}

/** Public-key encoding for ML-DSA-65, the agent's post-quantum signing key. */
export function pqSigningPublicKeyToJWK(publicKey: Uint8Array): PqJWK {
	return { kty: "MLDSA", alg: "ML-DSA-65", x: toBase64Url(publicKey) };
}

export function jwkToPqPublicKey(jwk: PqJWK): Uint8Array {
	const key = fromBase64Url(jwk.x);
	if (key.length !== MLKEM_PUBLIC_KEY_SIZE) {
		throw new Error(
			`Invalid PQ public key: expected ${MLKEM_PUBLIC_KEY_SIZE} bytes, got ${key.length}`,
		);
	}
	return key;
}

/** True for a dashed UUID in either case, the only id form safe to join into a path. */
export function isPathSafeId(id: string): boolean {
	return UUID_RE_ANY_CASE.test(id);
}

export function validatePathId(id: string, label: string): void {
	if (!isPathSafeId(id)) {
		throw new Error(`Invalid ${label}: must be a UUID, got '${id}'`);
	}
}

function keyDir(configDir: string, agentId: string): string {
	validatePathId(agentId, "agent ID");
	const dir = join(configDir, "keys", agentId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	return dir;
}

export function saveAgentKeys(configDir: string, agentId: string, keys: AgentKeys): void {
	const dir = keyDir(configDir, agentId);
	writeAtomic(join(dir, "signing.key"), toBase64Url(keys.signing.privateKey));
	writeAtomic(join(dir, "encryption.key"), toBase64Url(keys.encryption.privateKey));
	writeAtomic(join(dir, "pq_encryption.key"), toBase64Url(keys.pqEncryption.seed));
	writeAtomic(join(dir, "mls.key"), toBase64Url(keys.mls.privateKey));
	writeAtomic(join(dir, "key_gen"), `${keys.keyGen}\n`);
}

export function savePqEncryptionKey(configDir: string, agentId: string, pq: PqKeyPair): void {
	writeAtomic(join(keyDir(configDir, agentId), "pq_encryption.key"), toBase64Url(pq.seed));
}

function readSecret(dir: string, name: string): Uint8Array {
	const file = join(dir, name);
	if (!fs.existsSync(file)) throw new Error(`Missing ${name}`);
	return fromBase64Url(fs.readFileSync(file, "utf-8").trim());
}

function readKeyGen(dir: string): number {
	const file = join(dir, "key_gen");
	if (!fs.existsSync(file)) throw new Error("Missing key_gen");
	const raw = fs.readFileSync(file, "utf-8").trim();
	const keyGen = Number(raw);
	if (!KEY_GEN_RE.test(raw) || !Number.isSafeInteger(keyGen)) {
		throw new Error(`Corrupt key_gen: ${raw}`);
	}
	return keyGen;
}

export function loadAgentKeys(configDir: string, agentId: string): AgentKeys {
	validatePathId(agentId, "agent ID");
	const dir = join(configDir, "keys", agentId);

	const sigPriv = readSecret(dir, "signing.key");
	if (sigPriv.length !== 32) {
		throw new Error(`Corrupt signing key: expected 32 bytes, got ${sigPriv.length}`);
	}
	const encPriv = readSecret(dir, "encryption.key");
	if (encPriv.length !== 32) {
		throw new Error(`Corrupt encryption key: expected 32 bytes, got ${encPriv.length}`);
	}
	const pqSeed = readSecret(dir, "pq_encryption.key");
	if (pqSeed.length === MLKEM_SECRET_KEY_SIZE) throw new Error(UPGRADE_DETAIL);
	if (pqSeed.length !== MLKEM_SEED_SIZE) {
		throw new Error(`Corrupt PQ key: expected ${MLKEM_SEED_SIZE} bytes, got ${pqSeed.length}`);
	}
	const mlsPriv = readSecret(dir, "mls.key");
	if (mlsPriv.length !== 32) {
		throw new Error(`Corrupt MLS key: expected 32 bytes, got ${mlsPriv.length}`);
	}

	return agentKeysFromPrivate({
		signing: sigPriv,
		encryption: encPriv,
		pqSeed,
		mls: mlsPriv,
		keyGen: readKeyGen(dir),
	});
}

export function validateSigningKey(bytes: Uint8Array): void {
	if (bytes.length !== 32) throw new Error(`expected 32 bytes, got ${bytes.length}`);
	ed25519.getPublicKey(bytes);
}

export function validateEncryptionKey(bytes: Uint8Array): void {
	if (bytes.length !== 32) throw new Error(`expected 32 bytes, got ${bytes.length}`);
	x25519.getPublicKey(bytes);
}

export function agentKeysExist(configDir: string, agentId: string): boolean {
	validatePathId(agentId, "agent ID");
	const dir = join(configDir, "keys", agentId);
	return ["signing.key", "encryption.key", "pq_encryption.key", "mls.key", "key_gen"].every(
		(name) => fs.existsSync(join(dir, name)),
	);
}
