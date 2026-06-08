import * as fs from "node:fs";
import { join } from "node:path";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { generatePqKeyPair } from "./hybrid.js";

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

export interface AgentKeys {
	signing: KeyPair;
	encryption: KeyPair;
	pqEncryption?: KeyPair;
}

const MLKEM_PUBLIC_KEY_SIZE = 1184;
const MLKEM_SECRET_KEY_SIZE = 2400;

export function toBase64Url(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64url");
}

export function fromBase64Url(s: string): Uint8Array {
	return new Uint8Array(Buffer.from(s, "base64url"));
}

export function generateSigningKeyPair(): KeyPair {
	const privateKey = ed25519.utils.randomSecretKey();
	const publicKey = ed25519.getPublicKey(privateKey);
	return { privateKey, publicKey };
}

export function generateEncryptionKeyPair(): KeyPair {
	const privateKey = x25519.utils.randomSecretKey();
	const publicKey = x25519.getPublicKey(privateKey);
	return { privateKey, publicKey };
}

export function generateAgentKeys(): AgentKeys {
	return {
		signing: generateSigningKeyPair(),
		encryption: generateEncryptionKeyPair(),
		pqEncryption: generatePqKeyPair(),
	};
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

export function jwkToPqPublicKey(jwk: PqJWK): Uint8Array {
	const key = fromBase64Url(jwk.x);
	if (key.length !== MLKEM_PUBLIC_KEY_SIZE) {
		throw new Error(
			`Invalid PQ public key: expected ${MLKEM_PUBLIC_KEY_SIZE} bytes, got ${key.length}`,
		);
	}
	return key;
}

const KID_RE =
	/^rine:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

export function agentIdFromKid(kid: string): string {
	const match = KID_RE.exec(kid);
	if (!match) throw new Error(`Invalid sender KID format: ${kid}`);
	return match[1]!;
}

const PATH_SAFE_RE =
	/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function validatePathId(id: string, label: string): void {
	if (!PATH_SAFE_RE.test(id)) {
		throw new Error(`Invalid ${label}: must be a UUID, got '${id}'`);
	}
}

export function saveAgentKeys(
	configDir: string,
	agentId: string,
	keys: AgentKeys,
): void {
	validatePathId(agentId, "agent ID");
	const dir = join(configDir, "keys", agentId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

	const sigPath = join(dir, "signing.key");
	fs.writeFileSync(sigPath, toBase64Url(keys.signing.privateKey), "utf-8");
	fs.chmodSync(sigPath, 0o600);

	const encPath = join(dir, "encryption.key");
	fs.writeFileSync(encPath, toBase64Url(keys.encryption.privateKey), "utf-8");
	fs.chmodSync(encPath, 0o600);

	if (keys.pqEncryption) {
		const pqPath = join(dir, "pq_encryption.key");
		fs.writeFileSync(
			pqPath,
			toBase64Url(keys.pqEncryption.privateKey),
			"utf-8",
		);
		fs.chmodSync(pqPath, 0o600);
	}
}

export function savePqEncryptionKey(
	configDir: string,
	agentId: string,
	pqKeyPair: KeyPair,
): void {
	validatePathId(agentId, "agent ID");
	const dir = join(configDir, "keys", agentId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	const pqPath = join(dir, "pq_encryption.key");
	fs.writeFileSync(pqPath, toBase64Url(pqKeyPair.privateKey), "utf-8");
	fs.chmodSync(pqPath, 0o600);
}

export function loadAgentKeys(configDir: string, agentId: string): AgentKeys {
	validatePathId(agentId, "agent ID");
	const dir = join(configDir, "keys", agentId);

	const sigRaw = fs.readFileSync(join(dir, "signing.key"), "utf-8").trim();
	const sigPriv = fromBase64Url(sigRaw);
	if (sigPriv.length !== 32) {
		throw new Error(
			`Corrupt signing key: expected 32 bytes, got ${sigPriv.length}`,
		);
	}
	const sigPub = ed25519.getPublicKey(sigPriv);

	const encRaw = fs.readFileSync(join(dir, "encryption.key"), "utf-8").trim();
	const encPriv = fromBase64Url(encRaw);
	if (encPriv.length !== 32) {
		throw new Error(
			`Corrupt encryption key: expected 32 bytes, got ${encPriv.length}`,
		);
	}
	const encPub = x25519.getPublicKey(encPriv);

	const keys: AgentKeys = {
		signing: { privateKey: sigPriv, publicKey: sigPub },
		encryption: { privateKey: encPriv, publicKey: encPub },
	};

	const pqPath = join(dir, "pq_encryption.key");
	if (fs.existsSync(pqPath)) {
		const pqRaw = fs.readFileSync(pqPath, "utf-8").trim();
		const pqPriv = fromBase64Url(pqRaw);
		if (pqPriv.length !== MLKEM_SECRET_KEY_SIZE) {
			throw new Error(
				`Corrupt PQ key: expected ${MLKEM_SECRET_KEY_SIZE} bytes, got ${pqPriv.length}`,
			);
		}
		keys.pqEncryption = {
			privateKey: pqPriv,
			publicKey: ml_kem768.getPublicKey(pqPriv),
		};
	}

	return keys;
}

export function validateSigningKey(bytes: Uint8Array): void {
	if (bytes.length !== 32) {
		throw new Error(`expected 32 bytes, got ${bytes.length}`);
	}
	ed25519.getPublicKey(bytes);
}

export function validateEncryptionKey(bytes: Uint8Array): void {
	if (bytes.length !== 32) {
		throw new Error(`expected 32 bytes, got ${bytes.length}`);
	}
	x25519.getPublicKey(bytes);
}

export function agentKeysExist(configDir: string, agentId: string): boolean {
	validatePathId(agentId, "agent ID");
	const dir = join(configDir, "keys", agentId);
	return (
		fs.existsSync(join(dir, "signing.key")) &&
		fs.existsSync(join(dir, "encryption.key"))
	);
}
