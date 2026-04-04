import * as fs from "node:fs";
import { join } from "node:path";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";

export interface JWK {
	kty: string;
	crv: string;
	x: string;
	d?: string;
}

export interface KeyPair {
	privateKey: Uint8Array;
	publicKey: Uint8Array;
}

export interface AgentKeys {
	signing: KeyPair;
	encryption: KeyPair;
}

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

const KID_RE = /^rine:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

export function agentIdFromKid(kid: string): string {
	const match = KID_RE.exec(kid);
	if (!match) throw new Error(`Invalid sender KID format: ${kid}`);
	return match[1]!;
}

const PATH_SAFE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function validatePathId(id: string, label: string): void {
	if (!PATH_SAFE_RE.test(id)) {
		throw new Error(`Invalid ${label}: must be a UUID, got '${id}'`);
	}
}

export function saveAgentKeys(configDir: string, agentId: string, keys: AgentKeys): void {
	validatePathId(agentId, "agent ID");
	const dir = join(configDir, "keys", agentId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

	const sigPath = join(dir, "signing.key");
	fs.writeFileSync(sigPath, toBase64Url(keys.signing.privateKey), "utf-8");
	fs.chmodSync(sigPath, 0o600);

	const encPath = join(dir, "encryption.key");
	fs.writeFileSync(encPath, toBase64Url(keys.encryption.privateKey), "utf-8");
	fs.chmodSync(encPath, 0o600);
}

export function loadAgentKeys(configDir: string, agentId: string): AgentKeys {
	validatePathId(agentId, "agent ID");
	const dir = join(configDir, "keys", agentId);

	const sigRaw = fs.readFileSync(join(dir, "signing.key"), "utf-8").trim();
	const sigPriv = fromBase64Url(sigRaw);
	if (sigPriv.length !== 32) {
		throw new Error(`Corrupt signing key: expected 32 bytes, got ${sigPriv.length}`);
	}
	const sigPub = ed25519.getPublicKey(sigPriv);

	const encRaw = fs.readFileSync(join(dir, "encryption.key"), "utf-8").trim();
	const encPriv = fromBase64Url(encRaw);
	if (encPriv.length !== 32) {
		throw new Error(`Corrupt encryption key: expected 32 bytes, got ${encPriv.length}`);
	}
	const encPub = x25519.getPublicKey(encPriv);

	return {
		signing: { privateKey: sigPriv, publicKey: sigPub },
		encryption: { privateKey: encPriv, publicKey: encPub },
	};
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
