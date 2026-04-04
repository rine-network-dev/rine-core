import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	agentIdFromKid,
	agentKeysExist,
	encryptionPublicKeyToJWK,
	fromBase64Url,
	generateAgentKeys,
	generateEncryptionKeyPair,
	generateSigningKeyPair,
	jwkToPublicKey,
	loadAgentKeys,
	saveAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
} from "../../src/crypto/keys.js";

describe("key generation", () => {
	it("generates 32-byte Ed25519 signing keys", () => {
		const kp = generateSigningKeyPair();
		expect(kp.privateKey).toHaveLength(32);
		expect(kp.publicKey).toHaveLength(32);
	});

	it("generates 32-byte X25519 encryption keys", () => {
		const kp = generateEncryptionKeyPair();
		expect(kp.privateKey).toHaveLength(32);
		expect(kp.publicKey).toHaveLength(32);
	});

	it("generates unique keys each time", () => {
		const a = generateSigningKeyPair();
		const b = generateSigningKeyPair();
		expect(Buffer.from(a.privateKey).equals(Buffer.from(b.privateKey))).toBe(
			false,
		);
	});

	it("generateAgentKeys returns both key pairs", () => {
		const keys = generateAgentKeys();
		expect(keys.signing.privateKey).toHaveLength(32);
		expect(keys.signing.publicKey).toHaveLength(32);
		expect(keys.encryption.privateKey).toHaveLength(32);
		expect(keys.encryption.publicKey).toHaveLength(32);
	});
});

describe("JWK serialization", () => {
	it("signing key roundtrips through JWK", () => {
		const kp = generateSigningKeyPair();
		const jwk = signingPublicKeyToJWK(kp.publicKey);
		expect(jwk.kty).toBe("OKP");
		expect(jwk.crv).toBe("Ed25519");
		const recovered = jwkToPublicKey(jwk);
		expect(Buffer.from(recovered).equals(Buffer.from(kp.publicKey))).toBe(true);
	});

	it("encryption key roundtrips through JWK", () => {
		const kp = generateEncryptionKeyPair();
		const jwk = encryptionPublicKeyToJWK(kp.publicKey);
		expect(jwk.kty).toBe("OKP");
		expect(jwk.crv).toBe("X25519");
		const recovered = jwkToPublicKey(jwk);
		expect(Buffer.from(recovered).equals(Buffer.from(kp.publicKey))).toBe(true);
	});

	it("x field is valid base64url", () => {
		const kp = generateSigningKeyPair();
		const jwk = signingPublicKeyToJWK(kp.publicKey);
		expect(jwk.x).toMatch(/^[A-Za-z0-9_-]+$/);
	});
});

describe("base64url helpers", () => {
	it("roundtrips", () => {
		const data = new Uint8Array([0, 1, 2, 255, 254, 253]);
		expect(
			Buffer.from(fromBase64Url(toBase64Url(data))).equals(Buffer.from(data)),
		).toBe(true);
	});
});

describe("filesystem storage", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rine-keys-test-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("save and load roundtrips", () => {
		const keys = generateAgentKeys();
		const agentId = "00000000-0000-4000-a000-000000000001";
		saveAgentKeys(tmpDir, agentId, keys);
		const loaded = loadAgentKeys(tmpDir, agentId);

		expect(
			Buffer.from(loaded.signing.privateKey).equals(
				Buffer.from(keys.signing.privateKey),
			),
		).toBe(true);
		expect(
			Buffer.from(loaded.signing.publicKey).equals(
				Buffer.from(keys.signing.publicKey),
			),
		).toBe(true);
		expect(
			Buffer.from(loaded.encryption.privateKey).equals(
				Buffer.from(keys.encryption.privateKey),
			),
		).toBe(true);
		expect(
			Buffer.from(loaded.encryption.publicKey).equals(
				Buffer.from(keys.encryption.publicKey),
			),
		).toBe(true);
	});

	it("sets restrictive file permissions", () => {
		const keys = generateAgentKeys();
		const permAgent = "00000000-0000-4000-a000-000000000002";
		saveAgentKeys(tmpDir, permAgent, keys);

		const dir = path.join(tmpDir, "keys", permAgent);
		const dirStat = fs.statSync(dir);
		expect(dirStat.mode & 0o777).toBe(0o700);

		const sigStat = fs.statSync(path.join(dir, "signing.key"));
		expect(sigStat.mode & 0o777).toBe(0o600);

		const encStat = fs.statSync(path.join(dir, "encryption.key"));
		expect(encStat.mode & 0o777).toBe(0o600);
	});

	it("agentKeysExist returns correct values", () => {
		expect(agentKeysExist(tmpDir, "00000000-0000-4000-a000-ffffffffffff")).toBe(false);
		const existsId = "00000000-0000-4000-a000-000000000003";
		saveAgentKeys(tmpDir, existsId, generateAgentKeys());
		expect(agentKeysExist(tmpDir, existsId)).toBe(true);
	});

	it("loadAgentKeys rejects corrupted signing key (non-32-byte)", () => {
		const agentId = "00000000-0000-4000-a000-000000000004";
		const dir = path.join(tmpDir, "keys", agentId);
		fs.mkdirSync(dir, { recursive: true });
		fs.writeFileSync(path.join(dir, "signing.key"), toBase64Url(new Uint8Array(16)));
		fs.writeFileSync(path.join(dir, "encryption.key"), toBase64Url(new Uint8Array(32)));
		expect(() => loadAgentKeys(tmpDir, agentId)).toThrow("Corrupt signing key: expected 32 bytes, got 16");
	});

	it("loadAgentKeys rejects corrupted encryption key (non-32-byte)", () => {
		const agentId = "00000000-0000-4000-a000-000000000005";
		const dir = path.join(tmpDir, "keys", agentId);
		fs.mkdirSync(dir, { recursive: true });
		fs.writeFileSync(path.join(dir, "signing.key"), toBase64Url(new Uint8Array(32)));
		fs.writeFileSync(path.join(dir, "encryption.key"), toBase64Url(new Uint8Array(16)));
		expect(() => loadAgentKeys(tmpDir, agentId)).toThrow("Corrupt encryption key: expected 32 bytes, got 16");
	});
});

describe("jwkToPublicKey validation", () => {
	it("rejects short x value", () => {
		expect(() => jwkToPublicKey({ kty: "OKP", crv: "Ed25519", x: toBase64Url(new Uint8Array(16)) }))
			.toThrow("Invalid public key: expected 32 bytes, got 16");
	});

	it("rejects long x value", () => {
		expect(() => jwkToPublicKey({ kty: "OKP", crv: "Ed25519", x: toBase64Url(new Uint8Array(48)) }))
			.toThrow("Invalid public key: expected 32 bytes, got 48");
	});
});

describe("agentIdFromKid", () => {
	it("extracts UUID from valid KID", () => {
		expect(agentIdFromKid("rine:00000000-0000-4000-a000-000000000001"))
			.toBe("00000000-0000-4000-a000-000000000001");
	});

	it("rejects old rich format", () => {
		expect(() => agentIdFromKid("rine:acme:bot:abc123")).toThrow("Invalid sender KID format");
	});

	it("rejects empty string", () => {
		expect(() => agentIdFromKid("")).toThrow("Invalid sender KID format");
	});

	it("rejects missing prefix", () => {
		expect(() => agentIdFromKid("00000000-0000-4000-a000-000000000001")).toThrow("Invalid sender KID format");
	});
});
