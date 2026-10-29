import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deriveAgent, deriveBranch, deriveOrg } from "../../src/crypto/derive.js";
import { agentKeysExist, agentKeysFromDerived, encryptionPublicKeyToJWK, fromBase64Url, jwkToPublicKey, loadAgentKeys, parseSigningKid, pqKeyPairFromSeed, saveAgentKeys, savePqEncryptionKey, signingKid, signingPublicKeyToJWK, toBase64Url, validateEncryptionKey, validateSigningKey } from "../../src/crypto/keys.js";
import { generateAgentKeys, generateEncryptionKeyPair, generatePqKeyPair, generateSigningKeyPair } from "../helpers/keys.js";
import { UPGRADE_DETAIL } from "../../src/crypto/upgrade-detail.js";
import { hex, kat, unhex } from "./kat-fixture.js";

const AGENT_ID = "00000000-0000-4000-a000-000000000001";

describe("upgrade detail", () => {
	it("matches the KAT constant", () => {
		expect(UPGRADE_DETAIL).toBe(kat.constants.upgrade_detail);
	});
});

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
		expect(Buffer.from(a.privateKey).equals(Buffer.from(b.privateKey))).toBe(false);
	});

	it("generateAgentKeys returns all five leaf keys", () => {
		const keys = generateAgentKeys();
		expect(keys.signing.privateKey).toHaveLength(32);
		expect(keys.signing.publicKey).toHaveLength(32);
		expect(keys.encryption.privateKey).toHaveLength(32);
		expect(keys.encryption.publicKey).toHaveLength(32);
		expect(keys.pqEncryption.seed).toHaveLength(64);
		expect(keys.pqEncryption.privateKey).toHaveLength(2400);
		expect(keys.pqEncryption.publicKey).toHaveLength(1184);
		expect(keys.mls.privateKey).toHaveLength(32);
		expect(keys.mls.publicKey).toHaveLength(32);
		expect(keys.keyGen).toBe(0);
	});

	it("generateAgentKeys honours the key generation", () => {
		expect(generateAgentKeys(7).keyGen).toBe(7);
	});

	it("pqKeyPairFromSeed expands the stored seed deterministically", () => {
		const seed = new Uint8Array(64).fill(9);
		const a = pqKeyPairFromSeed(seed);
		const b = pqKeyPairFromSeed(seed);
		expect(a.seed).toBe(seed);
		expect(a.privateKey).toHaveLength(2400);
		expect(a.publicKey).toHaveLength(1184);
		expect(hex(a.publicKey)).toBe(hex(b.publicKey));
	});

	it("pqKeyPairFromSeed rejects a wrong-length seed", () => {
		expect(() => pqKeyPairFromSeed(new Uint8Array(32))).toThrow(
			"Invalid PQ seed: expected 64 bytes, got 32",
		);
	});

	it("generatePqKeyPair produces a fresh 64-byte seed", () => {
		const a = generatePqKeyPair();
		const b = generatePqKeyPair();
		expect(a.seed).toHaveLength(64);
		expect(hex(a.seed)).not.toBe(hex(b.seed));
	});
});

describe("agentKeysFromDerived", () => {
	const root = kat.roots.roots[0];
	const agent = root.agents[0];
	const gen = agent.gens[0];
	const derived = deriveAgent(
		deriveBranch(deriveOrg(unhex(root.entropy)), agent.branch),
		agent.id,
		gen.gen,
	);
	const keys = agentKeysFromDerived(derived);

	it("matches the fixture for root 0's first agent gen 0", () => {
		expect(hex(keys.signing.privateKey)).toBe(gen.ed25519.seed);
		expect(hex(keys.signing.publicKey)).toBe(gen.ed25519.pk);
		expect(hex(keys.encryption.privateKey)).toBe(gen.x25519.sk);
		expect(hex(keys.encryption.publicKey)).toBe(gen.x25519.pk);
		expect(hex(keys.pqEncryption.seed)).toBe(gen.ml_kem_768.seed);
		expect(hex(keys.pqEncryption.publicKey)).toBe(gen.ml_kem_768.pk);
		expect(hex(keys.mls.privateKey)).toBe(gen.mls_ed25519.seed);
		expect(hex(keys.mls.publicKey)).toBe(gen.mls_ed25519.pk);
		expect(keys.keyGen).toBe(gen.gen);
	});

	it("round-trips through save and load with the same public keys", () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rine-derived-test-"));
		try {
			saveAgentKeys(tmpDir, agent.id, keys);
			const loaded = loadAgentKeys(tmpDir, agent.id);
			expect(hex(loaded.signing.publicKey)).toBe(hex(keys.signing.publicKey));
			expect(hex(loaded.encryption.publicKey)).toBe(hex(keys.encryption.publicKey));
			expect(hex(loaded.pqEncryption.publicKey)).toBe(hex(keys.pqEncryption.publicKey));
			expect(hex(loaded.mls.publicKey)).toBe(hex(keys.mls.publicKey));
			expect(loaded.keyGen).toBe(keys.keyGen);
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
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
		expect(Buffer.from(fromBase64Url(toBase64Url(data))).equals(Buffer.from(data))).toBe(true);
	});
});

describe("signing kid", () => {
	it("formats and parses a kid", () => {
		expect(signingKid(AGENT_ID, 0)).toBe(`rine:${AGENT_ID}#0`);
		expect(parseSigningKid(`rine:${AGENT_ID}#0`)).toEqual({ agentId: AGENT_ID, keyGen: 0 });
		expect(parseSigningKid(`rine:${AGENT_ID}#12`)).toEqual({ agentId: AGENT_ID, keyGen: 12 });
	});

	it("rejects a missing generation", () => {
		expect(() => parseSigningKid(`rine:${AGENT_ID}`)).toThrow("Invalid sender KID format");
	});

	it("rejects a leading-zero generation", () => {
		expect(() => parseSigningKid(`rine:${AGENT_ID}#01`)).toThrow("Invalid sender KID format");
	});

	it("rejects an uppercase agent id", () => {
		expect(() => parseSigningKid(`rine:${AGENT_ID.toUpperCase()}#0`)).toThrow(
			"Invalid sender KID format",
		);
	});

	it("rejects the old rich format", () => {
		expect(() => parseSigningKid("rine:acme:bot:abc123")).toThrow("Invalid sender KID format");
	});

	it("rejects an empty string", () => {
		expect(() => parseSigningKid("")).toThrow("Invalid sender KID format");
	});

	it("rejects a missing prefix", () => {
		expect(() => parseSigningKid(`${AGENT_ID}#0`)).toThrow("Invalid sender KID format");
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

	it("save and load roundtrips every leaf key", () => {
		const keys = generateAgentKeys(3);
		saveAgentKeys(tmpDir, AGENT_ID, keys);
		const loaded = loadAgentKeys(tmpDir, AGENT_ID);

		expect(hex(loaded.signing.privateKey)).toBe(hex(keys.signing.privateKey));
		expect(hex(loaded.signing.publicKey)).toBe(hex(keys.signing.publicKey));
		expect(hex(loaded.encryption.privateKey)).toBe(hex(keys.encryption.privateKey));
		expect(hex(loaded.encryption.publicKey)).toBe(hex(keys.encryption.publicKey));
		expect(hex(loaded.pqEncryption.seed)).toBe(hex(keys.pqEncryption.seed));
		expect(hex(loaded.pqEncryption.privateKey)).toBe(hex(keys.pqEncryption.privateKey));
		expect(hex(loaded.pqEncryption.publicKey)).toBe(hex(keys.pqEncryption.publicKey));
		expect(hex(loaded.mls.privateKey)).toBe(hex(keys.mls.privateKey));
		expect(hex(loaded.mls.publicKey)).toBe(hex(keys.mls.publicKey));
		expect(loaded.keyGen).toBe(3);
	});

	it("stores the PQ seed, not the expanded key", () => {
		const keys = generateAgentKeys();
		saveAgentKeys(tmpDir, AGENT_ID, keys);
		const raw = fs.readFileSync(path.join(tmpDir, "keys", AGENT_ID, "pq_encryption.key"), "utf-8");
		expect(fromBase64Url(raw.trim())).toHaveLength(64);
	});

	it("writes key_gen as a decimal followed by a newline", () => {
		saveAgentKeys(tmpDir, AGENT_ID, generateAgentKeys(42));
		expect(fs.readFileSync(path.join(tmpDir, "keys", AGENT_ID, "key_gen"), "utf-8")).toBe("42\n");
	});

	it("sets restrictive file permissions", () => {
		saveAgentKeys(tmpDir, AGENT_ID, generateAgentKeys());
		const dir = path.join(tmpDir, "keys", AGENT_ID);
		expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
		for (const name of ["signing.key", "encryption.key", "pq_encryption.key", "mls.key", "key_gen"]) {
			expect(fs.statSync(path.join(dir, name)).mode & 0o777).toBe(0o600);
		}
	});

	it("never exposes a key file at a mode other than 0600, even mid-write", () => {
		const dir = path.join(tmpDir, "keys", AGENT_ID);
		const exposed: string[] = [];
		const observe = () => {
			if (!fs.existsSync(dir)) return;
			for (const name of fs.readdirSync(dir)) {
				const mode = fs.statSync(path.join(dir, name)).mode & 0o777;
				if (mode !== 0o600) exposed.push(`${name} at ${mode.toString(8)}`);
			}
		};
		const writers = ["openSync", "writeFileSync", "closeSync", "renameSync", "chmodSync"] as const;
		const spies = writers.map((name) => {
			const real = fs[name] as (...args: unknown[]) => unknown;
			return vi.spyOn(fs, name).mockImplementation(((...args: unknown[]) => {
				const result = real(...args);
				observe();
				return result;
			}) as never);
		});
		const umask = process.umask(0o022);
		try {
			saveAgentKeys(tmpDir, AGENT_ID, generateAgentKeys());
			savePqEncryptionKey(tmpDir, AGENT_ID, generatePqKeyPair());
		} finally {
			process.umask(umask);
			for (const spy of spies) spy.mockRestore();
		}
		expect(exposed).toEqual([]);
	});

	it("agentKeysExist requires all five files", () => {
		expect(agentKeysExist(tmpDir, AGENT_ID)).toBe(false);
		saveAgentKeys(tmpDir, AGENT_ID, generateAgentKeys());
		expect(agentKeysExist(tmpDir, AGENT_ID)).toBe(true);
		fs.rmSync(path.join(tmpDir, "keys", AGENT_ID, "mls.key"));
		expect(agentKeysExist(tmpDir, AGENT_ID)).toBe(false);
	});

	it("loadAgentKeys rejects a corrupted signing key", () => {
		const dir = path.join(tmpDir, "keys", AGENT_ID);
		fs.mkdirSync(dir, { recursive: true });
		fs.writeFileSync(path.join(dir, "signing.key"), toBase64Url(new Uint8Array(16)));
		expect(() => loadAgentKeys(tmpDir, AGENT_ID)).toThrow(
			"Corrupt signing key: expected 32 bytes, got 16",
		);
	});

	it("loadAgentKeys rejects a corrupted encryption key", () => {
		const dir = path.join(tmpDir, "keys", AGENT_ID);
		fs.mkdirSync(dir, { recursive: true });
		fs.writeFileSync(path.join(dir, "signing.key"), toBase64Url(new Uint8Array(32)));
		fs.writeFileSync(path.join(dir, "encryption.key"), toBase64Url(new Uint8Array(16)));
		expect(() => loadAgentKeys(tmpDir, AGENT_ID)).toThrow(
			"Corrupt encryption key: expected 32 bytes, got 16",
		);
	});

	it("loadAgentKeys refuses the retired 2400-byte PQ file with the upgrade detail", () => {
		const keys = generateAgentKeys();
		saveAgentKeys(tmpDir, AGENT_ID, keys);
		fs.writeFileSync(
			path.join(tmpDir, "keys", AGENT_ID, "pq_encryption.key"),
			toBase64Url(new Uint8Array(2400)),
		);
		expect(() => loadAgentKeys(tmpDir, AGENT_ID)).toThrow(UPGRADE_DETAIL);
	});

	it("loadAgentKeys rejects a corrupted PQ seed", () => {
		const keys = generateAgentKeys();
		saveAgentKeys(tmpDir, AGENT_ID, keys);
		fs.writeFileSync(
			path.join(tmpDir, "keys", AGENT_ID, "pq_encryption.key"),
			toBase64Url(new Uint8Array(32)),
		);
		expect(() => loadAgentKeys(tmpDir, AGENT_ID)).toThrow(
			"Corrupt PQ key: expected 64 bytes, got 32",
		);
	});

	it("loadAgentKeys rejects a corrupted MLS key", () => {
		const keys = generateAgentKeys();
		saveAgentKeys(tmpDir, AGENT_ID, keys);
		fs.writeFileSync(path.join(tmpDir, "keys", AGENT_ID, "mls.key"), toBase64Url(new Uint8Array(16)));
		expect(() => loadAgentKeys(tmpDir, AGENT_ID)).toThrow(
			"Corrupt MLS key: expected 32 bytes, got 16",
		);
	});

	it("loadAgentKeys rejects a corrupt key_gen", () => {
		const keys = generateAgentKeys();
		saveAgentKeys(tmpDir, AGENT_ID, keys);
		fs.writeFileSync(path.join(tmpDir, "keys", AGENT_ID, "key_gen"), "01\n");
		expect(() => loadAgentKeys(tmpDir, AGENT_ID)).toThrow("Corrupt key_gen: 01");
	});

	it("loadAgentKeys names a missing mls.key", () => {
		saveAgentKeys(tmpDir, AGENT_ID, generateAgentKeys());
		fs.rmSync(path.join(tmpDir, "keys", AGENT_ID, "mls.key"));
		expect(() => loadAgentKeys(tmpDir, AGENT_ID)).toThrow("Missing mls.key");
	});

	it("loadAgentKeys names a missing key_gen", () => {
		saveAgentKeys(tmpDir, AGENT_ID, generateAgentKeys());
		fs.rmSync(path.join(tmpDir, "keys", AGENT_ID, "key_gen"));
		expect(() => loadAgentKeys(tmpDir, AGENT_ID)).toThrow("Missing key_gen");
	});
});

describe("jwkToPublicKey validation", () => {
	it("rejects short x value", () => {
		expect(() =>
			jwkToPublicKey({ kty: "OKP", crv: "Ed25519", x: toBase64Url(new Uint8Array(16)) }),
		).toThrow("Invalid public key: expected 32 bytes, got 16");
	});

	it("rejects long x value", () => {
		expect(() =>
			jwkToPublicKey({ kty: "OKP", crv: "Ed25519", x: toBase64Url(new Uint8Array(48)) }),
		).toThrow("Invalid public key: expected 32 bytes, got 48");
	});
});

describe("validateSigningKey", () => {
	it("accepts a valid 32-byte key", () => {
		expect(() => validateSigningKey(generateSigningKeyPair().privateKey)).not.toThrow();
	});

	it("rejects empty array", () => {
		expect(() => validateSigningKey(new Uint8Array(0))).toThrow("expected 32 bytes, got 0");
	});

	it("rejects 16-byte array", () => {
		expect(() => validateSigningKey(new Uint8Array(16))).toThrow("expected 32 bytes, got 16");
	});

	it("rejects 64-byte array", () => {
		expect(() => validateSigningKey(new Uint8Array(64))).toThrow("expected 32 bytes, got 64");
	});
});

describe("validateEncryptionKey", () => {
	it("accepts a valid 32-byte key", () => {
		expect(() => validateEncryptionKey(generateEncryptionKeyPair().privateKey)).not.toThrow();
	});

	it("rejects empty array", () => {
		expect(() => validateEncryptionKey(new Uint8Array(0))).toThrow("expected 32 bytes, got 0");
	});

	it("rejects 16-byte array", () => {
		expect(() => validateEncryptionKey(new Uint8Array(16))).toThrow("expected 32 bytes, got 16");
	});

	it("rejects 64-byte array", () => {
		expect(() => validateEncryptionKey(new Uint8Array(64))).toThrow("expected 32 bytes, got 64");
	});
});

describe("savePqEncryptionKey", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rine-pq-save-test-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("saves the PQ seed and loadAgentKeys picks it up", () => {
		const keys = generateAgentKeys();
		saveAgentKeys(tmpDir, AGENT_ID, keys);
		const pq = generatePqKeyPair();
		savePqEncryptionKey(tmpDir, AGENT_ID, pq);

		const loaded = loadAgentKeys(tmpDir, AGENT_ID);
		expect(hex(loaded.pqEncryption.seed)).toBe(hex(pq.seed));
		expect(hex(loaded.pqEncryption.publicKey)).toBe(hex(pq.publicKey));
	});

	it("does not overwrite existing signing or encryption keys", () => {
		saveAgentKeys(tmpDir, AGENT_ID, generateAgentKeys());
		const dir = path.join(tmpDir, "keys", AGENT_ID);
		const originalSig = fs.readFileSync(path.join(dir, "signing.key"), "utf-8");
		const originalEnc = fs.readFileSync(path.join(dir, "encryption.key"), "utf-8");

		savePqEncryptionKey(tmpDir, AGENT_ID, generatePqKeyPair());

		expect(fs.readFileSync(path.join(dir, "signing.key"), "utf-8")).toBe(originalSig);
		expect(fs.readFileSync(path.join(dir, "encryption.key"), "utf-8")).toBe(originalEnc);
	});

	it("sets 0o600 permissions on pq_encryption.key", () => {
		saveAgentKeys(tmpDir, AGENT_ID, generateAgentKeys());
		savePqEncryptionKey(tmpDir, AGENT_ID, generatePqKeyPair());
		expect(fs.statSync(path.join(tmpDir, "keys", AGENT_ID, "pq_encryption.key")).mode & 0o777).toBe(
			0o600,
		);
	});
});
