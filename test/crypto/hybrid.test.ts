import { describe, expect, it } from "vitest";
import {
	MLKEM_CT_SIZE,
	VERSION_HYBRID,
	generatePqKeyPair,
	openHybrid,
	sealHybrid,
} from "../../src/crypto/hybrid.js";
import { generateEncryptionKeyPair } from "../../src/crypto/keys.js";

const X25519_ENC_SIZE = 32;

describe("generatePqKeyPair", () => {
	it("produces ML-KEM-768 sized keys", () => {
		const kp = generatePqKeyPair();
		expect(kp.publicKey).toHaveLength(1184);
		expect(kp.privateKey).toHaveLength(2400);
	});

	it("produces a distinct key pair each time", () => {
		const a = generatePqKeyPair();
		const b = generatePqKeyPair();
		expect(Buffer.from(a.publicKey).equals(Buffer.from(b.publicKey))).toBe(
			false,
		);
	});
});

describe("sealHybrid + openHybrid", () => {
	it("roundtrips: seal then open", async () => {
		const x = generateEncryptionKeyPair();
		const pq = generatePqKeyPair();
		const plaintext = new TextEncoder().encode("hello post-quantum");

		const ct = await sealHybrid(x.publicKey, pq.publicKey, plaintext);
		const recovered = await openHybrid(x.privateKey, pq.privateKey, ct);

		expect(Buffer.from(recovered).equals(Buffer.from(plaintext))).toBe(true);
	});

	it("version byte is 0x03", async () => {
		const x = generateEncryptionKeyPair();
		const pq = generatePqKeyPair();
		const ct = await sealHybrid(
			x.publicKey,
			pq.publicKey,
			new Uint8Array([1, 2, 3]),
		);
		expect(ct[0]).toBe(VERSION_HYBRID);
		expect(VERSION_HYBRID).toBe(0x03);
	});

	it("wire layout is version + x25519_enc + mlkem_ct + aead", async () => {
		const x = generateEncryptionKeyPair();
		const pq = generatePqKeyPair();
		const plaintext = new TextEncoder().encode("layout");
		const ct = await sealHybrid(x.publicKey, pq.publicKey, plaintext);

		// RFC 9180 AES-256-GCM tag is Nt=16 bytes; no per-message nonce on the wire.
		const GCM_TAG_SIZE = 16;
		expect(ct[0]).toBe(VERSION_HYBRID);
		expect(ct.length).toBe(
			1 + X25519_ENC_SIZE + MLKEM_CT_SIZE + plaintext.length + GCM_TAG_SIZE,
		);
		// Exact segment framing: x25519 enc (32) then ML-KEM ct (1088).
		expect(ct.slice(1, 1 + X25519_ENC_SIZE)).toHaveLength(X25519_ENC_SIZE);
		expect(
			ct.slice(1 + X25519_ENC_SIZE, 1 + X25519_ENC_SIZE + MLKEM_CT_SIZE),
		).toHaveLength(MLKEM_CT_SIZE);
	});

	it("produces different ciphertext each time (ephemeral + KEM randomness)", async () => {
		const x = generateEncryptionKeyPair();
		const pq = generatePqKeyPair();
		const msg = new TextEncoder().encode("same message");

		const ct1 = await sealHybrid(x.publicKey, pq.publicKey, msg);
		const ct2 = await sealHybrid(x.publicKey, pq.publicKey, msg);

		expect(Buffer.from(ct1).equals(Buffer.from(ct2))).toBe(false);
	});

	it("fails when the classical key is wrong", async () => {
		const x = generateEncryptionKeyPair();
		const wrongX = generateEncryptionKeyPair();
		const pq = generatePqKeyPair();

		const ct = await sealHybrid(x.publicKey, pq.publicKey, new Uint8Array([1]));
		await expect(
			openHybrid(wrongX.privateKey, pq.privateKey, ct),
		).rejects.toThrow();
	});

	it("fails when the PQ key is wrong", async () => {
		const x = generateEncryptionKeyPair();
		const pq = generatePqKeyPair();
		const wrongPq = generatePqKeyPair();

		const ct = await sealHybrid(x.publicKey, pq.publicKey, new Uint8Array([1]));
		await expect(
			openHybrid(x.privateKey, wrongPq.privateKey, ct),
		).rejects.toThrow();
	});

	it("rejects an unsupported version byte", async () => {
		const x = generateEncryptionKeyPair();
		const pq = generatePqKeyPair();
		const ct = await sealHybrid(x.publicKey, pq.publicKey, new Uint8Array([1]));
		ct[0] = 0x01; // classical version — not handled by openHybrid
		await expect(openHybrid(x.privateKey, pq.privateKey, ct)).rejects.toThrow(
			"unsupported version",
		);
	});

	it("rejects a truncated payload", async () => {
		const x = generateEncryptionKeyPair();
		const pq = generatePqKeyPair();
		await expect(
			openHybrid(x.privateKey, pq.privateKey, new Uint8Array(10)),
		).rejects.toThrow("too short");
	});

	it("supports AAD binding and rejects mismatched AAD", async () => {
		const x = generateEncryptionKeyPair();
		const pq = generatePqKeyPair();
		const msg = new TextEncoder().encode("bound");
		const aad = new TextEncoder().encode("context-A");

		const ct = await sealHybrid(x.publicKey, pq.publicKey, msg, aad);
		const recovered = await openHybrid(x.privateKey, pq.privateKey, ct, aad);
		expect(Buffer.from(recovered).equals(Buffer.from(msg))).toBe(true);

		await expect(
			openHybrid(
				x.privateKey,
				pq.privateKey,
				ct,
				new TextEncoder().encode("context-B"),
			),
		).rejects.toThrow();
	});

	it("handles empty and large plaintext", async () => {
		const x = generateEncryptionKeyPair();
		const pq = generatePqKeyPair();

		const empty = await sealHybrid(
			x.publicKey,
			pq.publicKey,
			new Uint8Array(0),
		);
		expect(await openHybrid(x.privateKey, pq.privateKey, empty)).toHaveLength(
			0,
		);

		const large = new Uint8Array(100_000).fill(0x42);
		const ct = await sealHybrid(x.publicKey, pq.publicKey, large);
		const recovered = await openHybrid(x.privateKey, pq.privateKey, ct);
		expect(Buffer.from(recovered).equals(Buffer.from(large))).toBe(true);
	});

	it("AEAD segment adds exactly the GCM tag (Nt=16) over plaintext", async () => {
		const x = generateEncryptionKeyPair();
		const pq = generatePqKeyPair();
		const GCM_TAG_SIZE = 16;
		const headerSize = 1 + X25519_ENC_SIZE + MLKEM_CT_SIZE;

		// Empty plaintext: the AEAD segment is tag-only.
		const empty = await sealHybrid(x.publicKey, pq.publicKey, new Uint8Array(0));
		expect(empty.slice(headerSize)).toHaveLength(GCM_TAG_SIZE);

		// Known-length plaintext: overhead over plaintext is exactly the tag.
		const plaintext = new TextEncoder().encode("overhead-check");
		const sealed = await sealHybrid(x.publicKey, pq.publicKey, plaintext);
		expect(sealed.length - headerSize).toBe(plaintext.length + GCM_TAG_SIZE);
	});
});
