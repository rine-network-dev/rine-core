import { describe, expect, it } from "vitest";
import { open, seal } from "../../src/crypto/hpke.js";
import { generateEncryptionKeyPair } from "../../src/crypto/keys.js";

describe("HPKE seal + open", () => {
	it("roundtrips: seal then open", async () => {
		const recipient = generateEncryptionKeyPair();
		const plaintext = new TextEncoder().encode("hello e2ee");

		const ct = await seal(recipient.publicKey, plaintext);
		const recovered = await open(recipient.privateKey, ct);

		expect(Buffer.from(recovered).equals(Buffer.from(plaintext))).toBe(true);
	});

	it("version byte is 0x01", async () => {
		const recipient = generateEncryptionKeyPair();
		const ct = await seal(recipient.publicKey, new Uint8Array([1, 2, 3]));
		expect(ct[0]).toBe(0x01);
	});

	it("ciphertext starts with version + 32-byte enc", async () => {
		const recipient = generateEncryptionKeyPair();
		const ct = await seal(
			recipient.publicKey,
			new TextEncoder().encode("test"),
		);
		// version(1) + enc(32) + ciphertext(variable)
		expect(ct.length).toBeGreaterThan(33);
	});

	it("produces different ciphertext each time (ephemeral key)", async () => {
		const recipient = generateEncryptionKeyPair();
		const msg = new TextEncoder().encode("same message");

		const ct1 = await seal(recipient.publicKey, msg);
		const ct2 = await seal(recipient.publicKey, msg);

		expect(Buffer.from(ct1).equals(Buffer.from(ct2))).toBe(false);
	});

	it("rejects wrong recipient key", async () => {
		const real = generateEncryptionKeyPair();
		const wrong = generateEncryptionKeyPair();
		const msg = new TextEncoder().encode("secret");

		const ct = await seal(real.publicKey, msg);
		await expect(open(wrong.privateKey, ct)).rejects.toThrow();
	});

	it("rejects unsupported version", async () => {
		const kp = generateEncryptionKeyPair();
		const ct = await seal(kp.publicKey, new Uint8Array([1]));
		ct[0] = 0x99; // corrupt version
		await expect(open(kp.privateKey, ct)).rejects.toThrow(
			"unsupported version",
		);
	});

	it("rejects truncated payload", async () => {
		const kp = generateEncryptionKeyPair();
		await expect(open(kp.privateKey, new Uint8Array(5))).rejects.toThrow(
			"too short",
		);
	});

	it("handles empty plaintext", async () => {
		const kp = generateEncryptionKeyPair();
		const ct = await seal(kp.publicKey, new Uint8Array(0));
		const recovered = await open(kp.privateKey, ct);
		expect(recovered).toHaveLength(0);
	});

	it("handles large plaintext", async () => {
		const kp = generateEncryptionKeyPair();
		const large = new Uint8Array(100_000).fill(0x42);
		const ct = await seal(kp.publicKey, large);
		const recovered = await open(kp.privateKey, ct);
		expect(Buffer.from(recovered).equals(Buffer.from(large))).toBe(true);
	});
});
