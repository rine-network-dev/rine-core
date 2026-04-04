import { describe, expect, it } from "vitest";
import { generateSigningKeyPair } from "../../src/crypto/keys.js";
import { signPayload, verifySignature } from "../../src/crypto/sign.js";

describe("signPayload + verifySignature", () => {
	it("roundtrips: sign then verify", () => {
		const kp = generateSigningKeyPair();
		const msg = new TextEncoder().encode("hello world");
		const sig = signPayload(kp.privateKey, msg);

		expect(sig).toHaveLength(64);
		expect(verifySignature(kp.publicKey, msg, sig)).toBe(true);
	});

	it("rejects wrong public key", () => {
		const sender = generateSigningKeyPair();
		const other = generateSigningKeyPair();
		const msg = new TextEncoder().encode("secret");
		const sig = signPayload(sender.privateKey, msg);

		expect(verifySignature(other.publicKey, msg, sig)).toBe(false);
	});

	it("rejects tampered message", () => {
		const kp = generateSigningKeyPair();
		const msg = new TextEncoder().encode("original");
		const sig = signPayload(kp.privateKey, msg);
		const tampered = new TextEncoder().encode("modified");

		expect(verifySignature(kp.publicKey, tampered, sig)).toBe(false);
	});

	it("produces deterministic signatures", () => {
		const kp = generateSigningKeyPair();
		const msg = new TextEncoder().encode("deterministic");
		const sig1 = signPayload(kp.privateKey, msg);
		const sig2 = signPayload(kp.privateKey, msg);

		expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(true);
	});

	it("signs empty payload", () => {
		const kp = generateSigningKeyPair();
		const empty = new Uint8Array(0);
		const sig = signPayload(kp.privateKey, empty);

		expect(verifySignature(kp.publicKey, empty, sig)).toBe(true);
	});
});
