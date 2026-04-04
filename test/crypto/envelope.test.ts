import { describe, expect, it } from "vitest";
import { decodeEnvelope, encodeEnvelope } from "../../src/crypto/envelope.js";

describe("encodeEnvelope + decodeEnvelope", () => {
	it("roundtrips with typical values", () => {
		const kid = "rine:00000000-0000-4000-a000-000000000001";
		const sig = new Uint8Array(64).fill(0xab);
		const payload = new TextEncoder().encode('{"task":"validate"}');

		const encoded = encodeEnvelope(kid, sig, payload);
		const decoded = decodeEnvelope(encoded);

		expect(decoded.kid).toBe(kid);
		expect(Buffer.from(decoded.signature).equals(Buffer.from(sig))).toBe(true);
		expect(Buffer.from(decoded.payload).equals(Buffer.from(payload))).toBe(
			true,
		);
	});

	it("first byte is kid length", () => {
		const kid = "abc";
		const sig = new Uint8Array(64);
		const payload = new Uint8Array(0);

		const encoded = encodeEnvelope(kid, sig, payload);
		expect(encoded[0]).toBe(3);
	});

	it("handles empty payload", () => {
		const kid = "k";
		const sig = new Uint8Array(64).fill(0xff);
		const payload = new Uint8Array(0);

		const encoded = encodeEnvelope(kid, sig, payload);
		const decoded = decodeEnvelope(encoded);

		expect(decoded.kid).toBe("k");
		expect(decoded.payload).toHaveLength(0);
	});

	it("handles max kid length (255 bytes)", () => {
		const kid = "x".repeat(255);
		const sig = new Uint8Array(64);
		const payload = new TextEncoder().encode("data");

		const encoded = encodeEnvelope(kid, sig, payload);
		const decoded = decodeEnvelope(encoded);
		expect(decoded.kid).toBe(kid);
	});

	it("rejects kid longer than 255 bytes", () => {
		const kid = "x".repeat(256);
		const sig = new Uint8Array(64);
		const payload = new Uint8Array(0);

		expect(() => encodeEnvelope(kid, sig, payload)).toThrow("kid too long");
	});

	it("rejects wrong signature size", () => {
		expect(() =>
			encodeEnvelope("k", new Uint8Array(32), new Uint8Array(0)),
		).toThrow("signature must be 64 bytes");
	});

	it("rejects truncated envelope", () => {
		expect(() => decodeEnvelope(new Uint8Array(10))).toThrow(
			"envelope too short",
		);
	});

	it("rejects invalid UTF-8 in KID field", () => {
		const sig = new Uint8Array(64);
		const payload = new TextEncoder().encode("test");
		const invalidUtf8Kid = new Uint8Array([0xfe, 0xff]);
		const buf = new Uint8Array(1 + invalidUtf8Kid.length + 64 + payload.length);
		buf[0] = invalidUtf8Kid.length;
		buf.set(invalidUtf8Kid, 1);
		buf.set(sig, 1 + invalidUtf8Kid.length);
		buf.set(payload, 1 + invalidUtf8Kid.length + 64);
		expect(() => decodeEnvelope(buf)).toThrow();
	});

	it("handles multi-byte UTF-8 kid", () => {
		const kid = "agent-\u00e9\u00e8\u00ea";
		const sig = new Uint8Array(64);
		const payload = new TextEncoder().encode("test");

		const encoded = encodeEnvelope(kid, sig, payload);
		const decoded = decodeEnvelope(encoded);
		expect(decoded.kid).toBe(kid);
	});
});
