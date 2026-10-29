import { describe, expect, it } from "vitest";
import type {
	MessageDecryptResult,
	VerificationStatus,
} from "../../src/crypto/message.js";
import { X402_ERROR, X402Error } from "../../src/x402/errors.js";
import {
	requireVerifiedPlaintext,
	requireVerifiedSender,
} from "../../src/x402/sender-guard.js";

const SENDER = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const MESSAGE = "33333333-3333-4333-8333-333333333333";

function decrypt(status: VerificationStatus): MessageDecryptResult {
	return {
		plaintext: '{"ok":true}',
		senderKid: `rine:${OTHER}#0`,
		verified: status === "verified",
		verificationStatus: status,
	};
}

describe("requireVerifiedPlaintext", () => {
	it("returns the body of a verified decrypt", () => {
		expect(requireVerifiedPlaintext(decrypt("verified"), SENDER, MESSAGE)).toBe(
			'{"ok":true}',
		);
	});

	it.each([
		"invalid",
		"sender-mismatch",
	] as const)("refuses a %s decrypt with inauthentic-sender, body present or not", (status) => {
		for (const decrypted of [
			decrypt(status),
			{ ...decrypt(status), plaintext: undefined },
		]) {
			const attempt = () => requireVerifiedPlaintext(decrypted, SENDER, MESSAGE);
			expect(attempt).toThrow(X402Error);
			expect(attempt).toThrow(
				expect.objectContaining({
					code: X402_ERROR.INAUTHENTIC_SENDER,
					details: expect.objectContaining({ verificationStatus: status }),
				}),
			);
		}
	});

	it("refuses an unverifiable decrypt with the retryable sender-unverifiable code, body present or not", () => {
		for (const decrypted of [
			decrypt("unverifiable"),
			{ ...decrypt("unverifiable"), plaintext: undefined },
		]) {
			const attempt = () => requireVerifiedPlaintext(decrypted, SENDER, MESSAGE);
			expect(attempt).toThrow(X402Error);
			expect(attempt).toThrow(
				expect.objectContaining({
					code: X402_ERROR.SENDER_UNVERIFIABLE,
					details: expect.objectContaining({ verificationStatus: "unverifiable" }),
				}),
			);
		}
	});

	it("refuses a verified decrypt that carries no body rather than returning undefined", () => {
		const bodiless: MessageDecryptResult = { ...decrypt("verified"), plaintext: undefined };
		const attempt = () => requireVerifiedPlaintext(bodiless, SENDER, MESSAGE);
		expect(attempt).toThrow(
			expect.objectContaining({
				code: X402_ERROR.INAUTHENTIC_SENDER,
				details: expect.objectContaining({ verificationStatus: "verified" }),
			}),
		);
	});

	it("names the agent that actually signed a re-sealed message", () => {
		expect(() =>
			requireVerifiedPlaintext(decrypt("sender-mismatch"), SENDER, MESSAGE),
		).toThrow(`rine:${OTHER}#0`);
	});

	it("tells the operator an unverifiable refusal is retryable", () => {
		expect(() =>
			requireVerifiedPlaintext(decrypt("unverifiable"), SENDER, MESSAGE),
		).toThrow(/retry/);
	});
});

describe("requireVerifiedSender", () => {
	it("accepts a verified verdict from a surface with no kid", () => {
		expect(() =>
			requireVerifiedSender({ verificationStatus: "verified" }, SENDER, MESSAGE),
		).not.toThrow();
	});

	it("refuses an unverifiable verdict whose kid is null", () => {
		expect(() =>
			requireVerifiedSender(
				{ verificationStatus: "unverifiable", senderKid: null },
				SENDER,
				MESSAGE,
			),
		).toThrow(expect.objectContaining({ code: X402_ERROR.SENDER_UNVERIFIABLE }));
	});

	it.each([
		["a row that failed to decrypt", { decryptError: "AEAD failure" }, SENDER],
		["a cleartext A2A row", { a2aCleartext: true }, SENDER],
		["a row with no authenticated sender", {}, null],
	] as const)("keeps %s on the final inauthentic-sender refusal", (_name, extra, sender) => {
		const attempt = () =>
			requireVerifiedSender(
				{ verificationStatus: "unverifiable", ...extra },
				sender,
				MESSAGE,
			);
		expect(attempt).toThrow(
			expect.objectContaining({ code: X402_ERROR.INAUTHENTIC_SENDER }),
		);
	});

	it("still marks an opened row with an authenticated sender retryable", () => {
		expect(() =>
			requireVerifiedSender(
				{ verificationStatus: "unverifiable", decryptError: null, a2aCleartext: false },
				SENDER,
				MESSAGE,
			),
		).toThrow(expect.objectContaining({ code: X402_ERROR.SENDER_UNVERIFIABLE }));
	});
});
