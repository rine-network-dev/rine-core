/**
 * Payee-settle orchestration — behaviour tests through the public interface.
 * The payer stamps `extensions["rine.quoteMessageId"]`; the payee loads THAT one
 * quote by id, proves it is payee-issued + same-conversation, and reconciles
 * against it. Every forge/omit/cross-conversation path must fail closed
 * (`NO_QUOTE`); the operator `--expect` override must NOT inherit payer-controlled
 * `extra`/`maxTimeoutSeconds`; the result must carry the matched quote.
 *
 * `decryptMessage` (the payee self-seal read) is the only external mocked — the
 * quote plaintext it returns stands in for the real HPKE self-decrypt so these
 * tests stay pure and deterministic.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/crypto/message.js", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("../../src/crypto/message.js")>();
	return { ...actual, decryptMessage: vi.fn() };
});

import type { MessageRead } from "../../src/api-types.js";
import { decryptMessage } from "../../src/crypto/message.js";
import type { HttpClient } from "../../src/http.js";
import { X402_ERROR } from "../../src/x402/errors.js";
import { FACILITATOR_PRESET } from "../../src/x402/facilitator.js";
import { MAX_AUTHORIZATION_TTL_SECONDS } from "../../src/x402/pay.js";
import {
	type ResolvedPayeeRequirement,
	buildExpectedRequirement,
	resolvePayeeRequirement,
	settleToReceipt,
} from "../../src/x402/payee-settle.js";
import type {
	PaymentPayload,
	PaymentRequirements,
} from "../../src/x402/types.js";

const USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"; // registry (sepolia)
const MERCHANT = "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF";
const PAYEE = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const OTHER = "ffffffff-1111-2222-3333-444444444444";
const CONV = "conv-1111";
const QUOTE_ID = "quote-9999";

const decryptMock = vi.mocked(decryptMessage);

afterEach(() => {
	vi.clearAllMocks();
	vi.unstubAllGlobals();
});

function req(over: Partial<PaymentRequirements> = {}): PaymentRequirements {
	return {
		scheme: "exact",
		network: "eip155:84532",
		amount: "100000",
		asset: USDC,
		payTo: MERCHANT,
		maxTimeoutSeconds: 60,
		extra: { name: "USDC", version: "2" },
		...over,
	};
}

function payment(over: Partial<PaymentPayload> = {}): PaymentPayload {
	return {
		x402Version: 2,
		accepted: req(),
		payload: {
			signature: `0x${"11".repeat(65)}`,
			authorization: {
				from: "0x1111111111111111111111111111111111111111",
				to: MERCHANT,
				value: "100000",
				validAfter: "1",
				validBefore: "9999999999",
				nonce: `0x${"22".repeat(32)}`,
			},
		},
		extensions: { "rine.quoteMessageId": QUOTE_ID },
		...over,
	};
}

/** A payee-issued quote row as `GET /messages/{id}` returns it (self-seal present). */
function quoteMsg(over: Partial<MessageRead> = {}): MessageRead {
	return {
		id: QUOTE_ID,
		conversation_id: CONV,
		from_agent_id: PAYEE,
		type: "rine.v1.x402_payment_required",
		encrypted_payload: "recipient-blob",
		self_encrypted_payload: "self-blob",
		encryption_version: "hpke-v1",
		created_at: "2026-07-21T00:00:00Z",
		...over,
	};
}

function clientReturning(msg: MessageRead | (() => never)): HttpClient {
	return {
		get: vi.fn(async () => (typeof msg === "function" ? msg() : msg)),
	} as unknown as HttpClient;
}

/** Make the mocked self-decrypt yield the given quote `accepts[]`. */
function decryptYields(accepts: PaymentRequirements[]): void {
	decryptMock.mockResolvedValue({
		plaintext: JSON.stringify({ x402Version: 2, accepts }),
		senderKid: `rine:${PAYEE}`,
		verified: true,
		verificationStatus: "verified",
	});
}

async function resolveWithRef(
	over: {
		payment?: Partial<PaymentPayload>;
		msg?: MessageRead | (() => never);
	} = {},
): Promise<ResolvedPayeeRequirement> {
	return resolvePayeeRequirement({
		payment: payment(over.payment),
		expected: {},
		client: clientReturning(over.msg ?? quoteMsg()),
		configDir: "/tmp/cfg",
		payeeAgentId: PAYEE,
		conversationId: CONV,
	});
}

async function expectRefused(
	promise: Promise<unknown>,
	code: string,
): Promise<void> {
	await expect(promise).rejects.toMatchObject({ name: "X402Error", code });
}

describe("resolvePayeeRequirement — ref binding", () => {
	it("test_ref_bind_happy_path_returns_matched_quote", async () => {
		decryptYields([req()]);
		// Overpayment rides the SIGNED authorization value; the echoed `accepted`
		// still names the payee's 100000 tier exactly. The RETURNED match
		// amount is the payee-authored quote's, never the payer's signed value.
		const resolved = await resolveWithRef({
			payment: {
				payload: {
					signature: `0x${"11".repeat(65)}`,
					authorization: {
						from: "0x1111111111111111111111111111111111111111",
						to: MERCHANT,
						value: "150000", // overpay via the signed value
						validAfter: "1",
						validBefore: "9999999999",
						nonce: `0x${"22".repeat(32)}`,
					},
				},
			},
		});
		expect(resolved.requirement.payTo).toBe(MERCHANT);
		expect(resolved.match.quoteMessageId).toBe(QUOTE_ID);
		expect(resolved.match.amount).toBe("100000"); // the payee-authored quote amount
		expect(resolved.match.asset).toBe(USDC);
		expect(resolved.match.network).toBe("eip155:84532");
	});

	it("test_missing_ref_fails_closed", async () => {
		decryptYields([req()]);
		await expectRefused(
			resolveWithRef({ payment: { extensions: {} } }),
			X402_ERROR.NO_QUOTE,
		);
		expect(decryptMock).not.toHaveBeenCalled();
	});

	it("test_forged_ref_not_payee_issued_fails_closed", async () => {
		decryptYields([req()]);
		await expectRefused(
			resolveWithRef({ msg: quoteMsg({ from_agent_id: OTHER }) }),
			X402_ERROR.NO_QUOTE,
		);
	});

	it("test_cross_conversation_ref_fails_closed", async () => {
		decryptYields([req()]);
		await expectRefused(
			resolveWithRef({ msg: quoteMsg({ conversation_id: "other-conv" }) }),
			X402_ERROR.NO_QUOTE,
		);
	});

	it("test_ref_points_at_non_quote_type_fails_closed", async () => {
		decryptYields([req()]);
		await expectRefused(
			resolveWithRef({ msg: quoteMsg({ type: "rine.v1.x402_payment" }) }),
			X402_ERROR.NO_QUOTE,
		);
	});

	it("test_unresolvable_ref_fails_closed", async () => {
		await expectRefused(
			resolveWithRef({
				msg: () => {
					throw new Error("404 not found");
				},
			}),
			X402_ERROR.NO_QUOTE,
		);
	});

	it("test_ref_without_self_seal_fails_closed", async () => {
		await expectRefused(
			resolveWithRef({ msg: quoteMsg({ self_encrypted_payload: null }) }),
			X402_ERROR.NO_QUOTE,
		);
		expect(decryptMock).not.toHaveBeenCalled();
	});

	it("test_ref_failing_signature_verification_fails_closed", async () => {
		decryptMock.mockResolvedValue({
			plaintext: JSON.stringify({ x402Version: 2, accepts: [req()] }),
			senderKid: `rine:${PAYEE}`,
			verified: false,
			verificationStatus: "invalid",
		});
		await expectRefused(resolveWithRef(), X402_ERROR.NO_QUOTE);
	});

	it("test_ref_signed_by_another_agent_fails_closed", async () => {
		// The referenced quote decrypts, but its envelope was signed by an agent other
		// than the payee the server recorded as its sender — the terms are not the
		// payee's own, so there is nothing safe to reconcile against.
		decryptMock.mockResolvedValue({
			plaintext: JSON.stringify({ x402Version: 2, accepts: [req()] }),
			senderKid: `rine:${OTHER}`,
			verified: false,
			verificationStatus: "sender-mismatch",
		});
		await expectRefused(resolveWithRef(), X402_ERROR.NO_QUOTE);
	});

	it("test_underpayment_against_referenced_quote_is_refused", async () => {
		decryptYields([req({ amount: "1000000" })]); // quote wants 1.00
		await expectRefused(
			resolveWithRef({ payment: { accepted: req({ amount: "100000" }) } }),
			X402_ERROR.REQUIREMENT_MISMATCH,
		);
	});
});

describe("buildExpectedRequirement / override", () => {
	it("test_override_extra_is_registry_derived_not_payer_inherited", async () => {
		// The payer set a hostile `extra`/`maxTimeoutSeconds`; the operator override
		// must ignore both and author the requirement entirely itself.
		const resolved = await resolvePayeeRequirement({
			payment: payment({
				accepted: req({
					extra: { name: "EVIL", version: "9" },
					maxTimeoutSeconds: 315_360_000,
				}),
				extensions: {}, // no ref — override is the only source
			}),
			expected: {
				payTo: MERCHANT,
				expectAmount: "0.10",
				expectAsset: USDC,
				expectNetwork: "eip155:84532",
			},
			client: clientReturning(() => {
				throw new Error("override must not fetch a quote");
			}),
			configDir: "/tmp/cfg",
			payeeAgentId: PAYEE,
			conversationId: CONV,
		});
		expect(resolved.requirement.extra).toEqual({ name: "USDC", version: "2" });
		expect(resolved.requirement.maxTimeoutSeconds).toBe(
			MAX_AUTHORIZATION_TTL_SECONDS,
		);
		expect(resolved.match.quoteMessageId).toBeNull();
		expect(resolved.match.amount).toBe("100000");
	});

	it("test_partial_expected_terms_fail_closed", () => {
		expect(() => buildExpectedRequirement({ payTo: MERCHANT })).toThrow(
			/expect-amount/,
		);
	});

	it("test_no_expected_terms_returns_undefined", () => {
		expect(buildExpectedRequirement({})).toBeUndefined();
	});

	it("test_unknown_asset_override_is_rejected", () => {
		expect(() =>
			buildExpectedRequirement({
				payTo: MERCHANT,
				expectAmount: "0.10",
				expectAsset: "0x9999999999999999999999999999999999999999",
				expectNetwork: "eip155:84532",
			}),
		).toThrow();
	});
});

describe("settleToReceipt — surfaces the matched quote", () => {
	const resolved: ResolvedPayeeRequirement = {
		requirement: req(),
		match: {
			quoteMessageId: QUOTE_ID,
			amount: "100000",
			asset: USDC,
			network: "eip155:84532",
		},
	};

	it("test_settled_result_carries_matched_quote", async () => {
		let call = 0;
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => {
				call += 1;
				const body =
					call === 1
						? { isValid: true }
						: {
								success: true,
								transaction: "0xabc",
								network: "base-sepolia",
								payer: "0x1",
							};
				return new Response(JSON.stringify(body), { status: 200 });
			}),
		);
		const out = await settleToReceipt(
			payment(),
			resolved,
			FACILITATOR_PRESET.payai,
		);
		expect(out.status).toBe("settled");
		expect(out.matchedQuote.quoteMessageId).toBe(QUOTE_ID);
		expect(out.receiptBody.transaction).toBe("0xabc");
	});

	it("test_verification_failure_still_carries_matched_quote", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(
						JSON.stringify({ isValid: false, invalidReason: "bad_sig" }),
						{ status: 200 },
					),
			),
		);
		const out = await settleToReceipt(
			payment(),
			resolved,
			FACILITATOR_PRESET.payai,
		);
		expect(out.status).toBe("verification-failed");
		expect(out.receiptBody.success).toBe(false);
		expect(out.receiptBody.errorReason).toBe("bad_sig");
		expect(out.matchedQuote.quoteMessageId).toBe(QUOTE_ID);
	});

	it("test_carries_real_facilitator_verify_response_on_settle", async () => {
		// The facilitator's /verify reply carries `payer` plus a provider-specific
		// field; settleToReceipt must thread that REAL response through so callers
		// keep those fields instead of a synthesised `{ isValid: true }`.
		let call = 0;
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => {
				call += 1;
				const body =
					call === 1
						? { isValid: true, payer: "0xPAYER", riskScore: 7 }
						: {
								success: true,
								transaction: "0xabc",
								network: "base-sepolia",
								payer: "0xPAYER",
							};
				return new Response(JSON.stringify(body), { status: 200 });
			}),
		);
		const out = await settleToReceipt(
			payment(),
			resolved,
			FACILITATOR_PRESET.payai,
		);
		expect(out.verification.isValid).toBe(true);
		expect(out.verification.payer).toBe("0xPAYER");
		expect(out.verification.riskScore).toBe(7);
	});

	it("test_carries_real_facilitator_verify_response_on_failure", async () => {
		// The failure branch threads the REAL response too — `payer` survives.
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(
						JSON.stringify({
							isValid: false,
							invalidReason: "bad_sig",
							payer: "0xPAYER",
						}),
						{ status: 200 },
					),
			),
		);
		const out = await settleToReceipt(
			payment(),
			resolved,
			FACILITATOR_PRESET.payai,
		);
		expect(out.verification.isValid).toBe(false);
		expect(out.verification.invalidReason).toBe("bad_sig");
		expect(out.verification.payer).toBe("0xPAYER");
	});
});
