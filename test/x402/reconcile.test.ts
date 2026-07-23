/**
 * Reconciliation — behavioural tests through the public reconcile
 * interface. Every mismatch axis (payTo redirect,
 * underpay, wrong asset/network/scheme, worthless token) must REFUSE; the payer's
 * NAMED tier is returned for a multi-tier same-asset quote; the SIGNED
 * authorization value — not the echoed `accepted.amount` — is what must cover the
 * quote; exact/overpay pass.
 */

import { describe, expect, it } from "vitest";
import { X402_ERROR } from "../../src/x402/errors.js";
import { reconcilePayment } from "../../src/x402/reconcile.js";
import type {
	PaymentPayload,
	PaymentRequirements,
} from "../../src/x402/types.js";

const USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const MERCHANT = "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF";
const MALLORY = "0x000000000000000000000000000000000000dEaD";
const WORTHLESS = "0x1111111111111111111111111111111111111111";
const PAYER = "0x9999999999999999999999999999999999999999";

function quote(over: Partial<PaymentRequirements> = {}): PaymentRequirements {
	return {
		scheme: "exact",
		network: "eip155:84532",
		amount: "1000000", // 1.00 USDC
		asset: USDC,
		payTo: MERCHANT,
		maxTimeoutSeconds: 60,
		extra: { name: "USDC", version: "2" },
		...over,
	};
}

/**
 * A signed payment envelope. `accepted` is the payer-echoed block (the tier it
 * names); `signedValue` is the EIP-3009 `authorization.value` actually signed —
 * defaults to the named amount so the common case signs exactly what it names.
 */
function payment(
	over: Partial<PaymentRequirements> = {},
	signedValue?: string,
): PaymentPayload {
	const accepted = quote(over);
	return {
		x402Version: 2,
		accepted,
		payload: {
			signature: `0x${"11".repeat(65)}`,
			authorization: {
				from: PAYER,
				to: accepted.payTo,
				value: signedValue ?? accepted.amount ?? "0",
				validAfter: "0",
				validBefore: "99999999999",
				nonce: `0x${"00".repeat(32)}`,
			},
		},
	};
}

function expectCode(fn: () => unknown, code: string): void {
	try {
		fn();
		throw new Error("expected reconciliation to throw");
	} catch (err) {
		expect((err as { code?: string }).code).toBe(code);
	}
}

describe("reconcilePayment — happy path", () => {
	it("test_exact_match_returns_the_payee_owned_quote", () => {
		const q = quote();
		const result = reconcilePayment(payment(), [q]);
		// Returns the PAYEE-authored entry (identity), not the payment's block.
		expect(result).toBe(q);
	});

	it("test_overpayment_via_signed_value_is_accepted", () => {
		const q = quote();
		// Payer NAMES the 1.00 tier but SIGNS 2.00 — overpayment rides the signed
		// value, not the echoed amount, and still settles against the payee tier.
		expect(reconcilePayment(payment({}, "2000000"), [q])).toBe(q);
	});

	it("test_asset_and_payTo_match_is_case_insensitive", () => {
		const q = quote();
		const paid = payment({
			asset: USDC.toUpperCase(),
			payTo: MERCHANT.toLowerCase(),
		});
		expect(reconcilePayment(paid, [q])).toBe(q);
	});

	it("test_selects_matching_entry_among_several_quotes", () => {
		const usdcQuote = quote();
		const otherNet = quote({ network: "eip155:8453" });
		expect(reconcilePayment(payment(), [otherNet, usdcQuote])).toBe(usdcQuote);
	});
});

describe("reconcilePayment — multi-tier same-asset quote binds the NAMED tier", () => {
	it("test_five_dollar_payer_gets_the_five_dollar_tier_not_the_first", () => {
		const tier1 = quote({ amount: "1000000" }); // 1.00
		const tier5 = quote({ amount: "5000000" }); // 5.00, same asset/network/payTo
		// The payer names (and signs) the 5.00 tier. A `>=` first-match would wrongly
		// return tier1; the fix returns the tier the payer actually selected.
		const result = reconcilePayment(payment({ amount: "5000000" }), [
			tier1,
			tier5,
		]);
		expect(result).toBe(tier5);
		expect(result.amount).toBe("5000000");
	});

	it("test_one_dollar_payer_gets_the_one_dollar_tier", () => {
		const tier1 = quote({ amount: "1000000" });
		const tier5 = quote({ amount: "5000000" });
		const result = reconcilePayment(payment({ amount: "1000000" }), [
			tier1,
			tier5,
		]);
		expect(result).toBe(tier1);
	});

	it("test_named_amount_matching_no_tier_is_refused", () => {
		const tier1 = quote({ amount: "1000000" });
		const tier5 = quote({ amount: "5000000" });
		// 3.00 is between the tiers — it names no tier, so it must be refused rather
		// than silently settling the cheaper one.
		expectCode(
			() => reconcilePayment(payment({ amount: "3000000" }), [tier1, tier5]),
			X402_ERROR.REQUIREMENT_MISMATCH,
		);
	});
});

describe("reconcilePayment — signed authorization value is the underpayment guard", () => {
	it("test_signed_value_below_named_tier_is_refused_locally", () => {
		const q = quote(); // 1.00 tier
		// Payer echoes the full 1.00 in `accepted` (names the tier) but SIGNS only
		// 0.000001 — a conformant facilitator would refuse, but the payee must not
		// depend on that: refuse locally.
		expectCode(
			() => reconcilePayment(payment({}, "1"), [q]),
			X402_ERROR.REQUIREMENT_MISMATCH,
		);
	});

	it("test_named_expensive_tier_but_signed_cheap_is_refused", () => {
		const tier1 = quote({ amount: "1000000" });
		const tier5 = quote({ amount: "5000000" });
		// The cross-tier attack: name the 5.00 tier (to obtain its good) but sign
		// only 1.00. The named tier matches, but the signed value underfunds it.
		expectCode(
			() =>
				reconcilePayment(payment({ amount: "5000000" }, "1000000"), [
					tier1,
					tier5,
				]),
			X402_ERROR.REQUIREMENT_MISMATCH,
		);
	});

	it("test_non_integer_signed_value_is_a_typed_refusal", () => {
		const q = quote();
		expectCode(
			() => reconcilePayment(payment({}, "1.5"), [q]),
			X402_ERROR.INVALID_REQUIREMENT,
		);
	});
});

describe("reconcilePayment — hostile payer refusals", () => {
	it("test_payTo_redirect_is_refused", () => {
		expectCode(
			() => reconcilePayment(payment({ payTo: MALLORY }), [quote()]),
			X402_ERROR.REQUIREMENT_MISMATCH,
		);
	});

	it("test_underpayment_via_named_amount_is_refused", () => {
		expectCode(
			() => reconcilePayment(payment({ amount: "1" }), [quote()]),
			X402_ERROR.REQUIREMENT_MISMATCH,
		);
	});

	it("test_wrong_asset_worthless_token_is_refused", () => {
		expectCode(
			() => reconcilePayment(payment({ asset: WORTHLESS }), [quote()]),
			X402_ERROR.REQUIREMENT_MISMATCH,
		);
	});

	it("test_wrong_network_is_refused", () => {
		expectCode(
			() => reconcilePayment(payment({ network: "eip155:8453" }), [quote()]),
			X402_ERROR.REQUIREMENT_MISMATCH,
		);
	});

	it("test_wrong_scheme_is_refused", () => {
		expectCode(
			() => reconcilePayment(payment({ scheme: "permit2" }), [quote()]),
			X402_ERROR.REQUIREMENT_MISMATCH,
		);
	});

	it("test_no_quote_fails_closed", () => {
		expectCode(() => reconcilePayment(payment(), []), X402_ERROR.NO_QUOTE);
	});

	it("test_missing_asset_refuses_without_throwing_typeerror", () => {
		// A well-formed envelope whose `accepted` omits `asset` must refuse with a
		// typed X402Error (not a TypeError from `undefined.toLowerCase()`), so every
		// surface threads a graceful receipt — parity with Python reconcile_payment.
		const paid = payment();
		const { asset: _dropAsset, ...noAsset } = paid.accepted;
		paid.accepted = noAsset as PaymentRequirements;
		expectCode(
			() => reconcilePayment(paid, [quote()]),
			X402_ERROR.REQUIREMENT_MISMATCH,
		);
	});

	it("test_missing_payTo_refuses_without_throwing_typeerror", () => {
		const paid = payment();
		const { payTo: _dropPayTo, ...noPayTo } = paid.accepted;
		paid.accepted = noPayTo as PaymentRequirements;
		expectCode(
			() => reconcilePayment(paid, [quote()]),
			X402_ERROR.REQUIREMENT_MISMATCH,
		);
	});
});
