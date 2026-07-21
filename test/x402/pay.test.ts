import { hexToBytes } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";
import { deriveEvmAddress, recoverAddress } from "../../src/crypto/wallet.js";
import { chainIdFromCaip2 } from "../../src/x402/assets.js";
import { eip3009Digest } from "../../src/x402/eip3009.js";
import { X402Error, X402_ERROR } from "../../src/x402/errors.js";
import { buildPaymentPayload, selectRequirement } from "../../src/x402/pay.js";
import type {
	PaymentPolicy,
	PaymentRequired,
	PaymentRequirements,
} from "../../src/x402/types.js";

const PRIV = hexToBytes(
	"0000000000000000000000000000000000000000000000000000000000000001",
);
const WALLET = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
const USDC_SEPOLIA = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const NONCE = new Uint8Array(32).fill(0xab);
const NOW = 1_752_744_000; // fixed unix seconds

function makeRequirement(
	over: Partial<PaymentRequirements> = {},
): PaymentRequirements {
	return {
		scheme: "exact",
		network: "eip155:84532",
		amount: "100000",
		asset: USDC_SEPOLIA,
		payTo: "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF",
		maxTimeoutSeconds: 60,
		extra: { name: "USDC", version: "2" },
		...over,
	};
}

const POLICY: PaymentPolicy = {
	perTxCap: "10.00",
	dailyCap: "20.00",
	allowedAssets: ["USDC"],
	allowedNetworks: ["eip155:84532"],
	autoPayThreshold: "1.00",
};

function makeRequired(accepts: PaymentRequirements[]): PaymentRequired {
	return {
		x402Version: 2,
		error: "payment required",
		resource: {
			url: "rine://task/1",
			description: "translate",
			mimeType: "application/json",
		},
		accepts,
		extensions: { foo: "bar" },
	};
}

describe("selectRequirement", () => {
	it("picks_first_acceptable_preserving_payee_order", () => {
		const tooBig = makeRequirement({ amount: "11000000" }); // > per-tx cap
		const ok = makeRequirement({ amount: "100000" });
		expect(selectRequirement(makeRequired([tooBig, ok]), POLICY, 0n)).toBe(ok);
	});

	it("picks_earliest_when_multiple_acceptable", () => {
		const a = makeRequirement({ amount: "100000" });
		const b = makeRequirement({ amount: "200000" });
		expect(selectRequirement(makeRequired([a, b]), POLICY, 0n)).toBe(a);
	});

	it("denies_by_default_when_policy_null", () => {
		try {
			selectRequirement(makeRequired([makeRequirement()]), null, 0n);
			throw new Error("expected throw");
		} catch (err) {
			expect(err).toBeInstanceOf(X402Error);
			expect((err as X402Error).code).toBe(
				X402_ERROR.NO_ACCEPTABLE_REQUIREMENT,
			);
			expect((err as X402Error).details?.reason).toBe(X402_ERROR.NO_POLICY);
		}
	});

	it("throws_no_acceptable_when_none_pass", () => {
		const tooBig = makeRequirement({ amount: "11000000" });
		expect(() => selectRequirement(makeRequired([tooBig]), POLICY, 0n)).toThrow(
			X402Error,
		);
	});

	it("throws_invalid_when_accepts_empty", () => {
		expect(() => selectRequirement(makeRequired([]), POLICY, 0n)).toThrow(
			/empty/,
		);
	});
});

describe("buildPaymentPayload", () => {
	const req = makeRequirement();
	const pr = makeRequired([req]);
	const payload = buildPaymentPayload(pr, req, PRIV, {
		now: NOW,
		nonce: NONCE,
	});

	it("echoes_chosen_requirement_verbatim", () => {
		expect(payload.accepted).toBe(req);
	});

	it("echoes_resource_and_extensions_from_quote", () => {
		expect(payload.resource).toEqual(pr.resource);
		expect(payload.extensions).toEqual(pr.extensions);
		expect(payload.x402Version).toBe(2);
	});

	it("test_stamps_quote_message_id_into_signed_extensions", () => {
		// R-1: the payer stamps the answered quote's message id so the payee can
		// bind the payment to the ONE quote it authored — alongside (not replacing)
		// the quote's own echoed extensions.
		const built = buildPaymentPayload(pr, req, PRIV, {
			now: NOW,
			nonce: NONCE,
			quoteMessageId: "quote-123",
		});
		expect(built.extensions?.["rine.quoteMessageId"]).toBe("quote-123");
		expect(built.extensions?.foo).toBe("bar");
	});

	it("test_omits_quote_ref_when_no_id_supplied", () => {
		// The raw HTTP-402 fetch flow has no rine quote message; the stamp is absent
		// and the payee then requires an explicit expected-terms override.
		expect(payload.extensions?.["rine.quoteMessageId"]).toBeUndefined();
	});

	it("test_stamp_does_not_mutate_the_source_quote_extensions", () => {
		buildPaymentPayload(pr, req, PRIV, {
			now: NOW,
			nonce: NONCE,
			quoteMessageId: "quote-xyz",
		});
		expect(pr.extensions).toEqual({ foo: "bar" });
	});

	it("builds_authorization_from_wallet_and_requirement", () => {
		const a = payload.payload.authorization;
		expect(a.from).toBe(WALLET);
		expect(a.from).toBe(deriveEvmAddress(PRIV));
		expect(a.to).toBe(req.payTo);
		expect(a.value).toBe(req.amount);
		expect(a.validAfter).toBe(String(NOW - 60));
		expect(a.validBefore).toBe(String(NOW + req.maxTimeoutSeconds));
		expect(a.nonce).toMatch(/^0x[0-9a-f]{64}$/);
	});

	it("signature_recovers_to_wallet_address", () => {
		const digest = eip3009Digest(
			{
				name: req.extra.name,
				version: req.extra.version,
				chainId: chainIdFromCaip2(req.network),
				verifyingContract: req.asset,
			},
			payload.payload.authorization,
		);
		expect(payload.payload.signature).toMatch(/^0x[0-9a-f]{130}$/);
		expect(recoverAddress(payload.payload.signature, digest)).toBe(WALLET);
	});

	it("preserves_unknown_requirement_fields_in_accepted", () => {
		const custom = makeRequirement({
			vendorTag: "acme",
		} as Partial<PaymentRequirements>);
		const built = buildPaymentPayload(makeRequired([custom]), custom, PRIV, {
			now: NOW,
			nonce: NONCE,
		});
		expect((built.accepted as Record<string, unknown>).vendorTag).toBe("acme");
	});

	it("uses_random_nonce_when_not_injected", () => {
		const p1 = buildPaymentPayload(pr, req, PRIV, { now: NOW });
		const p2 = buildPaymentPayload(pr, req, PRIV, { now: NOW });
		expect(p1.payload.authorization.nonce).not.toBe(
			p2.payload.authorization.nonce,
		);
	});

	it("clamps_validBefore_when_maxTimeoutSeconds_is_absurd", () => {
		const decade = makeRequirement({ maxTimeoutSeconds: 315_360_000 });
		const built = buildPaymentPayload(makeRequired([decade]), decade, PRIV, {
			now: NOW,
			nonce: NONCE,
		});
		// Clamped to the 24h ceiling, not now + 10 years.
		expect(built.payload.authorization.validBefore).toBe(String(NOW + 86_400));
	});

	it("reads_amount_from_maxAmountRequired_when_amount_absent", () => {
		const v1 = makeRequirement({ maxAmountRequired: "100000" });
		delete (v1 as Partial<PaymentRequirements>).amount;
		const built = buildPaymentPayload(makeRequired([v1]), v1, PRIV, {
			now: NOW,
			nonce: NONCE,
		});
		expect(built.payload.authorization.value).toBe("100000");
	});
});
