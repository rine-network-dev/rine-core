/**
 * Shared x402 payee-settle orchestration — the ONE place CLI, MCP, and the SDKs
 * reconcile an incoming payment against the payee's OWN quote and run the
 * verify → settle → receipt ladder. No surface reimplements this: each surface
 * supplies only its own facilitator/header parsing and result rendering, importing
 * everything else.
 *
 * A payment is bound to the ONE quote it answers via {@link loadReferencedQuote}
 * (the signed `extensions[X402_QUOTE_REF_KEY]`) — never the payer-echoed
 * `pp.accepted`, and never a conversation-wide union. An explicit operator
 * expected-terms override short-circuits the ref (authoritative, no ref needed).
 * Every unresolved path fails closed with a typed `NO_QUOTE`.
 */

import type { HttpClient } from "../http.js";
import {
	parseUnits,
	requirementAmount,
	resolveDecimals,
	resolveTokenExtra,
} from "./assets.js";
import { X402Error, X402_ERROR } from "./errors.js";
import {
	type FacilitatorConfig,
	type VerifyResponse,
	settlePayment,
	verifyPayment,
} from "./facilitator.js";
import { MAX_AUTHORIZATION_TTL_SECONDS } from "./pay.js";
import { loadReferencedQuote } from "./quote-ref.js";
import { reconcilePayment } from "./reconcile.js";
import type {
	PaymentPayload,
	PaymentRequirements,
	SettlementResponse,
} from "./types.js";

/** Terminal outcome of the verify→settle ladder (a receipt is sent in all three). */
export type FulfillSettleStatus =
	| "settled"
	| "settlement-failed"
	| "verification-failed";

/** Provenance of the reconciled quote so an integration binds good<->quote. */
export interface MatchedQuote {
	/** The quote message id the payment answered; `null` for an operator override. */
	quoteMessageId: string | null;
	/** The reconciled requirement's atomic amount / asset / network. */
	amount: string;
	asset: string;
	network: string;
}

/** The payee-owned requirement to settle + the matched-quote provenance. */
export interface ResolvedPayeeRequirement {
	requirement: PaymentRequirements;
	match: MatchedQuote;
}

export interface FulfillReceipt {
	status: FulfillSettleStatus;
	receiptBody: SettlementResponse;
	/**
	 * The REAL facilitator `/verify` response (never a synthesised stand-in), so a
	 * caller keeps `payer` and any provider-specific fields the facilitator returns.
	 * `isValid` is `true` on a settlement failure (verification passed; settlement
	 * is what failed) and `false` only on a verification failure.
	 */
	verification: VerifyResponse;
	/** Which quote the settled payment answered — surfaced to integrations. */
	matchedQuote: MatchedQuote;
}

/** Operator-supplied expected terms for an OUT-OF-BAND quote (escape hatch). */
export interface ExpectedTermsInput {
	payTo?: string;
	expectAmount?: string;
	expectAsset?: string;
	expectNetwork?: string;
}

/**
 * Build the operator's explicit single-entry quote, or `undefined` when none were
 * supplied. All four fields are required together (a partial expectation is
 * ambiguous — fail closed); `scheme` is inferred `exact`. The major-unit amount is
 * converted via the asset's registry decimals (unknown ⇒ `UNKNOWN_ASSET_DECIMALS`).
 *
 * The override is FULLY operator-authored. `extra` (the EIP-712 domain) is
 * derived from the trusted known-asset registry and `maxTimeoutSeconds` is the
 * fixed protocol ceiling — NEVER inherited from the payer-controlled `accepted`.
 */
export function buildExpectedRequirement(
	input: ExpectedTermsInput,
): PaymentRequirements | undefined {
	const { payTo, expectAmount, expectAsset, expectNetwork } = input;
	const provided = [payTo, expectAmount, expectAsset, expectNetwork].filter(
		(v) => v !== undefined && v !== "",
	);
	if (provided.length === 0) return undefined;
	if (provided.length < 4) {
		throw new X402Error(
			X402_ERROR.INVALID_REQUIREMENT,
			"Explicit expected terms need pay-to, expect-amount, expect-asset and expect-network together (a partial expectation is ambiguous — fail closed)",
		);
	}
	const network = expectNetwork as string;
	const asset = expectAsset as string;
	const amount = parseUnits(
		expectAmount as string,
		resolveDecimals(network, asset),
	).toString();
	return {
		scheme: "exact",
		network,
		asset,
		payTo: payTo as string,
		amount,
		maxTimeoutSeconds: MAX_AUTHORIZATION_TTL_SECONDS,
		extra: resolveTokenExtra(network, asset),
	};
}

function toMatch(
	req: PaymentRequirements,
	quoteMessageId: string | null,
): MatchedQuote {
	return {
		quoteMessageId,
		amount: requirementAmount(req),
		asset: req.asset,
		network: req.network,
	};
}

/**
 * Resolve the payee-owned requirement to settle against. Explicit expected
 * terms win when supplied (operator intent), else the payment's referenced quote.
 * Returns the matched payee-authored requirement + its provenance, or throws a
 * typed {@link X402Error} (`NO_QUOTE` / `REQUIREMENT_MISMATCH` /
 * `UNKNOWN_ASSET_DECIMALS` / `INVALID_REQUIREMENT`) — fail closed, never settling
 * payer-authored terms.
 */
export async function resolvePayeeRequirement(params: {
	payment: PaymentPayload;
	expected: ExpectedTermsInput;
	client: HttpClient;
	configDir: string;
	payeeAgentId: string;
	conversationId: string;
}): Promise<ResolvedPayeeRequirement> {
	const override = buildExpectedRequirement(params.expected);
	if (override) {
		const requirement = reconcilePayment(params.payment, [override]);
		return { requirement, match: toMatch(requirement, null) };
	}
	const ref = await loadReferencedQuote({
		payment: params.payment,
		client: params.client,
		configDir: params.configDir,
		payeeAgentId: params.payeeAgentId,
		conversationId: params.conversationId,
	});
	const requirement = reconcilePayment(params.payment, ref.accepts);
	return { requirement, match: toMatch(requirement, ref.messageId) };
}

/** Synthesise a `success:false` receipt body so a refused payer reaches payment-failed. */
export function refusalReceiptBody(
	network: string,
	payer: string,
	reason: string,
): SettlementResponse {
	return {
		success: false,
		transaction: "",
		network,
		payer,
		errorReason: reason,
	};
}

/**
 * The settle-first ladder: verify the signed payment against the RECONCILED,
 * payee-authored `requirement` (never `pp.accepted`), and — only when valid —
 * settle it. On an invalid verification, settlement is skipped and a
 * `success:false` receipt body is synthesised so the payer still reaches a
 * terminal `payment-failed`. The matched-quote provenance rides through on every
 * outcome. A facilitator HTTP failure throws `X402FacilitatorError`.
 */
export async function settleToReceipt(
	pp: PaymentPayload,
	resolved: ResolvedPayeeRequirement,
	facilitator: FacilitatorConfig,
	signal?: AbortSignal,
): Promise<FulfillReceipt> {
	const { requirement, match } = resolved;
	const verification = await verifyPayment(pp, requirement, {
		facilitator,
		signal,
	});
	if (verification.isValid) {
		const settlement = await settlePayment(pp, requirement, {
			facilitator,
			signal,
		});
		return {
			status: settlement.success ? "settled" : "settlement-failed",
			receiptBody: settlement,
			verification,
			matchedQuote: match,
		};
	}
	return {
		status: "verification-failed",
		receiptBody: refusalReceiptBody(
			requirement.network,
			pp.payload.authorization.from,
			verification.invalidReason ?? "verification_failed",
		),
		verification,
		matchedQuote: match,
	};
}
