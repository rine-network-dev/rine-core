/**
 * Payee-side reconciliation — the canonical x402 resource-server invariant.
 *
 * A payee settles a payment ONLY against terms IT authored (the quote it issued),
 * never against the payer's echoed `accepted` block: a mismatched `payTo`, amount,
 * asset, or network yields a `success:false` receipt and no settle.
 *
 * This module is PURE — zero I/O. A payment is bound to the ONE quote it answers
 * (via the signed `extensions[X402_QUOTE_REF_KEY]`); the payee loads that single
 * quote and passes its `accepts[]` here. Binding to that single quote — not a
 * conversation-wide union of every quote — keeps a payment from settling against
 * any quote other than the one it answers. The I/O-shaped ref loading lives in
 * `payee-settle.ts`, which every surface shares.
 */

import { parseAtomicAmount, parseAtomicUnits } from "./assets.js";
import { X402Error, X402_ERROR } from "./errors.js";
import type { PaymentPayload, PaymentRequirements } from "./types.js";

/**
 * Case-insensitive equality for hex addresses / CAIP ids (never `==`-loose).
 * Absent values coerce to `""` so a malformed payer `accepted` that omits `asset`
 * or `payTo` yields a clean non-match instead of a `TypeError` — field-for-field
 * with the Python `reconcile_payment` (`str(...get(..., ""))`). Keeps the failure
 * as a typed `X402Error(REQUIREMENT_MISMATCH)` so every surface threads a graceful
 * receipt rather than an uncaught throw.
 */
function eqCi(a: string | undefined, b: string | undefined): boolean {
	return String(a ?? "").toLowerCase() === String(b ?? "").toLowerCase();
}

/**
 * Return the payee-authored `PaymentRequirements` (from `quoteAccepts`) that the
 * incoming `payment` legitimately answers, or throw. A quote entry matches iff ALL
 * hold: same `scheme`; same `network`; same `asset` (case-insensitive); same
 * `payTo` (case-insensitive); and the tier the payer's OWN `accepted` block NAMES
 * (its exact atomic amount) equals the quote entry's atomic amount.
 *
 * Matching on the EXACT named amount (not the first tier the amount happens to
 * satisfy) is load-bearing: a multi-tier same-asset quote — `accepts=[{1.0},{5.0}]`
 * on one asset/network/payTo — must return the tier the 5.0 payer selected, never
 * the cheaper `1.0` entry a `>=` first-match would pick. Binding to the NAMED tier
 * keeps the settled amount and `matchedQuote` aligned with the quote the payer
 * answered.
 *
 * Defense-in-depth: the SIGNED EIP-3009 `authorization.value` — not the payer-
 * controlled echoed `accepted.amount` — must cover the quoted atomic amount, so a
 * payment whose signed value underfunds the tier it names is refused LOCALLY even
 * if a non-conformant facilitator would settle it. Overpayment (a signed value
 * above the tier) is still allowed. Amounts compare in the token's own atomic
 * units — asset+network already match, so no decimal scaling is needed and
 * unknown-decimal assets don't spuriously block here.
 *
 * The RETURNED value is the payee's own requirement; callers forward THAT to the
 * facilitator, never `payment.accepted`.
 */
export function reconcilePayment(
	payment: PaymentPayload,
	quoteAccepts: readonly PaymentRequirements[],
): PaymentRequirements {
	if (quoteAccepts.length === 0) {
		throw new X402Error(
			X402_ERROR.NO_QUOTE,
			"No payee-issued quote to reconcile against — refusing to settle payer-authored terms (fail closed)",
		);
	}
	const accepted = payment.accepted ?? ({} as PaymentRequirements);
	// The tier the payer's echoed `accepted` names, and the value it actually SIGNED.
	const named = parseAtomicAmount(accepted);
	const signed = parseAtomicUnits(
		String(payment.payload?.authorization?.value ?? ""),
		"Signed authorization value",
	);
	for (const quote of quoteAccepts) {
		if (accepted.scheme !== quote.scheme) continue;
		if (accepted.network !== quote.network) continue;
		if (!eqCi(accepted.asset, quote.asset)) continue;
		if (!eqCi(accepted.payTo, quote.payTo)) continue;
		const quoted = parseAtomicAmount(quote);
		if (named !== quoted) continue; // bind to the NAMED tier, not first-satisfied
		if (signed < quoted) {
			throw new X402Error(
				X402_ERROR.REQUIREMENT_MISMATCH,
				"Signed authorization value underfunds the quoted requirement — refusing to settle (local underpayment guard)",
				{ signed: signed.toString(), required: quoted.toString() },
			);
		}
		return quote;
	}
	throw new X402Error(
		X402_ERROR.REQUIREMENT_MISMATCH,
		"Payment matches no payee-issued quote (scheme/network/asset/payTo/amount) — refusing to settle",
		{
			scheme: accepted.scheme,
			network: accepted.network,
			asset: accepted.asset,
			payTo: accepted.payTo,
		},
	);
}
