/**
 * x402 v1.0 wire types — the verbatim x402 V2 objects carried as the E2EE payload
 * of the three rine message types, plus the client-side spend-policy shape.
 *
 * The decrypted plaintext of each x402 message IS the x402 V2 object byte-for-byte
 * — no rine wrapper, no renamed fields. Unknown keys are preserved (`[k: string]`).
 */

/** x402 protocol version carried in the objects. */
export const X402_VERSION = 2;

/** Cleartext-metadata key for the optional coarse status marker. */
export const X402_METADATA_KEY = "rine.x402";

/**
 * Extensions key: the payer stamps the answered quote's message id here, inside
 * the SIGNED, E2EE `PaymentPayload`, so the payee binds the payment to the ONE
 * `x402_payment_required` it authored — settling only against that single quote,
 * never a conversation-wide union of quotes. A SINGLE exported constant shared by
 * every payer/payee surface — never a bare string literal repeated across packages.
 */
export const X402_QUOTE_REF_KEY = "rine.quoteMessageId";

/** Settlement-rail identifier for this rail. */
export const X402_RAIL = "x402";

/** Schemes the v1.0 signer supports (EIP-3009 `exact` only; no Permit2/Solana). */
export const X402_SUPPORTED_SCHEMES = ["exact"] as const;
export type X402Scheme = (typeof X402_SUPPORTED_SCHEMES)[number];

/** The four — and only four — coarse lifecycle states in the cleartext marker. */
export const X402_STATUS = {
	REQUIRED: "payment-required",
	SUBMITTED: "payment-submitted",
	COMPLETED: "payment-completed",
	FAILED: "payment-failed",
} as const;
export type X402Status = (typeof X402_STATUS)[keyof typeof X402_STATUS];

/** Settlement-timing modes advertised in card terms / stated in the quote. */
export const X402_MODE = {
	SETTLE_FIRST: "settle-first",
	SETTLE_AFTER_DELIVERY: "settle-after-delivery",
} as const;
export type X402Mode = (typeof X402_MODE)[keyof typeof X402_MODE];

export interface X402Resource {
	url?: string;
	description?: string;
	mimeType?: string;
	[k: string]: unknown;
}

/** The token's EIP-712 domain fields (required for the `exact`/EIP-3009 path). */
export interface X402TokenExtra {
	name: string;
	version: string;
	[k: string]: unknown;
}

/** One entry of `PaymentRequired.accepts[]` — an x402 `PaymentRequirements`. */
export interface PaymentRequirements {
	scheme: string;
	network: string; // CAIP-2, e.g. "eip155:8453"
	amount?: string; // atomic token units (x402 V2); reads fall back to `maxAmountRequired`
	/** x402 V1 spelling of `amount`; accepted on read for cross-version interop. */
	maxAmountRequired?: string;
	asset: string; // token contract address (0x)
	payTo: string; // payee wallet (0x)
	maxTimeoutSeconds: number;
	extra: X402TokenExtra;
	[k: string]: unknown;
}

/** Payload of `rine.v1.x402_payment_required` (the 402 quote). */
export interface PaymentRequired {
	x402Version: number;
	error?: string;
	resource?: X402Resource;
	accepts: PaymentRequirements[];
	extensions?: Record<string, unknown>;
	[k: string]: unknown;
}

/** EIP-3009 `transferWithAuthorization` fields (all decimal/hex strings). */
export interface Eip3009Authorization {
	from: string;
	to: string;
	value: string;
	validAfter: string;
	validBefore: string;
	nonce: string; // 0x + 32 bytes
}

export interface Eip3009Signed {
	signature: string; // 0x + 65 bytes (r‖s‖v)
	authorization: Eip3009Authorization;
}

/** Payload of `rine.v1.x402_payment` (the signed authorization). */
export interface PaymentPayload {
	x402Version: number;
	resource?: X402Resource;
	accepted: PaymentRequirements;
	payload: Eip3009Signed;
	extensions?: Record<string, unknown>;
	[k: string]: unknown;
}

/** Payload of `rine.v1.x402_receipt` (the settlement result). */
export interface SettlementResponse {
	success: boolean;
	transaction: string;
	network: string;
	payer: string;
	errorReason?: string;
	amount?: string;
	extensions?: Record<string, unknown>;
	[k: string]: unknown;
}

/** The optional cleartext status marker. Never carries economic detail. */
export interface X402Marker {
	status: X402Status;
	rail: string;
}

/**
 * Client-side spend policy, enforced at signing. All cap fields are
 * decimal major-unit strings (e.g. "10.00") interpreted in canonical 6-decimal
 * stablecoin units; `allowedAssets` entries are symbols (e.g. "EURC") or 0x
 * contract addresses; `allowedNetworks` are CAIP-2 ids. Absence of a policy is
 * a hard deny (deny-by-default).
 */
export interface PaymentPolicy {
	perTxCap: string;
	dailyCap: string;
	allowedAssets: string[];
	allowedNetworks: string[];
	autoPayThreshold: string;
}
