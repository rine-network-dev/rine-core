/** Typed error codes for x402 policy enforcement and payload construction. */
export const X402_ERROR = {
	NO_POLICY: "no-policy",
	SCHEME_UNSUPPORTED: "scheme-unsupported",
	NETWORK_NOT_ALLOWED: "network-not-allowed",
	ASSET_NOT_ALLOWED: "asset-not-allowed",
	PER_TX_CAP_EXCEEDED: "per-tx-cap-exceeded",
	DAILY_CAP_EXCEEDED: "daily-cap-exceeded",
	NO_ACCEPTABLE_REQUIREMENT: "no-acceptable-requirement",
	INVALID_REQUIREMENT: "invalid-requirement",
	INVALID_NETWORK: "invalid-network",
	INVALID_POLICY: "invalid-policy",
	INVALID_AMOUNT: "invalid-amount",
	NOT_X402_TYPE: "not-x402-type",
	MALFORMED_PAYLOAD: "malformed-payload",
	WALLET_BUSY: "wallet-busy",
	ALREADY_PAID: "already-paid",
	// The payment does not match any payee-issued quote (scheme/network/asset/
	// payTo/amount) — the payee refuses to settle payer-authored terms.
	REQUIREMENT_MISMATCH: "requirement-mismatch",
	// No decryptable payee-issued quote (and no explicit expected terms) is
	// available to reconcile the payment against — fail closed.
	NO_QUOTE: "no-quote",
	// The asset's decimals cannot be resolved from the registry (and none were
	// explicitly declared) — refuse to price it rather than assume 6.
	UNKNOWN_ASSET_DECIMALS: "unknown-asset-decimals",
	// The message's envelope was not signed by the agent the server authenticated
	// as its sender (or its signature does not check out at all) — the body is not
	// the counterparty's word, so no quote is paid and no payment is settled.
	INAUTHENTIC_SENDER: "inauthentic-sender",
	// The sender's signing key could not be read, so the signature was never
	// checked — no verdict either way. Nothing is paid or settled; retry once the
	// key lookup works.
	SENDER_UNVERIFIABLE: "sender-unverifiable",
} as const;

export type X402ErrorCode = (typeof X402_ERROR)[keyof typeof X402_ERROR];

/** A structured, typed error (never a bare string) for all x402 refusals. */
export class X402Error extends Error {
	constructor(
		public readonly code: X402ErrorCode,
		message: string,
		public readonly details?: Record<string, unknown>,
	) {
		super(message);
		this.name = "X402Error";
	}
}
