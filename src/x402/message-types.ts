/**
 * The three first-party x402 rine message types and their
 * static descriptors. Kept in one small module so the build, parse, and
 * thread-state layers all key off the same typed constants — never string
 * literals scattered across call sites.
 */

/** The three first-party x402 message types. */
export const X402_MESSAGE_TYPE = {
	PAYMENT_REQUIRED: "rine.v1.x402_payment_required",
	PAYMENT: "rine.v1.x402_payment",
	RECEIPT: "rine.v1.x402_receipt",
} as const;
export type X402MessageType =
	(typeof X402_MESSAGE_TYPE)[keyof typeof X402_MESSAGE_TYPE];

/** `payload_schema` URI per type (advisory typing of the encrypted body). */
export const X402_PAYLOAD_SCHEMA = {
	[X402_MESSAGE_TYPE.PAYMENT_REQUIRED]:
		"https://rine.network/schemas/v1/x402-payment-required.json",
	[X402_MESSAGE_TYPE.PAYMENT]:
		"https://rine.network/schemas/v1/x402-payment.json",
	[X402_MESSAGE_TYPE.RECEIPT]:
		"https://rine.network/schemas/v1/x402-receipt.json",
} as const satisfies Record<X402MessageType, string>;

/** All three x402 payloads share `application/json`. */
export const X402_CONTENT_TYPE = "application/json";

/** Type guard: is `type` one of the three x402 message types? */
export function isX402MessageType(type: string): type is X402MessageType {
	return (
		type === X402_MESSAGE_TYPE.PAYMENT_REQUIRED ||
		type === X402_MESSAGE_TYPE.PAYMENT ||
		type === X402_MESSAGE_TYPE.RECEIPT
	);
}
