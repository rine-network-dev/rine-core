/**
 * x402 message build layer: assemble the three x402 rine message types for the
 * send path, attaching the optional cleartext status marker.
 *
 * The decrypted plaintext of each x402 message IS the verbatim x402 V2 object
 * (`PaymentRequired` / `PaymentPayload` / `SettlementResponse`) — this module
 * never wraps, renames, reshapes, or strips fields. A built message's `payload`
 * is handed VERBATIM to `encryptMessage` (which JSON-serialises it), so a
 * round-trip through encrypt → decrypt → `parseX402Payload` deep-equals the
 * original object. The only rine-added plane is the coarse, economically empty
 * `metadata["rine.x402"]` marker.
 *
 * Re-exports the message-type constants, parse layer, and marker helpers so the
 * whole message-flow surface is reachable from `x402/messages.js`.
 */

import { type X402MarkerMetadata, x402MarkerMetadata } from "./marker.js";
import {
	type X402MessageType,
	X402_CONTENT_TYPE,
	X402_MESSAGE_TYPE,
	X402_PAYLOAD_SCHEMA,
} from "./message-types.js";
import type { X402Payload } from "./parse.js";
import {
	type PaymentPayload,
	type PaymentRequired,
	type SettlementResponse,
	type X402Status,
	X402_STATUS,
} from "./types.js";

export * from "./message-types.js";
export * from "./parse.js";
export * from "./marker.js";

/**
 * A built x402 message, ready for the send layer. `payload` is the VERBATIM
 * x402 object to hand to `encryptMessage`; `metadata` (when present) carries
 * ONLY the coarse `rine.x402` marker — a surface merges it into any other
 * cleartext metadata it sends.
 */
export interface BuiltX402Message {
	type: X402MessageType;
	content_type: typeof X402_CONTENT_TYPE;
	payload_schema: string;
	payload: X402Payload;
	metadata?: X402MarkerMetadata;
}

export interface BuildX402Options {
	/**
	 * Whether to emit the cleartext `metadata["rine.x402"]` status marker.
	 * Sender-controlled. Defaults to `true` — the marker carries only
	 * coarse lifecycle state (never economic detail), so thread UIs and inbox
	 * filters can key off it; pass `false` for a fully-sealed message.
	 */
	emitMarker?: boolean;
}

function assemble(
	type: X402MessageType,
	payload: X402Payload,
	status: X402Status,
	opts?: BuildX402Options,
): BuiltX402Message {
	const message: BuiltX402Message = {
		type,
		content_type: X402_CONTENT_TYPE,
		payload_schema: X402_PAYLOAD_SCHEMA[type],
		payload,
	};
	if (opts?.emitMarker ?? true) message.metadata = x402MarkerMetadata(status);
	return message;
}

/** Build a `rine.v1.x402_payment_required` message (marker `payment-required`). */
export function buildPaymentRequiredMessage(
	pr: PaymentRequired,
	opts?: BuildX402Options,
): BuiltX402Message {
	return assemble(
		X402_MESSAGE_TYPE.PAYMENT_REQUIRED,
		pr,
		X402_STATUS.REQUIRED,
		opts,
	);
}

/** Build a `rine.v1.x402_payment` message (marker `payment-submitted`). */
export function buildPaymentMessage(
	pp: PaymentPayload,
	opts?: BuildX402Options,
): BuiltX402Message {
	return assemble(X402_MESSAGE_TYPE.PAYMENT, pp, X402_STATUS.SUBMITTED, opts);
}

/**
 * Build a `rine.v1.x402_receipt` message. The marker status is derived from the
 * settlement result: `payment-completed` on success, `payment-failed` otherwise.
 */
export function buildReceiptMessage(
	sr: SettlementResponse,
	opts?: BuildX402Options,
): BuiltX402Message {
	const status = sr.success ? X402_STATUS.COMPLETED : X402_STATUS.FAILED;
	return assemble(X402_MESSAGE_TYPE.RECEIPT, sr, status, opts);
}
