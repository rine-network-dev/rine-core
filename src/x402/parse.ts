/**
 * x402 message parsing: turn the decrypted plaintext of an x402
 * message back into its verbatim x402 V2 object. Discriminates on the message
 * `type`; validates only that the body is a JSON object with the type's
 * mandatory top-level key present — the object is otherwise returned UNCHANGED
 * (unknown fields preserved), so `parse(build(x)) ≡ x` byte-for-byte.
 */

import { X402Error, X402_ERROR } from "./errors.js";
import {
	type X402MessageType,
	X402_MESSAGE_TYPE,
	isX402MessageType,
} from "./message-types.js";
import type {
	PaymentPayload,
	PaymentRequired,
	SettlementResponse,
} from "./types.js";

/** The verbatim x402 V2 object carried as the encrypted payload. */
export type X402Payload = PaymentRequired | PaymentPayload | SettlementResponse;

/** A non-null, non-array plain object — the shape every x402 sub-object must be. */
function isObject(v: unknown): v is Record<string, unknown> {
	return v != null && typeof v === "object" && !Array.isArray(v);
}

function requireObject(
	type: X402MessageType,
	plaintext: string,
): Record<string, unknown> {
	let parsed: unknown;
	try {
		parsed = JSON.parse(plaintext);
	} catch {
		throw new X402Error(
			X402_ERROR.MALFORMED_PAYLOAD,
			`${type} payload is not valid JSON`,
		);
	}
	if (!isObject(parsed)) {
		throw new X402Error(
			X402_ERROR.MALFORMED_PAYLOAD,
			`${type} payload is not a JSON object`,
		);
	}
	return parsed;
}

/**
 * Parse the decrypted plaintext of an x402 message into its verbatim x402 V2
 * object. Throws {@link X402Error} for a non-x402 type or a structurally
 * malformed body; never reshapes a valid object.
 */
export function parseX402Payload(type: string, plaintext: string): X402Payload {
	if (!isX402MessageType(type)) {
		throw new X402Error(
			X402_ERROR.NOT_X402_TYPE,
			`not an x402 message type: ${type}`,
		);
	}
	const obj = requireObject(type, plaintext);
	if (type === X402_MESSAGE_TYPE.PAYMENT_REQUIRED) {
		if (!Array.isArray(obj.accepts)) {
			throw new X402Error(
				X402_ERROR.MALFORMED_PAYLOAD,
				"payment_required has no accepts[]",
			);
		}
		return obj as unknown as PaymentRequired;
	}
	if (type === X402_MESSAGE_TYPE.PAYMENT) {
		// A payment must carry BOTH the accepted requirement (what the payee will
		// reconcile against) AND a signed EIP-3009 authorization. Validating here
		// turns a downstream `pp.accepted.network` / `payload.authorization.from`
		// deref crash into a typed, catchable refusal.
		if (!isObject(obj.accepted)) {
			throw new X402Error(
				X402_ERROR.MALFORMED_PAYLOAD,
				"payment has no `accepted` requirement object",
			);
		}
		if (!isObject(obj.payload)) {
			throw new X402Error(
				X402_ERROR.MALFORMED_PAYLOAD,
				"payment has no signed payload",
			);
		}
		if (!isObject(obj.payload.authorization)) {
			throw new X402Error(
				X402_ERROR.MALFORMED_PAYLOAD,
				"payment payload has no `authorization` object",
			);
		}
		return obj as unknown as PaymentPayload;
	}
	if (typeof obj.success !== "boolean") {
		throw new X402Error(
			X402_ERROR.MALFORMED_PAYLOAD,
			"receipt has no success flag",
		);
	}
	return obj as unknown as SettlementResponse;
}
