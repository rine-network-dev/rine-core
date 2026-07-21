/**
 * x402 thread lifecycle (thread-aware slice): reduce the ordered
 * messages of ONE conversation thread to the current coarse x402 status.
 *
 * The three x402 message types live in a single conversation thread
 * (`quote → pay → receipt`). The thread's
 * current lifecycle state is the status of its LATEST x402 message. This reads
 * the cleartext marker when present (no decryption needed — works from the
 * server-visible plane) and falls back to the message `type` (plus the
 * decrypted receipt `success` flag, when the caller supplies it) for a
 * fully-sealed message with no marker.
 *
 * DISPLAY ONLY. The marker is sender-controlled cleartext and the receipt
 * `success` flag is opened locally, so this status is UI sugar and MUST NEVER be
 * treated as settlement proof. Real settlement is verified from the decrypted
 * receipt payload / facilitator response, not from this reducer. It fails closed:
 * a receipt whose `success` is unknown reads as failed, never completed.
 */

import { readX402Marker } from "./marker.js";
import {
	type X402MessageType,
	X402_MESSAGE_TYPE,
	isX402MessageType,
} from "./message-types.js";
import { type X402Status, X402_STATUS } from "./types.js";

/** One thread row, as much or as little as the caller can see of it. */
export interface X402ThreadEntry {
	type: string;
	/** Cleartext metadata (may carry the `rine.x402` marker). */
	metadata?: Record<string, unknown> | null;
	/**
	 * Decrypted `SettlementResponse.success`, when the caller has opened a
	 * receipt payload. Only consulted for a receipt with no marker.
	 */
	success?: boolean;
}

function derivedStatus(type: X402MessageType, success?: boolean): X402Status {
	if (type === X402_MESSAGE_TYPE.PAYMENT_REQUIRED) return X402_STATUS.REQUIRED;
	if (type === X402_MESSAGE_TYPE.PAYMENT) return X402_STATUS.SUBMITTED;
	// Receipt: a terminal message. Fail closed — ONLY an explicit `success === true`
	// reads as completed; `false` or unknown success is not-completed (a receipt with
	// success unknown must never be mistaken for a settled payment).
	return success === true ? X402_STATUS.COMPLETED : X402_STATUS.FAILED;
}

/**
 * The current coarse x402 status of a thread, or `null` if it carries no x402
 * message. `entries` MUST be ordered oldest → newest (the order
 * `GET /conversations/{id}/messages` returns).
 */
export function x402ThreadStatus(
	entries: readonly X402ThreadEntry[],
): X402Status | null {
	let status: X402Status | null = null;
	for (const entry of entries) {
		if (!isX402MessageType(entry.type)) continue;
		const marker = readX402Marker(entry.metadata);
		status = marker ? marker.status : derivedStatus(entry.type, entry.success);
	}
	return status;
}
