/**
 * x402 cleartext status marker: the ONLY rine-added, server-visible
 * plane on an x402 message. It carries coarse lifecycle state and nothing else —
 * never amounts, assets, addresses, tx hashes, or any economic detail (those
 * live only in the encrypted payload). Sender-controlled and opt-in.
 */

import {
	type X402Marker,
	type X402Status,
	X402_METADATA_KEY,
	X402_RAIL,
	X402_STATUS,
} from "./types.js";

/** The cleartext-metadata block carrying only the coarse marker. */
export type X402MarkerMetadata = { [X402_METADATA_KEY]: X402Marker };

/** The coarse marker object for a lifecycle status. Never carries economics. */
export function x402Marker(status: X402Status): X402Marker {
	return { status, rail: X402_RAIL };
}

/** The cleartext metadata block wrapping the coarse marker. */
export function x402MarkerMetadata(status: X402Status): X402MarkerMetadata {
	return { [X402_METADATA_KEY]: x402Marker(status) };
}

const X402_STATUS_VALUES = new Set<string>(Object.values(X402_STATUS));

/**
 * Read the coarse status marker out of a message's cleartext metadata.
 * Fail-closed: returns `null` unless `metadata["rine.x402"]` is present with a
 * `status` in the four-value enum. Extra keys are ignored (never surfaced as
 * economic detail); only `{ status, rail }` is returned.
 */
export function readX402Marker(
	metadata?: Record<string, unknown> | null,
): X402Marker | null {
	if (metadata == null || typeof metadata !== "object") return null;
	const raw = (metadata as Record<string, unknown>)[X402_METADATA_KEY];
	if (raw == null || typeof raw !== "object") return null;
	const { status, rail } = raw as Record<string, unknown>;
	if (typeof status !== "string" || !X402_STATUS_VALUES.has(status))
		return null;
	return {
		status: status as X402Status,
		rail: typeof rail === "string" ? rail : X402_RAIL,
	};
}
