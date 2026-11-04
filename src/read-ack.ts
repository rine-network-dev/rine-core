/**
 * When a by-id read may mark its row delivered.
 *
 * The server marks the acting agent's delivery row at fetch, before any key
 * has touched the bytes, and it has no route that un-marks one. So every read
 * path fetches with the peek header and decides here, once it has tried to open
 * the row, whether consuming it is safe. A row that may still heal (no key
 * material yet, a sender key that has not arrived, an unclassified throw) stays
 * `new`, so a key fix or a resync can still recover it.
 *
 * The same predicate is mirrored once in Python (`rine/_read_ack.py`) and is
 * what `rine_inbox`'s listing filter asks of each page.
 */
import { markDeliveredAs } from "./ack-batcher.js";
import type { MessageRead } from "./api-types.js";
import { ENCRYPTION_VERSION_HYBRID_V2 } from "./crypto/hybrid.js";
import { isAuthenticityFailure } from "./crypto/message.js";
import type { VerificationStatus } from "./crypto/message.js";
import {
	ENCRYPTION_VERSIONS,
	isGroupEncryptionVersion,
} from "./encryption-versions.js";
import type { HttpClient } from "./http.js";

/**
 * The two facts about a row this module reads: how it is sealed, and the verdict
 * a decrypt attempt may have left on it. Structural, so a surface's own decrypted
 * row shape passes without a cast.
 */
export type AckRow = Pick<MessageRead, "encryption_version"> & {
	verification_status?: VerificationStatus;
};

/** Whether a row's envelope is a 1:1 hybrid HPKE seal. */
export function isDirectEnvelope(msg: AckRow): boolean {
	return msg.encryption_version === ENCRYPTION_VERSION_HYBRID_V2;
}

/** Whether a row's envelope is a group seal, either encryption. */
export function isGroupEnvelope(msg: AckRow): boolean {
	return isGroupEncryptionVersion(msg.encryption_version);
}

/**
 * Whether this row was refused because its author could not be trusted: the one
 * refusal that never heals, because a signature that does not check out is a
 * permanent property of the bytes.
 *
 * Screened through {@link isAuthenticityFailure} rather than compared against a
 * member, so `unverifiable` (a transient key-lookup outcome, not a verdict) is
 * not swept in with it.
 */
export function rowAuthenticityFailure(row: AckRow): boolean {
	const status = row.verification_status;
	return status !== undefined && isAuthenticityFailure(status);
}

/**
 * Whether this row was never ciphertext in the first place, so there is nothing
 * to open and nothing a later look could change. The live instance is the
 * `encryption_version: "none"` row `_create_a2a_message` writes for an agent
 * whose A2A card sets `a2a_accept_cleartext`.
 *
 * Asks for `none` and nothing else. A version this client does not know is
 * ciphertext it cannot open yet, not cleartext, so that row stays `new` and a
 * later client that knows the version can open it. The wider `not-ciphertext`
 * verdict of the decrypt path also covers a missing authenticated sender and
 * an empty payload, neither of which a listing can produce; widening a
 * permanent-class predicate past the shapes that occur is how an ack starts
 * consuming rows on a guess.
 */
export function rowNeverCiphertext(row: AckRow): boolean {
	return row.encryption_version === ENCRYPTION_VERSIONS.NONE;
}

/**
 * Whether reading this row is finished: it opened, it was never ciphertext, or
 * its author was refused. Every other row (no keys, a sender key not yet
 * arrived, an unclassified throw) may still heal and stays unsettled.
 *
 * `opened` is the caller's POSITIVE fact that a body came back. It is never
 * derived from the absence of a decrypt error, because several non-opened
 * outcomes carry no error field at all.
 */
export function isSettledRow(row: AckRow, opened: boolean): boolean {
	return opened || rowNeverCiphertext(row) || rowAuthenticityFailure(row);
}

/** The two facts that gate a mark: the row settled, and the caller did not ask to peek. */
export interface AckDecision {
	readonly settled: boolean;
	readonly peek?: boolean;
}

/**
 * Mark read rows delivered when they are settled and the caller did not ask to
 * peek. Never throws: a missing mark is recoverable (the row stays `new`) and a
 * lost plaintext is not, so the failure comes back as a value for the caller to
 * report through its own warning channel.
 */
export async function ackAfterRead(
	client: HttpClient,
	agentId: string,
	messageIds: readonly string[],
	{ settled, peek }: AckDecision,
): Promise<Error | null> {
	if (!settled || peek || messageIds.length === 0) return null;
	try {
		await markDeliveredAs(client, agentId, messageIds);
		return null;
	} catch (err) {
		return err instanceof Error ? err : new Error(String(err));
	}
}
