/** How an epoch's escrow copies came out against one message: the gap that withholds it, or none. */
import { equalBytes } from "@noble/curves/utils.js";
import type { EpochCopies, GoodCopy } from "./escrow-book.js";
import {
	type ReadGap,
	ReadGapReason,
	escrowForged,
	escrowInvalid,
	forkUnmatched,
	keysUnavailable,
	memberRejected,
	ratchetGap,
} from "./gaps.js";
import type { Row } from "./rows.js";

/** What one copy opened the message to. */
export interface Opened {
	readonly envelope: Uint8Array;
	readonly senderIndex: number;
	readonly generation: number;
	readonly signerPublicKey: Uint8Array;
	readonly copy: GoodCopy;
}

/**
 * The result of trying every good copy of an epoch against one message. A copy that panicked
 * inside the native reader is in none of these lists, so it cannot name an honest uploader.
 */
export class Attempt {
	opened: Opened | null = null;
	/** Copies the framing signature check refused. */
	readonly rejected: GoodCopy[] = [];
	tooFar = false;
	/** Copies the native reader called invalid, each already naming its uploader. */
	readonly invalid: ReadGap[] = [];
	/** Copies that failed for any other reason. */
	readonly mismatched: GoodCopy[] = [];
}

/** Why no copy of the epoch opened at all: a key outage first, then a named uploader, then nobody. */
export function unopenedGap(epoch: number, copies: EpochCopies): ReadGap {
	if (copies.unavailable) return keysUnavailable(epoch);
	for (const reason of [
		ReadGapReason.EscrowInvalid,
		ReadGapReason.Unreadable,
	]) {
		const gap = copies.bad.find((bad) => bad.reason === reason);
		if (gap !== undefined) return gap;
	}
	return escrowForged(epoch);
}

/**
 * Why no copy opened the message. A copy whose uploader keys were out of reach may have been the
 * one that opens it or names its fork, so a key outage outranks every verdict drawn from the
 * copies that were readable.
 */
export function failureGap(
	epoch: number,
	row: Row,
	attempt: Attempt,
	copies: EpochCopies,
): ReadGap {
	if (copies.unavailable) return keysUnavailable(epoch);
	if (attempt.rejected.length > 0) return memberRejected(epoch);
	if (attempt.tooFar) return ratchetGap(row.sender.agentId, null);
	return attempt.invalid[0] ?? forkUnmatched(epoch);
}

/**
 * The gap that stops this message being shown, or null when it may be verified.
 *
 * A rejecting copy of the same fork as the one that opened proves the two escrows disagree about
 * the message: one of their uploaders lied and nothing says which, so the message is withheld. A
 * rejecting copy of another fork proves nothing and is ignored. With a single copy of the fork
 * the reader has no one to disagree with it, so that residual stands.
 */
export function resolve(
	epoch: number,
	row: Row,
	attempt: Attempt,
	copies: EpochCopies,
): ReadGap | null {
	if (attempt.opened === null) return failureGap(epoch, row, attempt, copies);
	const { fp } = attempt.opened.copy.copy;
	return attempt.rejected.some((rejected) => equalBytes(rejected.copy.fp, fp))
		? memberRejected(epoch)
		: null;
}

/**
 * Copies of the fork that opened the message but would not open it were not escrowed honestly:
 * their signed uploaders are named. A copy of another fork is not a failure.
 */
export function siblingFailures(
	epoch: number,
	fp: Uint8Array,
	attempt: Attempt,
): ReadGap[] {
	return [
		...attempt.mismatched
			.filter((copy) => equalBytes(copy.copy.fp, fp))
			.map((copy) => escrowInvalid(epoch, copy.copy.uploader)),
		...attempt.invalid,
	];
}
