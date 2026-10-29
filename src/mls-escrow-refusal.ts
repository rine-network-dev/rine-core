/**
 * What becomes of one pending escrow file the server refused: a stored slot
 * deletes the file and clears the fork's gap marker; a terminal code gives it up;
 * any other refusal keeps it on the retry schedule of `mls-escrow-retry.ts` and
 * the sixteenth gives it up. Giving up files a gap marker naming the loss, then
 * deletes the file (see {@link giveUpFile}).
 *
 * A refusal that names a revoked principal is not about the file: the loss it
 * means is read from {@link revokedLoss}, so a revoked branch or agent is filed
 * as such rather than as an ordinary refusal.
 */
import type { RineApiError } from "./errors.js";
import type { PeerActor } from "./mls-allowed.js";
import {
	EscrowAnswer,
	classifyRefusal,
} from "./mls-escrow-answer.js";
import { EscrowLoss, clearGap, giveUpPending } from "./mls-escrow-gap.js";
import { forgetEscrowKey } from "./mls-escrow-key.js";
import { type PendingEscrow, deletePending, pendingPath } from "./mls-escrow-pending.js";
import type { DrainOutcome } from "./mls-escrow-report.js";
import { revokedLoss } from "./mls-escrow-revoked.js";
import { isExhausted, noteFailure } from "./mls-escrow-retry.js";

/** The last answer a sidecar records: the status, plus the code when the server sent one. */
function lastAnswer(error: RineApiError): string {
	return error.code === undefined ? String(error.status) : `${error.status} ${error.code}`;
}

/**
 * The server holds this pending file: delete it and clear the fork's gap marker.
 * A marker left by an earlier give-up at the same slot is stale once the server
 * has the escrow, and the marker of another fork at the same epoch stays.
 */
export function markStored(actor: PeerActor, pending: PendingEscrow): void {
	deletePending(actor.configDir, actor.agentId, pending);
	clearGap(actor.configDir, actor.agentId, pending.groupId, pending.epoch, pending.fp);
}

/**
 * Give up one pending file: file the gap marker naming the loss, then delete the
 * file. A marker that cannot be written leaves the file for the next pass and
 * reports the failure instead.
 */
export function giveUpFile(
	actor: PeerActor,
	pending: PendingEscrow,
	loss: EscrowLoss,
	outcome: DrainOutcome,
): void {
	try {
		outcome.gaps.push(giveUpPending(actor.configDir, actor.agentId, pending, loss));
	} catch (error) {
		outcome.failures.push(error instanceof Error ? error : new Error(String(error)));
	}
}

/**
 * Settle one refused file by the answer to it and list the refusal in
 * `outcome`. Returns whether the server is available for the files that follow:
 * false for a 429 or a 5xx, which says nothing about the file.
 */
export function resolveRefusal(
	actor: PeerActor,
	pending: PendingEscrow,
	error: RineApiError,
	outcome: DrainOutcome,
	nowS: number,
): boolean {
	const answer = classifyRefusal(error);
	const revoked = revokedLoss(error);
	const path = pendingPath(actor.configDir, actor.agentId, pending);
	if (revoked === EscrowLoss.BranchRevoked) forgetEscrowKey(actor);
	if (answer === EscrowAnswer.Stored) {
		markStored(actor, pending);
		outcome.uploaded++;
		return true;
	}
	outcome.failures.push(error);
	if (answer === EscrowAnswer.Refused) {
		giveUpFile(actor, pending, revoked ?? EscrowLoss.Refused, outcome);
	} else if (answer === EscrowAnswer.Retry) {
		const record = noteFailure(path, lastAnswer(error), nowS);
		if (isExhausted(record)) giveUpFile(actor, pending, EscrowLoss.Refused, outcome);
	}
	return answer !== EscrowAnswer.Backoff;
}
