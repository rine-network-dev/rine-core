/**
 * What a seat update reports when its commit could not be built, and the one
 * way every sweep step spells an error as prose.
 */
import type { MlsGroup } from "./crypto/mls.js";
import {
	MLS_ERR_COMMIT_PENDING,
	MLS_ERR_SIGNER_LEAF_MISMATCH,
	mlsErrorCode,
} from "./crypto/mls-errors.js";
import {
	SeatDeferReason,
	SeatFailReason,
	type SeatUpdate,
	SeatUpdateStatus,
} from "./mls-seat-update.js";

/** The message of a failure, for a report that carries prose rather than a code. */
export function detailOf(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

/**
 * The seat a failed commit build reports, by what failed.
 *
 * Only a failure no retry can change is final. A commit another process of this
 * agent still has pending waits for that commit to settle, and a build that
 * died on the network (admitting a peer reads it) may succeed on the next beat:
 * both stay deferred, so the rotation marker waits and the sweep tries again. The
 * core refusing the build, or a leaf this device cannot sign for, will answer
 * the same way next time.
 */
export function buildFailure(
	err: unknown,
	group: MlsGroup,
): Omit<SeatUpdate, "group_id"> {
	const detail = detailOf(err);
	switch (mlsErrorCode(err)) {
		case MLS_ERR_COMMIT_PENDING:
			return {
				status: SeatUpdateStatus.Deferred,
				reason: SeatDeferReason.AwaitingAck,
				epoch: group.pendingCommitEpoch() ?? group.epoch() + 1,
			};
		case MLS_ERR_SIGNER_LEAF_MISMATCH:
			return {
				status: SeatUpdateStatus.Failed,
				reason: SeatFailReason.SeatUnhealable,
				detail,
			};
		case null:
			return {
				status: SeatUpdateStatus.Deferred,
				reason: SeatDeferReason.Unreachable,
				detail,
			};
		default:
			return { status: SeatUpdateStatus.Failed, reason: SeatFailReason.Refused, detail };
	}
}
