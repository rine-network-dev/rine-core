/**
 * The refusal a member gets when it tries to build a commit while its own key
 * update is still awaiting a member's acknowledgement.
 *
 * The native core refuses every other commit on a handle that holds a pending
 * one, with a sentence about group handles. This module turns that one refusal
 * into a typed error that says what is happening and when it ends, so a caller
 * is told to retry rather than shown an engine message.
 */
import { MLS_ERR_COMMIT_PENDING, mlsErrorCode } from "./crypto/mls-errors.js";

/** The sentence every surface shows for a commit refused because a key update is pending. */
export function commitPendingMessage(groupId: string): string {
	return (
		`This agent's key update in group ${groupId} is awaiting a member's ` +
		"acknowledgement; retry after it settles, at most 15 minutes."
	);
}

/** A commit refused because this agent's own key update in the group is still pending. */
export class MlsCommitPendingError extends Error {
	readonly code = MLS_ERR_COMMIT_PENDING;

	constructor(public readonly groupId: string) {
		super(commitPendingMessage(groupId));
		this.name = "MlsCommitPendingError";
	}
}

/**
 * Run a commit builder, and say a pending key update by its own name when the
 * core refuses the commit because of it. Any other failure passes through.
 */
export async function whenCommitPending<T>(
	groupId: string,
	build: () => T | Promise<T>,
): Promise<T> {
	try {
		return await build();
	} catch (err) {
		if (mlsErrorCode(err) === MLS_ERR_COMMIT_PENDING) {
			throw new MlsCommitPendingError(groupId);
		}
		throw err;
	}
}
