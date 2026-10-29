/**
 * The send-side escrow helpers: what an `mls-v1` group send needs
 * before it can be posted, and the one retry the server's 409 asks for.
 *
 * An `mls-v1` send body carries `escrow_fp`, the base64url fork fingerprint of
 * the sender's CURRENT epoch. The group reports its live fingerprint
 * (`epochFingerprint`); the drain remembers the newest drained epoch and fp
 * (`readHead`), and this module sends the live fingerprint when the head names
 * it. The server answers 409 `escrow_missing` until the sender's escrow for
 * (group, epoch, fp) is uploaded, which is why a send that meets one uploads
 * what is pending and posts exactly once more.
 */
import { EscrowGapReason } from "@rine-network/mls";
import { equalBytes } from "./crypto/bytes.js";
import { toBase64Url } from "./crypto/keys.js";
import { EscrowGapError, RineApiError } from "./errors.js";
import { type PeerActor, openPeerMlsGroup } from "./mls-allowed.js";
import { drainEscrow } from "./mls-escrow-drain.js";
import { type EscrowHead, readHead } from "./mls-escrow-head.js";
import { reclaimOnceForGap } from "./mls-escrow-leaves.js";
import { readGap } from "./mls-escrow-markers.js";
import { uploadPendingEscrow } from "./mls-escrow-upload.js";

/** The server's error code for a send whose escrow for (group, epoch, fp) is not uploaded. */
export const ESCROW_MISSING_CODE = "escrow_missing";

/**
 * The sender holds no uploaded-or-uploadable escrow for its current epoch: the
 * send is refused, never sent without one.
 *
 * A deferral (no verified branch escrow key) is the `cause`, so a caller can
 * tell "the branch key could not be verified" from "the drain's head is stale"
 * without parsing the message.
 */
export class EscrowUnavailableError extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "EscrowUnavailableError";
	}
}

/**
 * Drain this group's escrow (upload anything pending) and return the
 * `escrow_fp` for the sender's current epoch, base64url.
 *
 * The head decides, as on the Python twin: the drained head names the live
 * fork of the current epoch exactly when that fork's escrow was sealed, and the
 * server's 409 arbitrates whether it was uploaded. A deferral (no verified
 * escrow key) or a failed upload therefore does not refuse a send whose head is
 * current. When the head is not current, a gap marker of the live fork (or a
 * fork-less one) for the epoch throws {@link EscrowGapError} (a `too_many_leaves`
 * gap after one orphan reclamation, see {@link reclaimOnceForGap}); a marker of
 * another fork never does. No marker throws {@link EscrowUnavailableError}
 * (cause = the deferral when there was one).
 *
 * `openPeerMlsGroup` throws the no-state error when this agent holds no local
 * state for the group; that propagates unchanged, because the caller's recovery
 * matches on it.
 */
export async function prepareEscrowForSend(
	actor: PeerActor,
	groupId: string,
): Promise<string> {
	try {
		return await currentEscrowFp(actor, groupId);
	} catch (err) {
		if (
			!(err instanceof EscrowGapError) ||
			err.reason !== EscrowGapReason.TooManyLeaves ||
			!(await reclaimOnceForGap(actor, groupId, err.epoch))
		) {
			throw err;
		}
		return await currentEscrowFp(actor, groupId);
	}
}

/** Where the drain's head stands against the live epoch: absent, on another epoch, or on another fork of this one. */
function headDescription(head: EscrowHead | undefined, epoch: number): string {
	if (!head) return "absent";
	return head.epoch === epoch
		? `epoch ${head.epoch} on another fork`
		: `epoch ${head.epoch}`;
}

async function currentEscrowFp(
	actor: PeerActor,
	groupId: string,
): Promise<string> {
	const group = openPeerMlsGroup(actor, groupId);
	const outcome = await drainEscrow(actor, groupId, group);
	const epoch = group.epoch();
	const fp = group.epochFingerprint();
	const head = readHead(actor.configDir, actor.agentId, groupId);
	if (head && head.epoch === epoch && equalBytes(head.fp, fp)) {
		return toBase64Url(fp);
	}
	const reason = readGap(actor.configDir, actor.agentId, groupId, epoch, fp);
	if (reason !== undefined) throw new EscrowGapError(groupId, epoch, reason);
	throw new EscrowUnavailableError(
		`no escrow for the group's current epoch ${epoch}: the drain's head is ${headDescription(head, epoch)}${
			outcome.deferred ? " and the branch escrow key could not be verified" : ""
		}`,
		outcome.deferred ? { cause: outcome.deferred } : undefined,
	);
}

/** True for the server's 409 with error code `escrow_missing`. */
export function isEscrowMissing(err: unknown): boolean {
	return (
		err instanceof RineApiError &&
		err.status === 409 &&
		err.code === ESCROW_MISSING_CODE
	);
}

/**
 * Run `post(fp)`; on 409 `escrow_missing` upload what is pending and post the
 * SAME `fp` ONCE more. The ciphertext's epoch is fixed, so the fingerprint it was
 * built for is the only correct one. Any second failure, and every other error,
 * propagates unchanged: the retry exists because the server's answer names a
 * missing escrow, not because a send is worth repeating.
 */
export async function postWithEscrowRetry<T>(
	actor: PeerActor,
	groupId: string,
	fp: string,
	post: (escrowFp: string) => Promise<T>,
): Promise<T> {
	try {
		return await post(fp);
	} catch (err) {
		if (!isEscrowMissing(err)) throw err;
		await uploadPendingEscrow(actor, groupId);
		return await post(fp);
	}
}
