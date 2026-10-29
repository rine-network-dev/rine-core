/**
 * Moving one agent's own leaf in one group to the key it holds now.
 *
 * A key rotation mints a new generation of the agent's keys and publishes it,
 * but the leaf the agent occupies in each group still carries the key it joined
 * with. A native self-update moves that leaf: the new leaf is signed by the new
 * key while the commit's framing is signed by the key the handle holds now, so
 * the move is authorised by the seat it replaces.
 *
 * Every group-level problem is an outcome, never a throw: the caller gets a
 * {@link SeatUpdate} it can report. The five outcomes are
 *
 *   - `updated` — the leaf now carries the current key, at a new epoch;
 *   - `current` — the leaf already carried it, so nothing was built;
 *   - `deferred` — the move is still in flight (`awaiting_ack`), was rolled back
 *     (`rolled_back`), lost an epoch race (`epoch_race`), or the group could not
 *     be reached (`unreachable`);
 *   - `failed` — the agent was evicted (`evicted`), the leaf carries a key this
 *     device cannot sign for (`seat_unhealable`), or the core refused the build
 *     (`refused`).
 *
 * The commit is saved to disk BEFORE it is posted. A pending commit can be
 * cleared and an applied one cannot, so the save-before-post order loses
 * nothing: a post that never reached the server leaves a pending commit a later
 * sync settles, and a post the server accepted leaves a commit that is already
 * on disk to apply.
 */
import { equalBytes } from "./crypto/bytes.js";
import { loadAgentKeys } from "./crypto/keys.js";
import { noteMlsStateChanged } from "./crypto/mls-state.js";
import { RineApiError } from "./errors.js";
import { type PeerActor, openPeerMlsGroup } from "./mls-allowed.js";
import { admitGroupPeers } from "./mls-allowed-tree.js";
import { admitRefusedPeers } from "./mls-commit-admission.js";
import {
	isEpochConflict,
	postMlsCommitBundle,
	retryOnEpochConflict,
} from "./mls-commit.js";
import { whenCommitPending } from "./mls-commit-pending.js";
import { drainEscrow } from "./mls-escrow-drain.js";
import { epochEscrowStored } from "./mls-escrow-stored.js";
import { PendingCommitOutcome, dropPendingCommit } from "./mls-pending-commit.js";
import { syncMlsGroup } from "./mls-ops-sync.js";
import { isMlsRotatedLeaf } from "./mls-rotated-leaf.js";
import { buildFailure, detailOf } from "./mls-seat-failure.js";
import {
	SeatDeferReason,
	SeatFailReason,
	SeatUpdateStatus,
	type SeatUpdate,
} from "./mls-seat-update.js";
import { registerGroupReseat } from "./mls-settle-guard.js";

/**
 * Move this agent's own leaf in one group to the key it holds now, and report
 * what happened.
 *
 * The keys are read once, at the start: a rotation that lands mid-call must not
 * make the leaf and the seed disagree. The group is synced first, because a
 * pending self-update from an earlier call has to be settled before another can
 * be built, and because the leaf can only be compared against the current key
 * once the group is at its newest epoch.
 *
 * At most two attempts are made. The only retry is a lost epoch CAS: a peer's
 * commit landed first, so the group is synced again and the commit rebuilt once
 * against the new epoch. A second loss is reported, not retried — an unbounded
 * retry against an advancing epoch is a self-DoS.
 */
export async function selfUpdateGroup(
	actor: PeerActor,
	groupId: string,
): Promise<SeatUpdate> {
	const { configDir, agentId, client, extraHeaders } = actor;
	const keys = loadAgentKeys(configDir, agentId);
	const seat = (
		status: SeatUpdate["status"],
		extra: Omit<SeatUpdate, "group_id" | "status"> = {},
	): SeatUpdate => ({ group_id: groupId, status, ...extra });

	const attempt = async (): Promise<SeatUpdate> => {
		let synced;
		try {
			synced = await syncMlsGroup(configDir, agentId, groupId, client, extraHeaders);
		} catch (err) {
			const detail = detailOf(err);
			if (isMlsRotatedLeaf(err)) {
				return seat(SeatUpdateStatus.Failed, {
					reason: SeatFailReason.SeatUnhealable,
					detail,
				});
			}
			return seat(SeatUpdateStatus.Deferred, {
				reason: SeatDeferReason.Unreachable,
				detail,
			});
		}
		if (synced.evicted) {
			return seat(SeatUpdateStatus.Failed, { reason: SeatFailReason.Evicted });
		}
		if (synced.pendingCommit?.outcome === PendingCommitOutcome.Held) {
			return seat(SeatUpdateStatus.Deferred, {
				reason: SeatDeferReason.AwaitingAck,
				epoch: synced.pendingCommit.epoch,
			});
		}
		if (synced.pendingCommit?.outcome === PendingCommitOutcome.Lost) {
			return seat(SeatUpdateStatus.Deferred, {
				reason: SeatDeferReason.EpochRace,
			});
		}
		if (synced.pendingCommit?.outcome === PendingCommitOutcome.RolledBack) {
			return seat(SeatUpdateStatus.Deferred, {
				reason: SeatDeferReason.RolledBack,
			});
		}
		if (synced.pendingCommit?.outcome === PendingCommitOutcome.NotPosted) {
			return seat(SeatUpdateStatus.Deferred, {
				reason: SeatDeferReason.Unreachable,
			});
		}

		let group;
		try {
			await admitGroupPeers(actor, groupId);
			group = openPeerMlsGroup(actor, groupId);
		} catch (err) {
			return seat(SeatUpdateStatus.Deferred, {
				reason: SeatDeferReason.Unreachable,
				detail: detailOf(err),
			});
		}
		if (equalBytes(group.ownLeafSignatureKey(), keys.mls.publicKey)) {
			return seat(SeatUpdateStatus.Current, { epoch: group.epoch() });
		}

		let bundle;
		try {
			bundle = await whenCommitPending(groupId, () =>
				admitRefusedPeers(actor, group, () =>
					group.commitUpdate(keys.mls.privateKey),
				),
			);
		} catch (err) {
			const { status, ...failure } = buildFailure(err, group);
			return seat(status, failure);
		}

		// Write-ahead: the pending commit is on disk before anything leaves the host.
		group.save();

		let accepted;
		try {
			accepted = await postMlsCommitBundle(
				{ configDir, agentId, client },
				groupId,
				bundle,
				[],
				extraHeaders,
				[],
			);
		} catch (err) {
			if (isEpochConflict(err)) {
				dropPendingCommit(actor, groupId, group);
				throw err;
			}
			const detail = detailOf(err);
			// A 4xx is the server answering and refusing: the commit will never be
			// confirmed, so the pending state is dropped. Anything else (a transport
			// error, a timeout, a 5xx) may have been accepted, so the pending commit
			// stays saved for a later sync to settle.
			if (err instanceof RineApiError && err.status >= 400 && err.status < 500) {
				dropPendingCommit(actor, groupId, group);
			}
			return seat(SeatUpdateStatus.Deferred, {
				reason: SeatDeferReason.Unreachable,
				detail,
			});
		}

		if (accepted.confirmed) {
			group.applyPendingCommit();
			await drainEscrow(actor, groupId, group);
			noteMlsStateChanged(configDir, agentId, groupId);
			return seat(SeatUpdateStatus.Updated, {
				epoch: group.epoch(),
				escrow_pending: !epochEscrowStored(actor, groupId, group.epoch()),
			});
		}
		group.save();
		return seat(SeatUpdateStatus.Deferred, {
			reason: SeatDeferReason.AwaitingAck,
			epoch: accepted.epoch,
		});
	};

	try {
		return await retryOnEpochConflict(attempt);
	} catch (err) {
		if (!isEpochConflict(err)) throw err;
	}
	return seat(SeatUpdateStatus.Deferred, { reason: SeatDeferReason.EpochRace });
}

// A settlement reaches the self-update through the slot in mls-settle-guard.js.
registerGroupReseat(selfUpdateGroup);
