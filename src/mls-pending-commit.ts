/**
 * Settle a pending self-update commit against what the server says about it.
 *
 * An agent that rotated its key moves its own leaf with a native self-update:
 * `commitUpdate` leaves the commit PENDING on the handle, so the epoch, leaf and
 * signer stay where they were until the commit is applied. The server may hold
 * that commit tentatively until a member acknowledges it, so a later sync has to
 * learn where it stands and either apply it, drop it, or leave it alone.
 *
 * The handshakes read a holding handle makes names the pending epoch, and the
 * server answers where the caller's own commit at that epoch stands, under the
 * same lock as the feed. That standing is the whole decision; the settle makes
 * no read of its own:
 *
 *   - `confirmed`: a member acknowledged it. Applying it is what makes this
 *     handle sign with the key its leaf carries again.
 *   - `tentative`: still waiting. Report it held and save nothing. A held
 *     commit is why the sync stops: a peer's commit at the pending epoch or
 *     later may be built on ours, and NACKing it would roll back a commit the
 *     server is still holding for confirmation.
 *   - `rolled_back`: the server quarantined it or orphaned it. Drop it.
 *   - `superseded`: a peer's commit holds the pending epoch. Ours is dead;
 *     applying the peer's commit later is what the sync does next.
 *   - `absent`: the server never accepted it. Drop it.
 */
import { OwnCommitStanding } from "./crypto/mls-handshake-feed.js";
import { noteMlsStateChanged } from "./crypto/mls-state.js";
import type { MlsGroup } from "./crypto/mls.js";
import { type PeerActor, openPeerMlsGroup } from "./mls-allowed.js";
import { drainEscrow } from "./mls-escrow-drain.js";
import type { DrainOutcome } from "./mls-escrow-report.js";

export const PendingCommitOutcome = {
	Applied: "applied",
	Held: "held",
	/** A peer's commit took the pending epoch; ours is dead. */
	Lost: "lost",
	/** The group rolled our tentative commit back after accepting it. */
	RolledBack: "rolled_back",
	/** The server never accepted our commit. */
	NotPosted: "not_posted",
} as const;
export type PendingCommitOutcome =
	(typeof PendingCommitOutcome)[keyof typeof PendingCommitOutcome];

export interface PendingCommitSettlement {
	/** Applied: the epoch now held. Held: the epoch the commit awaits confirmation at. Every other outcome: the epoch the handle is at. */
	epoch: number;
	outcome: PendingCommitOutcome;
	/** Set with `applied`: the escrow drain that followed. The sync merges it into its own escrow report. */
	drain?: DrainOutcome;
}

/**
 * Drop the handle's pending commit and save the handle, unless another process
 * already moved the stored group past it.
 *
 * Two processes of one agent can sweep the same group. The one whose post lost
 * the epoch CAS clears and saves its handle at the old epoch; if the winner has
 * applied and saved the next epoch in the meantime, that save would put the
 * store back one epoch, and the server never serves an agent its own commit
 * again. The store is read just before the save, so the window is a few
 * microseconds rather than a whole network round trip.
 */
export function dropPendingCommit(actor: PeerActor, groupId: string, group: MlsGroup): void {
	if (openPeerMlsGroup(actor, groupId).epoch() > group.epoch()) return;
	group.clearPendingCommit();
	group.save();
}

/**
 * Settle the handle's pending self-update commit, or `null` when it holds none.
 *
 * A handle with nothing pending is the ordinary case and costs no network read
 * and no save. A holding handle needs the server's `standing`; a response that
 * carried none is malformed, and the commit stays pending: a caller that cannot
 * tell "still tentative" from an old server would drop a commit the server may
 * be holding.
 */
export async function settlePendingCommit(
	actor: PeerActor,
	groupId: string,
	group: MlsGroup,
	standing: OwnCommitStanding | undefined,
): Promise<PendingCommitSettlement | null> {
	const pending = group.pendingCommitEpoch();
	if (pending === null) return null;
	switch (standing) {
		case OwnCommitStanding.Confirmed: {
			group.applyPendingCommit();
			const drain = await drainEscrow(actor, groupId, group);
			noteMlsStateChanged(actor.configDir, actor.agentId, groupId);
			return { epoch: group.epoch(), outcome: PendingCommitOutcome.Applied, drain };
		}
		case OwnCommitStanding.Tentative:
			return { epoch: pending, outcome: PendingCommitOutcome.Held };
		case OwnCommitStanding.RolledBack:
			return dropped(actor, groupId, group, PendingCommitOutcome.RolledBack);
		case OwnCommitStanding.Superseded:
			return dropped(actor, groupId, group, PendingCommitOutcome.Lost);
		case OwnCommitStanding.Absent:
			return dropped(actor, groupId, group, PendingCommitOutcome.NotPosted);
		default:
			throw new Error(
				`The handshakes read for group ${groupId} did not say where the pending commit stands.`,
			);
	}
}

function dropped(
	actor: PeerActor,
	groupId: string,
	group: MlsGroup,
	outcome: PendingCommitOutcome,
): PendingCommitSettlement {
	dropPendingCommit(actor, groupId, group);
	return { epoch: group.epoch(), outcome };
}
