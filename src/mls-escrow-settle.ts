/**
 * Settle a group's escrow before its local state is discarded.
 *
 * A deferred drain leaves untaken exports only in the stored snapshot, so a
 * resync, a self-join, a Welcome re-join or a reseat that saves a new group over
 * it, and a leave that wipes it, would make the epochs the old snapshot still
 * holds unreadable after a recovery.
 *
 * The settle is local and lossless, and it makes no network call: the caller is
 * past a server-accepted commit or a Welcome that opened, and a round trip
 * there could lose the epoch it just won. With the verified escrow key cached,
 * the old state's exports are taken and sealed into pending files and the gaps
 * are filed. Without it, the old snapshot is parked in `escrow-backlog/` for the
 * sweep to reopen. A leave, kick or replacement never waits on escrow and is
 * never refused because of it.
 *
 * The Python twin is `rine/_mls/escrow_settle.py`.
 */
import type { MlsGroup } from "./crypto/mls.js";
import { type PeerActor, openPeerMlsGroup } from "./mls-allowed.js";
import { drainEscrow, takeAndSeal } from "./mls-escrow-drain.js";
import { cachedEscrowKey } from "./mls-escrow-key.js";
import {
	EscrowDeferral,
	type EscrowReport,
	emptyReport,
	mergeReports,
	reportDrain,
} from "./mls-escrow-report.js";
import { parkSnapshot } from "./mls-escrow-snapshots.js";

/** Seal the old state's exports under the cached key and save it; `undefined` when there is no key or sealing failed. */
function sealLocally(actor: PeerActor, groupId: string): EscrowReport | undefined {
	const key = cachedEscrowKey(actor);
	if (key === undefined) return undefined;
	try {
		const group = openPeerMlsGroup(actor, groupId);
		const { gaps } = takeAndSeal(actor, groupId, group, key);
		group.save();
		return { ...emptyReport(), gaps };
	} catch {
		// Nothing was saved: the snapshot still holds the exports, so park it.
		return undefined;
	}
}

/**
 * The fork of each queued export and of the current epoch. Advisory, like the
 * record it feeds: a group that cannot name them is parked with none.
 */
function forksOf(group: MlsGroup): Map<number, Uint8Array> {
	try {
		const forks = new Map(
			group.queuedEscrowFingerprints().map(({ epoch, fp }) => [epoch, fp] as const),
		);
		forks.set(group.epoch(), group.epochFingerprint());
		return forks;
	} catch {
		return new Map();
	}
}

/**
 * Park the old snapshot when it holds exports nobody has sealed, or lost some.
 * The report says what waits (`queued`, `dropped`) and whether the snapshot was
 * set aside (`backlogged`): a park that failed leaves `backlogged` at 0 beside a
 * non-zero `queued`, and the caller still goes on to replace the state. The park
 * records the fork of each queued export, so an unreadable snapshot is given up
 * under the forks it held.
 */
function park(actor: PeerActor, groupId: string): EscrowReport {
	const group = openPeerMlsGroup(actor, groupId);
	const { queued, dropped } = group.escrowBacklog();
	const report = { ...emptyReport(), deferral: EscrowDeferral.KeyUnavailable };
	if (queued === 0 && dropped === 0) return report;
	let backlogged = 0;
	try {
		parkSnapshot(
			actor.configDir,
			actor.agentId,
			groupId,
			group.epoch(),
			queued,
			dropped,
			forksOf(group),
		);
		backlogged = 1;
	} catch {
		// Never refuse the replacement or the leave: the report carries the loss.
	}
	return { ...report, queued, dropped, backlogged };
}

/**
 * Settle one group's escrow ahead of a wipe or a state replacement, and report
 * what was done. Best effort: no stored state means nothing to settle, and a
 * failure here must not block the replacement or the leave the caller is making.
 */
export function settleEscrow(actor: PeerActor, groupId: string): EscrowReport {
	try {
		return sealLocally(actor, groupId) ?? park(actor, groupId);
	} catch {
		// Absent or unreadable state is discarded anyway; pending files stay on disk.
		return emptyReport();
	}
}

/**
 * The escrow tail of every join that lands this agent in a group: seal or park
 * the epochs the replaced snapshot still held, drain the joined group's own
 * epoch exports, and report both as one. Callers record the establishment
 * (`noteMlsStateChanged`) themselves, at the mutation.
 */
export async function settleAfterJoin(
	actor: PeerActor,
	groupId: string,
	group: MlsGroup,
): Promise<EscrowReport> {
	const settled = settleEscrow(actor, groupId);
	const outcome = await drainEscrow(actor, groupId, group);
	return mergeReports(settled, reportDrain(actor, groupId, outcome));
}
