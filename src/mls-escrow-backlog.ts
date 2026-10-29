/**
 * Clearing the old-state snapshots a settle parked ({@link ./mls-escrow-snapshots.js}).
 *
 * The sweep reopens each one in a scratch store, takes and seals what it holds
 * into pending files, and deletes it. A snapshot stays until its exports are
 * sealed, except one that could not be reopened sixteen times (loss
 * `Unreadable`) and any when the branch is revoked (loss `BranchRevoked`); each
 * is deleted only after a gap marker records every epoch it held, so a crash
 * between the two leaves the snapshot and the next pass finishes the job. Only
 * a snapshot that holds no readable state is counted: a full disk, a permission
 * error or a fault in sealing says nothing about the snapshot, so it is
 * reported and tried again at the next pass without using up an attempt, and a
 * snapshot is never deleted for a bug that would fail it again.
 *
 * A reopened snapshot names each lost epoch's fork, so the marker is written for
 * that fork (`<epoch>-<fp>.gap`); a snapshot that cannot be reopened is known by
 * the range and the forks recorded when it was parked, so its markers name those
 * forks. An epoch with no recorded fork (the queue had dropped it) still gets a
 * fork-less marker.
 *
 * The Python twin is `rine/_mls/escrow_backlog.py`, with the same layout.
 */
import type { EscrowTake } from "@rine-network/mls";
import type { VerifiedEscrowKey } from "./crypto/escrow.js";
import type { PeerActor } from "./mls-allowed.js";
import { takeAndSeal, toDrainGap } from "./mls-escrow-drain.js";
import { type DrainGap, EscrowLoss, lostGaps, writeGap } from "./mls-escrow-gap.js";
import type { GroupGap } from "./mls-escrow-handoff.js";
import { SnapshotUnreadableError, isLocalIoFailure, withSnapshotGroup } from "./mls-escrow-snapshot-group.js";
import { lostEpochs, recordedForks } from "./mls-escrow-queued.js";
import { isDue, isExhausted, noteFailure, readAttempts } from "./mls-escrow-retry.js";
import { zeroExports } from "./mls-escrow-seal.js";
import { type BacklogSnapshot, deleteSnapshot, listSnapshots } from "./mls-escrow-snapshots.js";

/** What clearing the backlog did: the files it sealed, the gaps it filed (each with its group), the failures it met. */
export interface BacklogResult {
	sealed: number;
	gaps: GroupGap[];
	failures: Error[];
}

/**
 * The epochs a snapshot holds that nobody has sealed, as gaps for `loss`: the
 * take's own gaps plus one per unsealed export epoch, each carrying the export's
 * fork. A snapshot that cannot be reopened is known by the range and the forks
 * recorded when it was parked. A local I/O failure says nothing about the
 * snapshot, so it propagates.
 */
function lostSnapshotGaps(
	actor: PeerActor,
	snapshot: BacklogSnapshot,
	loss: EscrowLoss,
): DrainGap[] {
	let taken: EscrowTake;
	try {
		taken = withSnapshotGroup(actor, snapshot, (group) => group.takeEscrowExports());
	} catch (error) {
		if (isLocalIoFailure(error)) throw error;
		const epochs = lostEpochs(
			actor.configDir,
			actor.agentId,
			snapshot.groupId,
			snapshot.path,
			snapshot.epoch,
		);
		return lostGaps(epochs, loss, recordedForks(snapshot.path, snapshot.epoch));
	}
	try {
		const gaps = taken.gaps.map(toDrainGap);
		const forks: DrainGap[] = taken.exports.map((export_) => ({
			epoch: export_.epoch,
			reason: loss,
			fp: export_.fp,
		}));
		return [...gaps, ...forks];
	} finally {
		zeroExports(taken.exports);
	}
}

/** Add one snapshot's gaps to the result, once per (epoch, reason) and tagged with its group. */
function reportGaps(result: BacklogResult, groupId: string, gaps: DrainGap[]): void {
	const seen = new Set<string>();
	for (const gap of gaps) {
		const key = `${gap.epoch}\0${gap.reason}`;
		if (seen.has(key)) continue;
		seen.add(key);
		result.gaps.push({ groupId, gap });
	}
}

/**
 * File the loss of a snapshot's epochs, then delete it. A failure to make the
 * marker durable keeps the snapshot for the next pass.
 */
function giveUp(
	actor: PeerActor,
	snapshot: BacklogSnapshot,
	loss: EscrowLoss,
	result: BacklogResult,
): void {
	let gaps: DrainGap[];
	try {
		gaps = lostSnapshotGaps(actor, snapshot, loss).map((g) => ({
			...g,
			reason: writeGap(actor.configDir, actor.agentId, snapshot.groupId, g, g.fp),
		}));
	} catch (error) {
		result.failures.push(error instanceof Error ? error : new Error(String(error)));
		return;
	}
	deleteSnapshot(snapshot);
	reportGaps(result, snapshot.groupId, gaps);
}

/** Give up on every parked snapshot of this agent, as when its branch is revoked. */
export function giveUpSnapshots(actor: PeerActor, loss: EscrowLoss): BacklogResult {
	const result: BacklogResult = { sealed: 0, gaps: [], failures: [] };
	for (const snapshot of listSnapshots(actor.configDir, actor.agentId)) {
		giveUp(actor, snapshot, loss, result);
	}
	return result;
}

/**
 * Seal every due snapshot's exports into the pending store and delete the
 * snapshot; the sweep uploads the new files next. Reopening needs no network.
 * The sealed files are on disk before the snapshot goes.
 */
export function processBacklog(
	actor: PeerActor,
	key: VerifiedEscrowKey,
	nowS: number,
): BacklogResult {
	const result: BacklogResult = { sealed: 0, gaps: [], failures: [] };
	for (const snapshot of listSnapshots(actor.configDir, actor.agentId)) {
		if (isExhausted(readAttempts(snapshot.path))) {
			giveUp(actor, snapshot, EscrowLoss.Unreadable, result);
			continue;
		}
		if (!isDue(snapshot.path, nowS)) continue;
		try {
			const taken = withSnapshotGroup(actor, snapshot, (group) =>
				takeAndSeal(actor, snapshot.groupId, group, key, { recordHead: false }),
			);
			result.sealed += taken.sealed;
			result.gaps.push(...taken.gaps.map((gap) => ({ groupId: snapshot.groupId, gap })));
			deleteSnapshot(snapshot);
		} catch (error) {
			const failure = error instanceof Error ? error : new Error(String(error));
			result.failures.push(failure);
			if (!(error instanceof SnapshotUnreadableError)) continue;
			const record = noteFailure(snapshot.path, failure.message, nowS);
			if (isExhausted(record)) {
				giveUp(actor, snapshot, EscrowLoss.Unreadable, result);
			}
		}
	}
	return result;
}
