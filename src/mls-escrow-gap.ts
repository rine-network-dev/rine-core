/**
 * The record of an installed epoch that has no escrow.
 *
 * The native group reports an epoch it cannot escrow once, and the drain's
 * `group.save()` makes that report durable, so the drain files a marker here
 * before saving: nothing else remembers the epoch afterwards. A marker is a file
 * beside the group's pending escrows, holding the reason:
 *   <mls store>/escrow-pending/<group_id>/<epoch>.gap              {@link GapReason} value
 *   <mls store>/escrow-pending/<group_id>/<epoch>-<fp hex>.gap     one fork's loss
 *
 * The fork-less name is what a report of an epoch with no escrow at all files;
 * the fork-named one is what a give-up files, so the loss names the fork whose
 * bytes were dropped. A marker is only ever written once — the first reason for
 * a name is kept — and removed when that fork's escrow is stored.
 *
 * A marker also records an epoch whose escrow was given up for good (an
 * {@link EscrowLoss}): the marker is filed first and the file deleted after, so
 * a crash in between leaves both and the next sweep repeats the give-up
 * idempotently. No marker holds secret material.
 *
 * {@link listPending} reads only `<epoch>-<fp hex>.bin`, so a marker never
 * reaches an upload.
 */
import type { EscrowGapReason } from "@rine-network/mls";
import * as mls from "@rine-network/mls";
import * as fs from "node:fs";
import { createAtomicExclusive } from "./config.js";
import { RevokedCode } from "./errors-revoked.js";
import { fsyncDir, fsyncFile } from "./fsync.js";
import { clearHeadOf } from "./mls-escrow-head.js";
import { gapPath } from "./mls-escrow-gap-names.js";
import {
	type PendingEscrow,
	deletePending,
	groupPendingDir,
} from "./mls-escrow-pending.js";

/**
 * The binding's runtime enum object. A `const enum` has no value in the type
 * system, hence the cast; its members are non-enumerable, hence the names below.
 */
const BINDING_REASONS = (
	mls as unknown as { EscrowGapReason: Record<string, string> }
).EscrowGapReason;

/** Why an epoch's escrow was given up for good, rather than merely missing. */
export const EscrowLoss = {
	Refused: "refused",
	Unreadable: "unreadable",
	BranchRevoked: RevokedCode.Branch,
	/** The agent that would upload is revoked, so the server takes nothing from it. */
	AgentRevoked: RevokedCode.Agent,
} as const;
export type EscrowLoss = (typeof EscrowLoss)[keyof typeof EscrowLoss];

/** Every reason a marker may hold: a native gap reason or an {@link EscrowLoss}. */
export type GapReason = EscrowGapReason | EscrowLoss;

/**
 * Every reason a marker may hold, read off the binding itself so a variant the
 * addon gains is accepted without a list here to keep in step, plus the losses
 * this module records.
 */
const GAP_REASONS: ReadonlySet<string> = new Set([
	...Object.getOwnPropertyNames(BINDING_REASONS).map((name) =>
		String(BINDING_REASONS[name]),
	),
	...Object.values(EscrowLoss),
]);

/** The reason a marker's text names, or `undefined` when it names none. */
export function asGapReason(text: string): GapReason | undefined {
	return GAP_REASONS.has(text) ? (text as GapReason) : undefined;
}

/** An installed epoch with no escrow, and why. */
export interface DrainGap {
	epoch: number;
	reason: GapReason;
	/**
	 * The fork the epoch's escrow belongs to, when the core could name it; a gap
	 * without one blocks every fork at that epoch.
	 */
	fp?: Uint8Array;
}

/**
 * Record that `epoch` has no escrow, for one fork when `fp` is given. The first
 * reason written for a name is kept: a later write for the same marker leaves it
 * as it is. The marker and its directory entry are on disk before this returns,
 * because a deletion follows it. Returns the reason the marker holds, which is
 * the first writer's when this one lost.
 */
export function writeGap(
	configDir: string,
	agentId: string,
	groupId: string,
	gap: DrainGap,
	fp?: Uint8Array,
): GapReason {
	const dir = groupPendingDir(configDir, agentId, groupId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	const path = gapPath(configDir, agentId, groupId, gap.epoch, fp);
	createAtomicExclusive(path, gap.reason);
	fsyncFile(path);
	fsyncDir(dir);
	return asGapReason(fs.readFileSync(path, "utf-8")) ?? gap.reason;
}

/** Record a marker for every gap, each durable before the next is written. */
export function fileGaps(
	configDir: string,
	agentId: string,
	groupId: string,
	gaps: Iterable<DrainGap>,
): void {
	for (const gap of gaps) writeGap(configDir, agentId, groupId, gap, gap.fp);
}

/**
 * One gap per epoch, all with the same loss, each under the fork recorded for
 * its epoch when there is one.
 */
export function lostGaps(
	epochs: Iterable<number>,
	loss: EscrowLoss,
	forks: ReadonlyMap<number, Uint8Array> = new Map(),
): DrainGap[] {
	return [...epochs].map((epoch) => {
		const fp = forks.get(epoch);
		return { epoch, reason: loss, ...(fp === undefined ? {} : { fp }) };
	});
}

/**
 * Give up one pending escrow for good: file the marker naming the loss and the
 * fork, forget the group's escrow head when it names this escrow, then delete
 * the file. The marker is durable before the rest, so a crash in between leaves
 * it beside the file and the next pass repeats this idempotently. The gap names
 * the reason the marker holds, which is an earlier give-up's when there was one.
 * Throws when the marker cannot be written, leaving the file in place. With the head
 * forgotten, a send at the epoch reads the marker and raises the typed gap
 * instead of posting under a fingerprint the server will never hold.
 */
export function giveUpPending(
	configDir: string,
	agentId: string,
	pending: PendingEscrow,
	loss: EscrowLoss,
): DrainGap {
	const reason = writeGap(
		configDir,
		agentId,
		pending.groupId,
		{ epoch: pending.epoch, reason: loss },
		pending.fp,
	);
	const gap: DrainGap = { epoch: pending.epoch, reason };
	clearHeadOf(configDir, agentId, pending);
	deletePending(configDir, agentId, pending);
	return gap;
}

/** Drop one fork's marker: the server holds that fork's escrow now. Missing is success. */
export function clearGap(
	configDir: string,
	agentId: string,
	groupId: string,
	epoch: number,
	fp: Uint8Array,
): void {
	fs.rmSync(gapPath(configDir, agentId, groupId, epoch, fp), { force: true });
}
