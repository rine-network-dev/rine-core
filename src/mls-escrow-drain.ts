/**
 * The MLS read-escrow drain: seal every epoch the native
 * group has yielded, persist it, save the group, then upload.
 *
 * This replaces a bare `group.save()` at every epoch-install site. The order is
 * the crash-safety argument and every step matters:
 *
 *   1. take the exports and seal them to disk BEFORE `group.save()`, so a crash
 *      in between re-yields them on the next load;
 *   2. only then save, which is what makes the take durable;
 *   3. only then upload this group's pending files, so a network failure leaves
 *      the sealed bytes on disk for the next drain rather than losing them.
 *
 * The files of every other group, held or not, are not the drain's business: the
 * cross-group sweep ({@link ./mls-escrow-sweep.js}) clears them at most once per
 * heartbeat interval, because a drain per commit would multiply that traffic.
 *
 * It never throws for a key or network problem: those are reported in the
 * outcome. When no verified key can be had, for whatever reason, the exports
 * stay in the saved snapshot and the next drain yields them again; a revoked
 * branch is no exception, because only a signed revocation could justify
 * destroying an epoch's secret and a 410 is not one. A sealing or write failure
 * DOES propagate — nothing was saved, so nothing is lost, and the caller must
 * not treat the epoch as installed.
 */
import { type EscrowGap } from "@rine-network/mls";
import { equalBytes } from "./crypto/bytes.js";
import type { EscrowUploader, VerifiedEscrowKey } from "./crypto/escrow.js";
import type { MlsGroup } from "./crypto/mls.js";
import type { PeerActor } from "./mls-allowed.js";
import { type DrainGap, fileGaps } from "./mls-escrow-gap.js";
import { writeHead } from "./mls-escrow-head.js";
import { resolveEscrowKey } from "./mls-escrow-key.js";
import { type DrainOutcome, emptyOutcome } from "./mls-escrow-report.js";
import { sealTaken, zeroExports } from "./mls-escrow-seal.js";
import { actingHeaders, escrowUploader, uploadPending } from "./mls-escrow-upload.js";

export type { DrainOutcome };

/** The part of a native gap the drain records; the group is the drain's own. */
export function toDrainGap({ epoch, reason, fp }: EscrowGap): DrainGap {
	return { epoch, reason, ...(fp === undefined ? {} : { fp }) };
}

/** How {@link takeAndSeal} differs from the live drain's own call. */
interface TakeOptions {
	/** The uploader the exports are sealed under. Default: the acting agent's current keys. */
	uploader?: EscrowUploader;
	/**
	 * Remember the newest sealed epoch as the group's head. Only the live drain
	 * does: a settled or reopened old state is not the state a send advertises,
	 * and at an equal epoch number it could carry another fork's fingerprint.
	 */
	recordHead?: boolean;
}

/**
 * Take a group's exports, seal them to the pending store and file the gaps:
 * everything the drain does on disk, with no save and no network. The caller
 * owns what comes next: `group.save()` for a state that stays, nothing for one
 * about to go.
 *
 * Shared by the drain, the settle that runs before a state is discarded and the
 * reopening of a parked snapshot. A sealing or write failure propagates with
 * nothing saved, so the exports re-yield the next time the state is loaded.
 */
export function takeAndSeal(
	actor: PeerActor,
	groupId: string,
	group: MlsGroup,
	key: VerifiedEscrowKey,
	{ uploader = escrowUploader(actor), recordHead = false }: TakeOptions = {},
): { sealed: number; gaps: DrainGap[] } {
	const { exports: taken, gaps } = group.takeEscrowExports();
	let sealed: number;
	try {
		sealed = sealTaken(actor.configDir, actor.agentId, groupId, key, uploader, taken);
	} finally {
		zeroExports(taken);
	}
	if (recordHead && taken.length > 0) {
		const newest = taken.reduce((a, b) => (b.epoch > a.epoch ? b : a));
		writeHead(
			actor.configDir,
			actor.agentId,
			groupId,
			{ epoch: newest.epoch, fp: newest.fp },
			{
				live:
					newest.epoch === group.epoch() &&
					equalBytes(newest.fp, group.epochFingerprint()),
			},
		);
	}
	const drainGaps = gaps.map(toDrainGap);
	fileGaps(actor.configDir, actor.agentId, groupId, drainGaps);
	return { sealed, gaps: drainGaps };
}

/** What a drain needs to go on to upload: the verified key and the uploader it sealed under. */
interface Sealing {
	key: VerifiedEscrowKey;
	uploader: EscrowUploader;
}

/**
 * Steps 1-2: take, seal, record the gaps and save the group. `sealing` is what
 * the upload needs, and is absent when sealing was deferred (the outcome says why).
 */
async function sealAndSave(
	actor: PeerActor,
	groupId: string,
	group: MlsGroup,
): Promise<{ outcome: DrainOutcome; sealing?: Sealing }> {
	const outcome = emptyOutcome();
	let key: VerifiedEscrowKey;
	try {
		key = await resolveEscrowKey(actor, actingHeaders(actor));
	} catch (error) {
		outcome.deferred = error instanceof Error ? error : new Error(String(error));
		// No verified key: save WITHOUT taking, so the exports stay in the
		// snapshot and the next drain yields them again.
		outcome.backlog = group.escrowBacklog();
		group.save();
		return { outcome };
	}

	const uploader = escrowUploader(actor);
	const { sealed, gaps } = takeAndSeal(actor, groupId, group, key, {
		uploader,
		recordHead: true,
	});
	outcome.sealed = sealed;
	outcome.gaps.push(...gaps);

	// Everything is on disk: this is the line a crash before it re-yields the
	// exports, and the line a crash after it would lose them.
	group.save();
	return { outcome, sealing: { key, uploader } };
}

/**
 * Steps 1-3 of the read escrow. Replaces a bare `group.save()` at every epoch-install
 * site. Never throws for a key or network problem: it reports them in the
 * outcome.
 *
 * The outcome holds this drain's own gaps only. The epochs a background sweep
 * lost wait in the handoff for a result that reaches a caller
 * ({@link reportDrain}), so a drain whose outcome is dropped does not consume
 * them.
 */
export async function drainEscrow(
	actor: PeerActor,
	groupId: string,
	group: MlsGroup,
): Promise<DrainOutcome> {
	const { outcome, sealing } = await sealAndSave(actor, groupId, group);
	if (sealing !== undefined) {
		await uploadPending(actor, groupId, sealing.key, sealing.uploader, outcome);
	}
	return outcome;
}
