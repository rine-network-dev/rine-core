/**
 * What the escrow sweep does when the key read says the branch or agent is
 * revoked: give up every snapshot and pending file of the agent, noting each
 * lost epoch with its group ({@link ./mls-escrow-sweep.js}).
 */
import type { VerifiedEscrowKey } from "./crypto/escrow.js";
import type { PeerActor } from "./mls-allowed.js";
import { giveUpSnapshots } from "./mls-escrow-backlog.js";
import type { EscrowLoss } from "./mls-escrow-gap.js";
import type { GroupGap } from "./mls-escrow-handoff.js";
import { resolveEscrowKey } from "./mls-escrow-key.js";
import { listPending } from "./mls-escrow-pending.js";
import { giveUpFile } from "./mls-escrow-refusal.js";
import type { DrainOutcome } from "./mls-escrow-report.js";
import { revokedLoss } from "./mls-escrow-revoked.js";
import { actingHeaders } from "./mls-escrow-upload.js";

/** What a sweep pass has lost so far, by group, for the handoff. */
export type Lost = GroupGap[];

/**
 * Run `step`, which adds gaps of `groupId` to `outcome`, and note the ones it added.
 * They are noted even when `step` throws.
 */
export async function noting<T>(
	lost: Lost,
	groupId: string,
	outcome: DrainOutcome,
	step: () => T | Promise<T>,
): Promise<T> {
	const before = outcome.gaps.length;
	try {
		return await step();
	} finally {
		for (const gap of outcome.gaps.slice(before)) lost.push({ groupId, gap });
	}
}

/**
 * Give up every snapshot and pending file of the agent: the branch or agent is
 * revoked, so no key will ever be served for them. Each epoch is filed as a gap
 * before its file goes.
 */
async function giveUpEverything(
	actor: PeerActor,
	outcome: DrainOutcome,
	loss: EscrowLoss,
	lost: Lost,
): Promise<void> {
	const backlog = giveUpSnapshots(actor, loss);
	outcome.gaps.push(...backlog.gaps.map(({ gap }) => gap));
	lost.push(...backlog.gaps);
	outcome.failures.push(...backlog.failures);
	for (const pending of listPending(actor.configDir, actor.agentId)) {
		await noting(lost, pending.groupId, outcome, () =>
			giveUpFile(actor, pending, loss, outcome),
		);
	}
}

/**
 * The agent's verified escrow key, or `undefined` once a revoked branch or agent
 * has made every file of the agent worthless and been given up. Any other error
 * is the caller's to report as a deferral, and so is a revocation that does not
 * provably cover this agent (`coversAgent` false).
 */
export async function resolveKeyOrGiveUp(
	actor: PeerActor,
	outcome: DrainOutcome,
	lost: Lost,
	coversAgent: boolean,
): Promise<VerifiedEscrowKey | undefined> {
	try {
		return await resolveEscrowKey(actor, actingHeaders(actor));
	} catch (error) {
		const loss = revokedLoss(error);
		if (loss === undefined || !coversAgent) throw error;
		await giveUpEverything(actor, outcome, loss, lost);
		return undefined;
	}
}
