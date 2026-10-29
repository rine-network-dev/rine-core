import type { CommitBundle, MlsClient, MlsGroup } from "@rine-network/mls";
import { noteMlsStateChanged } from "./crypto/mls-state.js";
import { mlsGroupIdBytes } from "./crypto/mls.js";
import { RineApiError, rejectedAgents } from "./errors.js";
import {
	type AdmissionLedger,
	type AdmitContext,
	type MlsAdmissionResult,
	admissionKey,
	admissionResult,
	recordOutcome,
	requireGroup,
} from "./mls-admission.js";
import { dropSeatedJoiners } from "./mls-admission-recheck.js";
import { claimCurrentKeyPackages } from "./mls-claim-check.js";
import { type Joiner, isEpochConflict, postMlsCommit } from "./mls-commit.js";
import { whenCommitPending } from "./mls-commit-pending.js";
import { drainEscrow } from "./mls-escrow-drain.js";
import {
	type EscrowReport,
	emptyReport,
	mergeReports,
	reportDrain,
} from "./mls-escrow-report.js";
import { mlsFoundingBatchSizes } from "./mls-founding.js";
import { syncMlsGroup } from "./mls-ops-sync.js";

/**
 * The agent ids a `welcome_recipient_rejected` 422 named, or null when the
 * failure was something else entirely.
 *
 * The server carries every offending recipient in a machine-readable `rejected`
 * array precisely so a batch can drop them and retry once, instead of pattern-
 * matching UUIDs out of a sentence. An EMPTY array
 * is therefore meaningful and distinct from null: the refusal was about
 * recipients, but this client cannot tell which — so retrying the same batch
 * would fail identically, and the caller records the whole batch rather than
 * guessing or looping.
 *
 * Only the error CODE is read here; who the array names is `rejectedAgents`'
 * answer, given once for every route that carries one.
 */
export function rejectedRecipients(err: unknown): string[] | null {
	if (!(err instanceof RineApiError)) return null;
	if (err.code !== "welcome_recipient_rejected") return null;
	return rejectedAgents(err).map((entry) => entry.agent_id);
}

/**
 * The commit admitting `keyPackages`, built over state read fresh every time.
 *
 * Re-reading is what makes the retry below correct: a refused commit has
 * already mutated the handle that built it, and nothing was saved, so local
 * state still holds the epoch the server agrees with. `create` mints the group
 * instead — the founding case, and the only one with nothing to read.
 */
function buildCommit(
	ctx: AdmitContext,
	mls: MlsClient,
	create: boolean,
	keyPackages: Uint8Array[],
): { group: MlsGroup; bundle: CommitBundle } {
	if (!create) {
		const group = requireGroup(mls, ctx.groupId);
		return { group, bundle: group.addMembers(keyPackages) };
	}
	const group = mls.createGroupWithMembers(
		mlsGroupIdBytes(ctx.groupId),
		keyPackages,
	);
	const bundle = group.lastCommit();
	if (!bundle) {
		throw new Error(
			`MLS group ${ctx.groupId} was created without an init commit`,
		);
	}
	return { group, bundle };
}

/**
 * Post one batch, answering a rejected-recipient 422 by dropping exactly the
 * recipients it named and retrying the remainder ONCE, and a lost epoch race by
 * catching up and rebuilding ONCE.
 *
 * One retry each, never a loop: the KeyPackages a refused batch claimed are
 * spent either way, and a second refusal means this batch cannot be made to
 * land. Whoever is left is recorded `rejected_by_server` and the admission moves
 * on to the next batch — the group's state is exactly where it was, so the later
 * batches are still valid, and an admission never fails whole.
 *
 * 🔴 The epoch arm is the same single sync-then-retry `removeMlsGroupMember`,
 * `reclaimOrphanLeaves` and the self-join already answer a lost CAS with. Its
 * absence is what made `resume-admission` the one MLS commit verb that reported
 * an epoch conflict to the operator instead of resolving it — and the verb an
 * operator reaches for is precisely the one running against a group that other
 * members are committing to.
 *
 * Returns the epoch the commit landed at and the escrow report of its drain, or
 * null when nothing landed.
 */
async function commitBatch(
	ctx: AdmitContext,
	mls: MlsClient,
	create: boolean,
	joiners: Joiner[],
	ledger: AdmissionLedger,
): Promise<{ epoch: number; escrow: EscrowReport } | null> {
	let attempt = joiners;
	let tries = 0;
	let caughtUp = false;
	for (;;) {
		const { group, bundle } = await whenCommitPending(ctx.groupId, () =>
			buildCommit(ctx, mls, create, attempt.map((joiner) => joiner.keyPackage)),
		);
		try {
			const epoch = await postMlsCommit(
				ctx,
				ctx.groupId,
				bundle,
				attempt,
				ctx.extraHeaders,
			);
			// Local state is adopted only after the server accepts, and the
			// invalidation rides at the mutation, so a "this agent holds no MLS
			// state" answer taken before it cannot survive it. The drain saves the
			// group itself, after sealing this epoch's escrow to disk.
			const escrow = reportDrain(ctx, ctx.groupId, await drainEscrow(ctx, ctx.groupId, group));
			noteMlsStateChanged(ctx.configDir, ctx.agentId, ctx.groupId);
			for (const joiner of attempt) {
				recordOutcome(ledger, joiner.agentId, "added");
			}
			return { epoch, escrow };
		} catch (err) {
			// A peer's commit won the epoch CAS, so this one was built against a
			// superseded epoch. Catch up once and rebuild against the epoch the
			// server now holds. Two things make the rebuild sound: `buildCommit`
			// re-reads local state on every pass, so it builds over what the sync
			// just adopted; and the claimed KeyPackages outlive the conflict, being
			// one-time keys bound to their owner and not to an epoch.
			//
			// 🔴 What is NOT sound is assuming the winning commit seated nobody
			// from this batch. A claim is exclusive per KeyPackage, not per agent,
			// so a second admin holding a different one of the ten an agent
			// published admits it just as validly — and an Add rebuilt over a leaf
			// the tree already holds throws out of `buildCommit`, which is outside
			// this `try`. {@link dropSeatedJoiners} is what keeps that error from
			// escaping the whole admission with the ledger unwritten.
			//
			// Founding is excluded on purpose: `create` means the group's first
			// commit, so there is no local state to catch up and a conflict there
			// says somebody else founded the group, which no retry mends.
			if (isEpochConflict(err) && !create && !caughtUp) {
				caughtUp = true;
				await syncMlsGroup(
					ctx.configDir,
					ctx.agentId,
					ctx.groupId,
					ctx.client,
					ctx.extraHeaders,
				);
				attempt = await dropSeatedJoiners(ctx, mls, attempt, ledger);
				// Everybody in the batch was seated by the commit that won, each
				// recorded as such. Nothing landed from this client, which is what
				// the caller reads a null as, and the batches after it still run.
				if (attempt.length === 0) return null;
				continue;
			}
			const rejected = rejectedRecipients(err);
			if (rejected === null) throw err;
			const named = new Set(rejected.map(admissionKey));
			// A refusal naming nobody this client can read is, as far as it can
			// tell, about the whole batch.
			const drop = (joiner: Joiner): boolean =>
				named.size === 0 || named.has(admissionKey(joiner.agentId));
			const survivors = attempt.filter((joiner) => !drop(joiner));
			const spent = tries >= 1 || survivors.length === 0;
			for (const joiner of spent ? attempt : attempt.filter(drop)) {
				recordOutcome(ledger, joiner.agentId, "skipped", "rejected_by_server");
			}
			if (spent) return null;
			attempt = survivors;
			tries += 1;
		}
	}
}

/**
 * Seat `pending` in successive commits, each sized to the tree it joins.
 *
 * `seated` is the tree's size before the first commit, so founding is simply
 * the `seated = 1` caller of this loop, and a later
 * admission is the same arithmetic started further along. KeyPackages are
 * claimed per batch rather than up front: a claim consumes one-time keys, so a
 * founding refused at commit 5 of 39 used to burn the whole roster's pool with
 * nothing to show for it.
 *
 * `startEpoch` is null only while founding, where the first commit creates the
 * group. A group with no eligible member still founds — one commit admitting
 * nobody — so the caller always has a group to add to later.
 */
export async function runAdmission(
	ctx: AdmitContext,
	mls: MlsClient,
	pending: string[],
	ledger: AdmissionLedger,
	seated: number,
	startEpoch: number | null,
): Promise<MlsAdmissionResult> {
	const sizes = mlsFoundingBatchSizes(pending.length, seated);
	if (startEpoch === null && sizes.length === 0) sizes.push(0);

	let founded = startEpoch !== null;
	let epoch = startEpoch ?? 0;
	let commits = 0;
	let taken = 0;
	let escrow = emptyReport();
	for (const size of sizes) {
		const batch = pending.slice(taken, taken + size);
		taken += size;
		const joiners = await claimCurrentKeyPackages(ctx, batch, ledger);
		if (joiners.length === 0 && founded) continue;
		const landed = await commitBatch(ctx, mls, !founded, joiners, ledger);
		if (landed === null) continue;
		epoch = landed.epoch;
		escrow = mergeReports(escrow, landed.escrow);
		commits += 1;
		founded = true;
	}
	return admissionResult(ledger, epoch, commits, escrow);
}
