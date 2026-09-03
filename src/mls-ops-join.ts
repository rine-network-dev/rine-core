import { ACTING_AGENT_HEADER } from "./actor.js";
import {
	fetchGroupInfo,
	fetchWelcomes,
	mlsFromBase64,
} from "./crypto/mls-api.js";
import { isUnprocessableCommit } from "./crypto/mls-errors.js";
import { noteMlsStateChanged } from "./crypto/mls-state.js";
import { type MlsGroup, loadMlsGroup, openMlsClient } from "./crypto/mls.js";
import { RineApiError } from "./errors.js";
import type { HttpClient } from "./http.js";
import { postMlsCommit } from "./mls-commit.js";
import { mlsHeartbeat } from "./mls-heartbeat.js";
import {
	type MlsWelcomeRefusedError,
	refusalIsRetryable,
	welcomeRefusal,
} from "./mls-welcome-guard.js";
import { WelcomeSpool, isSpoolableId } from "./mls-welcome-spool.js";

/** One refusal a pass earned, and whether its bytes arrived in that pass. */
interface PassRefusal {
	refusal: MlsWelcomeRefusedError;
	isNew: boolean;
}

/** How a caller narrows a pass to the one group it is establishing. */
export interface ProcessMlsWelcomesOptions {
	/**
	 * The group this call is establishing state for, when there is exactly one.
	 *
	 * It decides which refusal is raised — see {@link pickRefusal} — and it is
	 * what keeps a refusal for an unrelated group from failing this caller's
	 * work. A caller processing the whole queue (a pre-send sync, a join verb
	 * that does not know which Welcome it is waiting for) leaves it unset.
	 */
	forGroup?: string;
}

/**
 * Which refusal a pass raises, out of the ones it earned.
 *
 * 🔴 Never `refusals[0]`. The queue used to be ordered by file name, which is
 * the server-chosen delivery id, so a server that wanted a refusal suppressed
 * minted a decoy that sorted first and the caller's own group's refusal became
 * a log line (MEASURED).
 *
 * `forGroup` answers about exactly that group and nothing else, in both
 * directions. Its refusal is raised whether or not the bytes arrived in this
 * pass — the caller asked about that group, and a refusal is the answer to the
 * question. Every other group's refusal is withheld from this caller, because a
 * substituted Welcome for one group must not fail a legitimate install, send or
 * read of another. Both halves have to live here: leaving the second one to the
 * caller is precisely how the TypeScript read path ended up aborting unrelated
 * decrypts while the Python one did not.
 *
 * With no `forGroup` the pass answers about the whole queue and the arrival
 * rule decides: reported once, when its bytes arrive, then quiet, because a
 * retained refusal that raised on every later pass would let one unusable
 * Welcome fail every future join, send and read.
 *
 * Nothing withheld here is lost. A withheld refusal keeps its Welcome on the
 * spool ({@link refusalIsRetryable}) and is raised by the first call scoped to
 * its own group — which is the call that needed to hear it.
 */
function pickRefusal(
	refusals: PassRefusal[],
	forGroup?: string,
): MlsWelcomeRefusedError | undefined {
	if (forGroup) {
		const wanted = forGroup.toLowerCase();
		return refusals.find((r) => r.refusal.groupId.toLowerCase() === wanted)
			?.refusal;
	}
	return refusals.find((r) => r.isNew)?.refusal;
}

/**
 * Fetch all pending MLS welcomes for an agent and process them, establishing
 * local group state for each group the agent has been added to.
 *
 * The native core matches the Welcome to the private half of the KeyPackage it
 * was sealed to and consumes that half on `save()`, so nothing here has to
 * bookkeep key packages.
 *
 * Ordering is the whole design. `GET /agents/{id}/mls/welcomes` marks every
 * Welcome it returns consumed in the same transaction that returns it, so the
 * response is the only copy: it is spooled to disk (`mls-welcome-spool.ts`)
 * before anything is done with it, and an entry leaves the spool only once its
 * join has a final outcome.
 *
 * Every Welcome passes {@link welcomeRefusal} before it is adopted — the group
 * substitution guard, which is what stands between a server-minted group and
 * this agent's real state for the id it claims. A refusal a later attempt could
 * clear keeps its bytes on the spool ({@link refusalIsRetryable}); a
 * deterministic one discards them. Either way the rest of the batch still
 * installs, because abandoning the loop on the first refusal would strand every
 * legitimate Welcome behind it. The same holds for a Welcome no MLS core here
 * can open and for one the server named something that is not a file name: both
 * are dropped and the pass carries on, as the Python twin does.
 *
 * READ — the twin reports those two drops with a `logger.warning` and counts
 * them into `MlsWelcomeOutcome.discarded`, and this stack does neither: rine-core
 * has no logging facility, and its convention for a partial failure is silent
 * degradation with a throw reserved for a total one (`sender-key-ops.ts`
 * `fetchPublishedKeys`). The two stacks agree on what HAPPENS; they disagree on
 * whether it is said out loud, and only the surfaces above rine-core can close
 * that.
 *
 * 🔴 **Which refusal is raised is {@link pickRefusal}'s decision, and a caller
 * that knows the group it is establishing must say so via `forGroup`.** Without
 * it the pass falls back to "the first refusal whose bytes arrived in this
 * pass" — loud once, then quiet, so a single unusable Welcome cannot fail every
 * future join, send and read on this agent.
 */
export async function processMlsWelcomes(
	configDir: string,
	agentId: string,
	client: HttpClient,
	opts: ProcessMlsWelcomesOptions = {},
): Promise<{ processed: number; groupIds: string[] }> {
	const spool = new WelcomeSpool(configDir, agentId);
	// Bound the carried-over set BEFORE this pass's arrivals land. The count
	// bound reaches refused entries only, so neither this pass's batch nor one
	// an aborted pass carried over is evicted by its own size — spooling is not
	// the same event as having had a chance.
	spool.prune();
	// The fetch is one-shot, so an id it returns has never been spooled before:
	// this set is exactly "arrived in this pass".
	const arrived = new Set<string>();
	const { welcomes } = await fetchWelcomes(client, agentId);
	for (const welcome of welcomes) {
		// State is keyed by the rine group UUID (carried on the welcome delivery),
		// which is also what the founder put in the MLS group id. Skip welcomes the
		// server could not associate with a group.
		if (!welcome.group_id) continue;
		if (!isSpoolableId(welcome.id)) {
			// The id becomes the file name, so a server free to answer with a path
			// fragment is free to place the file (MEASURED: `../../../credentials`
			// overwrote the OAuth store). Asked here rather than caught out of
			// `store`, so a genuine write failure still fails the pass instead of
			// being mistaken for a poisoned name — and so one poisoned name costs
			// its own Welcome and not the rest of the batch.
			continue;
		}
		spool.store({ ...welcome, group_id: welcome.group_id });
		arrived.add(welcome.id);
	}

	const pending = spool.pending();
	if (pending.length === 0) return { processed: 0, groupIds: [] };

	const mls = openMlsClient(configDir, agentId);
	const groupIds: string[] = [];
	const refusals: PassRefusal[] = [];

	for (const { path, delivery } of pending) {
		const rineGroupId = delivery.group_id;
		let group: MlsGroup;
		try {
			group = mls.joinFromWelcome(mlsFromBase64(delivery.blob));
		} catch (err) {
			// A store I/O failure, a contained panic or a poisoned handle is THIS
			// process failing, not the Welcome being unusable — reporting it as an
			// install would replenish key packages and hand the caller a group id it
			// does not hold. `isUnprocessableCommit` is the vocabulary's own name for
			// that split, and over `joinFromWelcome` it admits exactly the two the
			// Python twin catches by class (`RINE_MLS_PROTOCOL`,
			// `RINE_MLS_CIPHER_SUITE_MISMATCH`).
			if (!isUnprocessableCommit(err)) throw err;
			// A Welcome the server serves twice is one of these: `save()` consumed
			// the private half of the KeyPackage it was sealed to, so the second
			// attempt cannot find it. Local state settles which it was, and an
			// already-installed group is an outcome rather than a failure.
			if (loadMlsGroup(mls, rineGroupId) !== null) {
				groupIds.push(rineGroupId);
				spool.discard(path);
				continue;
			}
			// A different core or a different ciphersuite minted it and no later
			// attempt changes that, so it leaves the spool — a permanently
			// unjoinable Welcome must not fail every future pass. It is counted and
			// the pass carries on, because throwing here would skip the
			// key-package heartbeat and throw away the ids this pass DID install,
			// for one Welcome nobody can ever use. The Python twin
			// (`_mls/welcomes.py` `_install`) reaches the same outcome.
			spool.discard(path);
			continue;
		}
		// The acting-agent header is what makes the roster read answer for a
		// multi-agent org: without it the group routes cannot tell which agent is
		// asking, and the guard would degrade to its unreadable-roster answer.
		const refusal = await welcomeRefusal(client, mls, group, rineGroupId, {
			[ACTING_AGENT_HEADER]: agentId,
		});
		if (refusal) {
			refusals.push({ refusal, isNew: arrived.has(delivery.id) });
			// Retained, and now recorded as retained: `prune`'s count bound is over
			// exactly this population, so an entry that has earned a retryable
			// refusal is the only kind it may evict to cap the tax.
			if (refusalIsRetryable(refusal.reason)) spool.markRefused(path);
			else spool.discard(path);
			continue;
		}
		group.save();
		// A processed Welcome is an establishment: invalidate here, at the
		// mutation, so a "this agent holds no MLS state" answer taken before it
		// cannot survive the join that made it false.
		noteMlsStateChanged(configDir, agentId, rineGroupId);
		groupIds.push(rineGroupId);
		spool.discard(path);
	}

	// Each processed welcome consumed one key package, and this is the only path
	// on which an agent's OWN inventory shrinks — so the beat here is forced,
	// never gated: waiting out a floor would leave the agent short in exactly
	// the window a peer is most likely to add it.
	//
	// Unconditional WITHIN THE PASS, which is the whole claim and the wording
	// the Python twin already carries. `:151` returns early on an empty spool,
	// so a pass that found nothing never arrives here — and 🔴 the fix for that
	// is NOT to hoist this call above the early return. Those agents get their
	// beat from the `postMlsCommit`/`syncMlsGroup` seams; hoisting it would
	// change behaviour nobody has ruled on and split the two stacks.
	//
	// A pass whose Welcomes were all REFUSED still needs it, and that is
	// measured rather than argued: mls-rs deletes each KeyPackage's private half
	// inside `join_group` BEFORE rine's roster guard can refuse the install, so
	// a refused pass has already spent the pool. Hence also: before the refusal,
	// not after.
	await mlsHeartbeat({ configDir, agentId, client }, "forced");
	const refused = pickRefusal(refusals, opts.forGroup);
	if (refused) throw refused;

	return { processed: groupIds.length, groupIds };
}

/** A commit was rejected because our GroupInfo targeted a stale epoch. */
function isEpochConflict(err: unknown): boolean {
	return err instanceof RineApiError && err.code === "epoch_conflict";
}

/**
 * The group's only GroupInfo is still tentative (awaiting a peer ACK), so the
 * server has no confirmed join token yet. Distinct from epoch_conflict: a short
 * bounded retry resolves it once a peer ACKs, so it must NOT consume the single
 * epoch-conflict retry below.
 */
function isPendingConfirmation(err: unknown): boolean {
	return err instanceof RineApiError && err.code === "pending_confirmation";
}

const PENDING_RETRY_LIMIT = 3;
const PENDING_RETRY_DELAY_MS = 400;

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Self-join an MLS-active group via an RFC 9420 external commit.
 *
 * Used for OPEN enrollment, where the rine server adds a joiner to the group
 * with no member in the loop — so nobody mints a Welcome and the joiner is a
 * rine member but not yet an MLS member. The joiner fetches the group's latest
 * published GroupInfo, derives a fresh init_secret against its external_pub,
 * and posts a public External Commit that existing members process (via the
 * EXISTING syncMlsGroup path) to advance the epoch.
 *
 * State is keyed by the RINE group UUID — the same key encrypt/decrypt use — so
 * the joiner can immediately send and receive.
 *
 * Epoch-conflict handling (RFC 9420 §12.4.3.2 + RFC 9750): a GroupInfo is
 * single-use per epoch. If a competing external join lands first, our GroupInfo
 * is stale and our commit targets a stale epoch (members reject). We do a single
 * discard-and-rebuild retry against a freshly-fetched GroupInfo; on a second
 * failure we surface a clear, actionable terminal error rather than looping (an
 * unbounded retry against an advancing epoch is a self-DoS).
 */
export async function externalJoinMlsGroup(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number }> {
	const attempt = async (): Promise<{ epoch: number }> => {
		const info = await fetchGroupInfo(client, groupId, extraHeaders);
		if (!info.group_info) {
			throw new Error(
				`Cannot self-join MLS group ${groupId}: no published GroupInfo. ` +
					"An existing member must publish one (open enrollment requires a current-epoch GroupInfo).",
			);
		}

		const mls = openMlsClient(configDir, agentId);
		const group = mls.joinByExternalCommit(mlsFromBase64(info.group_info));
		const bundle = group.lastCommit();
		if (!bundle) {
			throw new Error(
				`External MLS self-join for group ${groupId} produced no commit`,
			);
		}

		const epoch = await postMlsCommit(
			{ configDir, agentId, client },
			groupId,
			group,
			bundle,
			[],
			extraHeaders,
		);
		// Only adopt state AFTER the server accepts the commit (never optimistically).
		group.save();
		// An accepted external commit is an establishment: invalidate at the
		// mutation rather than leaving it to whoever called the join.
		noteMlsStateChanged(configDir, agentId, groupId);
		return { epoch };
	};

	// A brand-new group whose first post-init commit is still tentative has no
	// confirmed join token yet. Briefly poll for confirmation, capturing the
	// FIRST non-pending error so it flows into the epoch-conflict handler below
	// WITHOUT a duplicate attempt. This never un-processes confirmed state — the
	// joiner simply has not yet seen a confirmed GroupInfo; an orphaned own-join
	// is discarded on the next sync, which re-syncs from the confirmed epoch and
	// re-attempts the external join.
	let firstErr: unknown;
	for (let i = 0; ; i++) {
		try {
			return await attempt();
		} catch (err) {
			if (!isPendingConfirmation(err)) {
				firstErr = err;
				break;
			}
			if (i >= PENDING_RETRY_LIMIT - 1) {
				throw new Error(
					`Cannot self-join MLS group ${groupId}: GroupInfo is still pending ` +
						"peer confirmation after a brief retry. Try again shortly.",
					{ cause: err },
				);
			}
			await sleep(PENDING_RETRY_DELAY_MS);
		}
	}

	// Only an epoch conflict is recoverable by retrying: a competing join
	// advanced the epoch, so our GroupInfo is stale. ANY other error (no
	// GroupInfo, auth failure, malformed blob) is surfaced immediately —
	// retrying would be pointless and the "epoch conflict" wrapper misleading.
	if (!isEpochConflict(firstErr)) throw firstErr;

	// Single discard-and-rebuild retry against a fresh GroupInfo (the competing
	// join already advanced the epoch, so a current GroupInfo should be
	// available immediately).
	try {
		return await attempt();
	} catch (retryErr) {
		const detail =
			retryErr instanceof Error ? retryErr.message : String(retryErr);
		throw new Error(
			`External MLS self-join failed for group ${groupId} after one retry ` +
				`(likely an epoch conflict — another joiner landed first): ${detail}`,
			{ cause: firstErr },
		);
	}
}
