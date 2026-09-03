/**
 * Recovering a group this agent can no longer follow — the recovery ladder, and
 * one place rine decides which rung a wedged member takes.
 *
 * Two rungs, ordered, cheap one first:
 *
 *   1. **Replay.** The member is merely behind and the server still holds the
 *      commits it missed. Reads only: no commit, no epoch, nothing billed to
 *      anybody else. This is {@link syncMlsGroup} against the replaying
 *      `since_epoch` the server now honours.
 *   2. **Resync.** Replay cannot bridge the gap — the server holds no commit it
 *      can deliver, or the chain will not apply to this member's state. One
 *      external commit replaces this agent's own leaf at the current epoch, and
 *      it is O(N): every member downloads and processes it.
 *
 * The expensive rung is never the first answer to a three-commit gap, and a
 * caller that paid for it is told so — {@link MlsRecoveryResult} names the rung
 * and how far behind the member was.
 *
 * What this is NOT: a way back for an agent whose local state is gone. The
 * stale leaf index comes from the stale handle and from nowhere else, so state
 * that will not load has no resync — {@link MlsResyncUnavailableError} says so
 * by name rather than surfacing a protocol error from a join that cannot work.
 */
import { fetchGroupInfo, mlsFromBase64 } from "./crypto/mls-api.js";
import {
	MLS_ERR_GROUP_INACTIVE,
	isUnprocessableCommit,
	mlsErrorCode,
} from "./crypto/mls-errors.js";
import { noteMlsStateChanged } from "./crypto/mls-state.js";
import { loadMlsGroup, openMlsClient } from "./crypto/mls.js";
import { RineApiError } from "./errors.js";
import type { HttpClient } from "./http.js";
import { isEpochConflict, postMlsCommit } from "./mls-commit.js";
import type { KeyPackageTopUp } from "./mls-keypackage-topup.js";
import { syncMlsGroup } from "./mls-ops-sync.js";
import { joinLines, keyPackageTopUpLine } from "./mls-recovery-format.js";

/**
 * The server's answer when a replay cannot carry this agent to the group: it
 * holds no deliverable commit for the gap. The ladder's escalation signal —
 * branch on this code, never on the sentence.
 */
export const MLS_RESYNC_REQUIRED_CODE = "mls_resync_required";

/** True when the server refused a replay it could not serve. */
export function isMlsResyncRequired(err: unknown): boolean {
	return err instanceof RineApiError && err.code === MLS_RESYNC_REQUIRED_CODE;
}

/** The stable code {@link MlsResyncUnavailableError} carries. */
export const MLS_RESYNC_UNAVAILABLE_CODE = "mls_resync_unavailable";

/**
 * This agent holds no loadable MLS state for the group, so there is no resync.
 *
 * A resync replaces the agent's **own** leaf, and the leaf index it names can
 * only come from the stale state. Absent state therefore has no recovery path
 * at this end: the remedy is an admin removing the agent and inviting it again,
 * which mints a new leaf and a fresh Welcome.
 *
 * Deliberately not a fallback to a plain external join. MLS refuses that for an
 * agent the tree already holds — `duplicate signature key, hpke key or identity
 * found at index N` — so the fallback would replace an actionable refusal with a
 * protocol error about a leaf the operator never asked about.
 *
 * 🔴 It carries the recovery's key-package top-up, and that is not decoration.
 * This refusal IS the answer an agent gets when a carried vote seated it with no
 * Welcome — the exact population whose published pool has run out — so the one
 * thing that unblocks the re-admission it asks for is the pool the top-up just
 * refilled. Reporting the top-up only on the returned result would report it
 * everywhere except the case it was built for.
 */
export class MlsResyncUnavailableError extends Error {
	readonly code = MLS_RESYNC_UNAVAILABLE_CODE;

	/** What the top-up that ran ahead of this refusal did, when one ran. */
	readonly keyPackages?: KeyPackageTopUp;

	constructor(
		public readonly groupId: string,
		options?: { cause?: unknown; keyPackages?: KeyPackageTopUp },
	) {
		super(
			joinLines(
				`Cannot resync MLS group ${groupId}: this agent's local group state ` +
					`will not load, and a resync needs it — the leaf a resync replaces is ` +
					`named by the stale state itself and by nothing the server knows. Ask ` +
					`an admin to remove this agent from the group and invite it again; ` +
					`re-admission mints a new leaf and a fresh Welcome.`,
				keyPackageTopUpLine(options?.keyPackages),
			),
			options,
		);
		this.name = "MlsResyncUnavailableError";
		this.keyPackages = options?.keyPackages;
	}
}

/** True for {@link MlsResyncUnavailableError}, matched on its code. */
export function isMlsResyncUnavailable(err: unknown): boolean {
	return (
		(err as { code?: unknown } | null | undefined)?.code ===
		MLS_RESYNC_UNAVAILABLE_CODE
	);
}

/**
 * A resync that was tried and refused, said in rine's own words.
 *
 * The core's message alone names no group, no rung and no remedy — it is an
 * mls-rs sentence about a protocol state — and handing that to an operator is
 * the failure this verb exists to replace. Everything the operator can
 * act on is put in front of it; the core's text is kept, last, because it is
 * what distinguishes one refusal from another in a bug report.
 *
 * 🔴 It carries no `cause`, deliberately. The refusal's own words are already
 * inlined as the last clause, and every renderer in this repo concatenates an
 * error with its cause — `formatError` returns `${message}: ${cause.message}` —
 * so attaching it printed the core's sentence twice, the second time behind a
 * bare `: `.
 */
function resyncFailure(groupId: string, err: unknown): Error {
	const detail = err instanceof Error ? err.message : String(err);
	return new Error(
		`Recovering MLS group ${groupId} failed on the resync rung. Replaying the ` +
			`commits the server still holds could not carry this agent, and the ` +
			`external commit that would re-seat its own leaf was refused. A resync ` +
			`recovers stale or corrupt local state, never absent state: if this ` +
			`agent's state cannot reach the group's stored epochs at all, ask an ` +
			`admin to remove it from the group and invite it again — re-admission ` +
			`mints a new leaf and a fresh Welcome. The refusal was: ${detail}`,
	);
}

/**
 * Whether a failed replay is the ladder's signal to pay for the expensive rung.
 *
 * Two signals, and only two. The server refusing a replay it cannot serve is
 * the explicit one. The other is a protocol-level refusal escaping the replay
 * itself: `syncMlsGroup`'s own orphan reconciliation re-bootstraps with a plain
 * external join, which MLS refuses for an agent the tree already holds
 * (`duplicate signature key, hpke key or identity found at index N`,
 * MEASURED) — so a seated member whose tentative commit was rolled back
 * reaches exactly this point, and the rung that fixes it is the resync. Left
 * unhandled it surfaced a protocol error naming a leaf the operator never
 * asked about.
 *
 * A **local** failure never escalates: a store, panic or poisoned handle is
 * this process's problem, and billing every member an O(N) commit for it would
 * be a self-inflicted denial of service. Nor does an eviction — an agent whose
 * leaf a Remove commit took has nothing to re-seat, and the surface says so.
 */
function replayExhausted(err: unknown): boolean {
	if (isMlsResyncRequired(err)) return true;
	return (
		isUnprocessableCommit(err) && mlsErrorCode(err) !== MLS_ERR_GROUP_INACTIVE
	);
}

/** Which rung of the ladder a recovery actually took. */
export type MlsRecoveryRung = "replay" | "resync";

export interface MlsRecoveryResult {
	/**
	 * Which encryption regime this recovery ran against.
	 *
	 * The discriminant of {@link GroupRecoveryResult}: a sender-key group has no
	 * epoch, no commit, no ratchet tree and no leaf, so it cannot be reported as
	 * a third value of {@link MlsRecoveryRung} without faking five of the fields
	 * below. Every consumer branches on this and never on which fields are
	 * present.
	 */
	regime: "mls";
	/**
	 * `replay` costs reads; `resync` cost one O(N) commit that every member of
	 * the group downloads and processes. Reported because an operator who paid
	 * for the second is entitled to know they did.
	 */
	rung: MlsRecoveryRung;
	/** The epoch this agent's local state was at before recovery started. */
	fromEpoch: number;
	/** The epoch it holds now. */
	epoch: number;
	/**
	 * How many epochs behind the group's **confirmed** epoch this agent was when
	 * recovery started, or `null` when the group published no confirmed
	 * GroupInfo to measure against (a brand-new group whose first commit is
	 * still awaiting a peer ACK is the ordinary case).
	 */
	behind: number | null;
	/** Commits applied by the replay rung. Zero when replay bridged nothing. */
	processed: number;
	/**
	 * True when recovery ended with this agent out of the ratchet tree: a Remove
	 * commit it replayed evicted it. The backlog it already holds secrets for
	 * still opens; nothing after the Remove ever will.
	 */
	evicted: boolean;
	/**
	 * What the key-package top-up that rode along with this recovery did.
	 *
	 * Absent when the recovery was not driven through `recoverGroup` — the
	 * `mlsNeverFoundedNote` rule: a consumer spreading the result into JSON then
	 * emits no key at all rather than a null.
	 */
	keyPackages?: KeyPackageTopUp;
}

/**
 * The group's confirmed epoch, or `null` when it cannot be read.
 *
 * A group with no confirmed GroupInfo, and one whose newest is still awaiting a
 * peer ACK, are both unmeasurable rather than wedged — so the distance is
 * reported as unknown and the ladder never escalates on a distance it could not
 * read. It still escalates on the server's explicit refusal.
 */
async function confirmedEpoch(
	client: HttpClient,
	groupId: string,
	extraHeaders?: Record<string, string>,
): Promise<number | null> {
	try {
		return (await fetchGroupInfo(client, groupId, extraHeaders)).epoch;
	} catch {
		return null;
	}
}

/**
 * One resync attempt: fetch the current GroupInfo, build the external commit
 * that replaces `staleLeaf`, and post it.
 *
 * The GroupInfo is fetched here rather than reused from the distance
 * measurement, because a replay may have advanced the group in between and a
 * commit built against a superseded GroupInfo loses the server's epoch CAS.
 *
 * No Welcomes: an external commit admits nobody, so the bundle's `welcomes` is
 * empty and the post names no joiners. Local state is adopted only after the
 * server accepts, so a refused commit leaves the stale state intact.
 */
async function resyncOnce(
	configDir: string,
	agentId: string,
	groupId: string,
	cipherSuite: number,
	staleLeaf: number,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number; target: number | null }> {
	const info = await fetchGroupInfo(client, groupId, extraHeaders);
	if (!info.group_info) {
		throw new Error(
			`Cannot resync MLS group ${groupId}: it has published no GroupInfo to ` +
				"commit against. An existing member must publish one first.",
		);
	}
	const mls = openMlsClient(configDir, agentId, cipherSuite);
	const group = mls.resyncByExternalCommit(
		mlsFromBase64(info.group_info),
		staleLeaf,
	);
	const bundle = group.lastCommit();
	if (!bundle) {
		throw new Error(`MLS resync for group ${groupId} produced no commit`);
	}
	const epoch = await postMlsCommit(
		{ configDir, agentId, client },
		groupId,
		group,
		bundle,
		[],
		extraHeaders,
	);
	group.save();
	noteMlsStateChanged(configDir, agentId, groupId);
	return { epoch, target: info.epoch };
}

/**
 * Resync, with the single rebuild every commit-posting path in rine gets.
 *
 * A resync is an O(N) commit against a group that is free to move while it is
 * in flight, so losing the epoch CAS is expected rather than exceptional. One
 * rebuild against a freshly fetched GroupInfo; a second failure is surfaced,
 * because retrying forever against an advancing epoch is a self-inflicted
 * denial of service — and each attempt bills every member.
 *
 * `staleLeaf` is reused unchanged across the retry: a leaf index belongs to its
 * member until that member is removed, so a peer's commit landing first does not
 * move it.
 */
async function resyncWithRetry(
	configDir: string,
	agentId: string,
	groupId: string,
	cipherSuite: number,
	staleLeaf: number,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number; target: number | null }> {
	try {
		return await resyncOnce(
			configDir,
			agentId,
			groupId,
			cipherSuite,
			staleLeaf,
			client,
			extraHeaders,
		);
	} catch (err) {
		// Not a lost CAS: the resync itself was refused, and that refusal is the
		// operator's answer rather than a race to rebuild against. It gets rine's
		// words instead of the core's. An eviction keeps its own vocabulary,
		// because a surface already translates it into a membership fact.
		if (!isEpochConflict(err)) {
			if (mlsErrorCode(err) === MLS_ERR_GROUP_INACTIVE) throw err;
			throw resyncFailure(groupId, err);
		}
		try {
			return await resyncOnce(
				configDir,
				agentId,
				groupId,
				cipherSuite,
				staleLeaf,
				client,
				extraHeaders,
			);
		} catch (retryErr) {
			const detail =
				retryErr instanceof Error ? retryErr.message : String(retryErr);
			throw new Error(
				`Resyncing MLS group ${groupId} failed after one retry (a peer's ` +
					`commit landed first): ${detail}`,
				{ cause: err },
			);
		}
	}
}

/**
 * Catch this agent's MLS state up with its group, taking the cheapest rung that
 * works.
 *
 * Escalates to the resync rung on exactly three signals, and on nothing else:
 * the server refusing the replay it cannot serve ({@link isMlsResyncRequired}),
 * a protocol-level refusal escaping the replay itself
 * ({@link replayExhausted}), and a replay that ran but left this agent short of
 * the epoch the group was at when recovery started. The last is measured
 * against the epoch read **before** the replay, so a busy group advancing
 * underneath a healthy catch-up is not mistaken for a wedge and billed an O(N)
 * commit for it.
 *
 * @throws MlsResyncUnavailableError when local state will not load at all.
 */
export async function recoverMlsGroup(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<MlsRecoveryResult> {
	const stale = loadMlsGroup(openMlsClient(configDir, agentId), groupId);
	if (stale === null) throw new MlsResyncUnavailableError(groupId);
	const fromEpoch = stale.epoch();
	const cipherSuite = stale.cipherSuite();
	// The ONLY source of the stale leaf. Never `GET /groups/{id}/members`,
	// never a server-supplied index — the server does not know MLS leaf indices.
	const staleLeaf = stale.currentMemberIndex();

	const target = await confirmedEpoch(client, groupId, extraHeaders);
	let behind = target === null ? null : Math.max(0, target - fromEpoch);
	let processed = 0;

	try {
		const replayed = await syncMlsGroup(
			configDir,
			agentId,
			groupId,
			client,
			extraHeaders,
		);
		processed = replayed.processed;
		// An eviction is a settled answer, not a gap: this agent has no leaf to
		// re-seat, so a resync would build a commit about a leaf that is gone.
		if (replayed.evicted || target === null || replayed.epoch >= target) {
			return {
				regime: "mls",
				rung: "replay",
				fromEpoch,
				epoch: replayed.epoch,
				behind,
				processed,
				evicted: replayed.evicted,
			};
		}
	} catch (err) {
		if (!replayExhausted(err)) throw err;
	}

	const { epoch, target: resyncTarget } = await resyncWithRetry(
		configDir,
		agentId,
		groupId,
		cipherSuite,
		staleLeaf,
		client,
		extraHeaders,
	);
	// The up-front measurement is the honest one; this only fills a distance that
	// was unmeasurable before the resync's own GroupInfo read answered it.
	if (behind === null && resyncTarget !== null) {
		behind = Math.max(0, resyncTarget - fromEpoch);
	}
	return {
		regime: "mls",
		rung: "resync",
		fromEpoch,
		epoch,
		behind,
		processed,
		evicted: false,
	};
}
