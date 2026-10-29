import type { CommitBundle } from "@rine-network/mls";
import { MLS_CIPHER_SUITE_XWING } from "./crypto/mls.js";
import { mlsCommit, mlsToBase64 } from "./crypto/mls-api.js";
import { RineApiError } from "./errors.js";
import { type MlsActor, mlsHeartbeat } from "./mls-heartbeat.js";
import { whileSettling } from "./mls-settle-guard.js";

/** A member a commit admits, and the KeyPackage claimed for them. */
export interface Joiner {
	agentId: string;
	keyPackage: Uint8Array;
}

/**
 * The server's epoch CAS refused this commit: a peer's commit landed first, so
 * the group has moved on and this one was built against a superseded epoch.
 *
 * Recoverable by catching up and rebuilding the commit once — and only once. An
 * unbounded retry against an advancing epoch is a self-DoS.
 */
export function isEpochConflict(err: unknown): boolean {
	return err instanceof RineApiError && err.code === "epoch_conflict";
}

/**
 * Run `attempt`; when it fails with an epoch conflict, `resync` with that
 * conflict and run `attempt` once more. Any other first failure, a failing
 * resync, and every second failure (a second conflict included) propagate, so
 * each caller decides what a lost second race means for its own result.
 */
export async function retryOnEpochConflict<T>(
	attempt: () => Promise<T>,
	resync: (conflict: unknown) => Promise<unknown> = async () => undefined,
): Promise<T> {
	try {
		return await attempt();
	} catch (err) {
		if (!isEpochConflict(err)) throw err;
		await resync(err);
	}
	return attempt();
}

/** What the server made of a posted commit. */
export interface MlsCommitAccepted {
	/** The epoch the server recorded the commit at. */
	epoch: number;
	/** False when the server holds the commit tentatively until a member acknowledges it (open-enrollment groups). */
	confirmed: boolean;
}

/**
 * Post one commit bundle to the server and report what it made of it.
 *
 * Nothing is persisted here on purpose: every caller saves local state only
 * after this resolves, so a commit the server's epoch CAS rejects leaves no
 * forked state behind.
 *
 * `bundle.welcomes[i]` is the Welcome for `joiners[i]` — the native core pairs
 * them by KeyPackage reference rather than by position luck, so a member with
 * no Welcome is a bug worth stopping on rather than a blob delivered to the
 * wrong agent.
 *
 * `removes` names the agents this commit says its Remove proposals evict.
 * It is the declaration a later
 * `DELETE /groups/{id}/members/{id}` spends, once per named agent, and a commit
 * that declares nobody can be named in no removal. 🔴 It is **client-asserted**:
 * a passthrough server never opens the commit blob, so nothing checks that the
 * commit really carries a Remove for these agents. Declaring buys that
 * the claim was made in advance — before the poster knew which DELETE would
 * land — and that it is spendable exactly once.
 *
 * Every commit the product posts passes through here, which is why the acting
 * agent's key-package heartbeat lives here too: seven verbs get it structurally
 * and an eighth cannot ship without one. It beats AFTER the server has accepted
 * the commit — the commit is the caller's purpose, replenishment is
 * maintenance, and a top-up must never be the reason a commit did not land.
 *
 * The beat runs inside the settlement hold because the caller's group handle is
 * still un-adopted at this point: a key-rotation settlement that opened the same
 * group from here would read the caller's own commit as a peer's. Inside the
 * hold the beat still tops up key packages.
 */
export async function postMlsCommitBundle(
	actor: MlsActor,
	groupId: string,
	bundle: CommitBundle,
	joiners: Joiner[] = [],
	extraHeaders?: Record<string, string>,
	removes: string[] = [],
): Promise<MlsCommitAccepted> {
	const welcomes = joiners.map((joiner, i) => {
		const welcome = bundle.welcomes[i];
		if (!welcome) {
			throw new Error(
				`MLS commit for group ${groupId} produced no welcome for ${joiner.agentId}`,
			);
		}
		return { agent_id: joiner.agentId, welcome: mlsToBase64(welcome) };
	});

	const resp = await mlsCommit(
		actor.client,
		groupId,
		{
			commit: mlsToBase64(bundle.commit),
			welcomes,
			group_info: mlsToBase64(bundle.groupInfo),
			cipher_suite: MLS_CIPHER_SUITE_XWING,
			epoch: bundle.epoch,
			removes,
		},
		extraHeaders,
	);
	await whileSettling(actor, () => mlsHeartbeat(actor, "gated"));
	return { epoch: resp.epoch ?? bundle.epoch, confirmed: resp.confirmed ?? true };
}

/**
 * Post one commit bundle and return the epoch the group is now at.
 *
 * See {@link postMlsCommitBundle} for the body, the heartbeat and the
 * settlement hold; this is the epoch-only view of the same call.
 */
export async function postMlsCommit(
	actor: MlsActor,
	groupId: string,
	bundle: CommitBundle,
	joiners: Joiner[] = [],
	extraHeaders?: Record<string, string>,
	removes: string[] = [],
): Promise<number> {
	return (
		await postMlsCommitBundle(actor, groupId, bundle, joiners, extraHeaders, removes)
	).epoch;
}
