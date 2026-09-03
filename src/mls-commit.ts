import type { CommitBundle, MlsGroup } from "@rine-network/mls";
import { mlsCommit, mlsToBase64 } from "./crypto/mls-api.js";
import { RineApiError } from "./errors.js";
import { type MlsActor, mlsHeartbeat } from "./mls-heartbeat.js";

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
 * Post one commit bundle to the server and return the epoch the group is now at.
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
 */
export async function postMlsCommit(
	actor: MlsActor,
	groupId: string,
	group: MlsGroup,
	bundle: CommitBundle,
	joiners: Joiner[] = [],
	extraHeaders?: Record<string, string>,
	removes: string[] = [],
): Promise<number> {
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
			cipher_suite: group.cipherSuite(),
			epoch: bundle.epoch,
			removes,
		},
		extraHeaders,
	);
	await mlsHeartbeat(actor, "gated");
	return resp.epoch ?? bundle.epoch;
}
