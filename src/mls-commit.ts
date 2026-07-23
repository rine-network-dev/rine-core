import type { CommitBundle, MlsGroup } from "@rine-network/mls";
import { mlsCommit, mlsToBase64 } from "./crypto/mls-api.js";
import type { HttpClient } from "./http.js";

/** A member a commit admits, and the KeyPackage claimed for them. */
export interface Joiner {
	agentId: string;
	keyPackage: Uint8Array;
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
 */
export async function postMlsCommit(
	client: HttpClient,
	groupId: string,
	group: MlsGroup,
	bundle: CommitBundle,
	joiners: Joiner[] = [],
	extraHeaders?: Record<string, string>,
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
		client,
		groupId,
		{
			commit: mlsToBase64(bundle.commit),
			welcomes,
			group_info: mlsToBase64(bundle.groupInfo),
			cipher_suite: group.cipherSuite(),
			epoch: bundle.epoch,
		},
		extraHeaders,
	);
	return resp.epoch ?? bundle.epoch;
}
