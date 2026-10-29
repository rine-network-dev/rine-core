// Step 6 of recovery: put a restored agent back into the closed groups it held a seat in.
import { ACTING_AGENT_HEADER } from "./actor.js";
import type { GroupRead } from "./api-types.js";
import { fetchGroupInfo, mlsFromBase64 } from "./crypto/mls-api.js";
import { MLS_ERR_NO_SEAT_TO_REPLACE, mlsErrorCode } from "./crypto/mls-errors.js";
import { noteMlsStateChanged } from "./crypto/mls-state.js";
import type { HttpClient } from "./http.js";
import { type PeerActor, openPeerMlsClient } from "./mls-allowed.js";
import { admitGroupPeers } from "./mls-allowed-tree.js";
import { postMlsCommit, retryOnEpochConflict } from "./mls-commit.js";
import { type EscrowReport, emptyReport } from "./mls-escrow-report.js";
import { epochEscrowStored } from "./mls-escrow-stored.js";
import { admitRefusingRotatedLeaf, isMlsRotatedLeaf } from "./mls-rotated-leaf.js";
import { seatedMlsGroups } from "./mls-seated-groups.js";
import { settleAfterJoin } from "./mls-escrow-settle.js";

export const ReseatStatus = {
	Reseated: "reseated",
	NoGroupInfo: "no_group_info",
	NotSeated: "not_seated",
	NeedsReAdd: "needs_readd",
	Failed: "failed",
} as const;
export type ReseatStatus = (typeof ReseatStatus)[keyof typeof ReseatStatus];

export interface GroupReseat {
	agent_id: string;
	/** Null when the agent's group list could not be read. */
	group_id: string | null;
	status: ReseatStatus;
	/** Why the group was not reseated; absent when it was. */
	reason?: string;
	/**
	 * True when the seat was retaken but the resync epoch's escrow is not stored
	 * yet: the agent's first send into the group is refused until a later drain
	 * uploads it.
	 */
	escrow_pending: boolean;
	/** The escrow work done on this reseat's behalf. */
	escrow: EscrowReport;
}

const outcome = (
	agentId: string,
	groupId: string | null,
	status: ReseatStatus,
	reason?: string,
	escrowPending = false,
	escrow: EscrowReport = emptyReport(),
): GroupReseat => ({
	agent_id: agentId,
	group_id: groupId,
	status,
	...(reason === undefined ? {} : { reason }),
	escrow_pending: escrowPending,
	escrow,
});

/**
 * One external-commit attempt: take the GroupInfo, replace the leaf found by the
 * agent's credential, post, then adopt and escrow the resync epoch. Local state
 * is adopted only after the server accepts the commit.
 */
async function reseatOnce(actor: PeerActor, groupId: string): Promise<GroupReseat> {
	const { agentId, client, configDir, extraHeaders } = actor;
	const info = await fetchGroupInfo(client, groupId, extraHeaders);
	if (!info.group_info) {
		return outcome(
			agentId,
			groupId,
			ReseatStatus.NoGroupInfo,
			"the group has published no GroupInfo",
		);
	}
	await admitGroupPeers(actor, groupId);
	const mls = openPeerMlsClient(actor);
	const groupInfo = info.group_info;
	const group = await admitRefusingRotatedLeaf(actor, mls, groupId, () =>
		mls.resyncFromGroupInfo(mlsFromBase64(groupInfo)),
	);
	const bundle = group.lastCommit();
	if (!bundle) throw new Error("the resync produced no commit");
	await postMlsCommit(actor, groupId, bundle, [], extraHeaders);
	const escrow = await settleAfterJoin(actor, groupId, group);
	noteMlsStateChanged(configDir, agentId, groupId);
	return outcome(
		agentId,
		groupId,
		ReseatStatus.Reseated,
		undefined,
		!epochEscrowStored(actor, groupId, group.epoch()),
		escrow,
	);
}

/**
 * Take this agent's own seat back in one group: one external-commit attempt,
 * rebuilt once from a fresh GroupInfo when the commit loses the epoch race (the
 * group advanced between the GroupInfo fetch and the post). A second loss, and
 * every other failure, is thrown. Resolves with the reseat, or with
 * {@link ReseatStatus.NoGroupInfo} when the group has published nothing to
 * commit against.
 */
export async function retakeSeat(actor: PeerActor, groupId: string): Promise<GroupReseat> {
	return retryOnEpochConflict(() => reseatOnce(actor, groupId));
}

/**
 * Reseat one agent in one closed group, reporting what happened as a status
 * rather than throwing: see {@link retakeSeat}.
 */
export async function reseatGroup(
	client: HttpClient,
	configDir: string,
	agentId: string,
	groupId: string,
): Promise<GroupReseat> {
	const extraHeaders = { [ACTING_AGENT_HEADER]: agentId };
	try {
		return await retakeSeat({ configDir, agentId, client, extraHeaders }, groupId);
	} catch (err) {
		if (mlsErrorCode(err) === MLS_ERR_NO_SEAT_TO_REPLACE) {
			return outcome(
				agentId,
				groupId,
				ReseatStatus.NotSeated,
				"the group's roster no longer holds this agent",
			);
		}
		return outcome(
			agentId,
			groupId,
			isMlsRotatedLeaf(err) ? ReseatStatus.NeedsReAdd : ReseatStatus.Failed,
			err instanceof Error ? err.message : String(err),
		);
	}
}

/**
 * Reseat each restored agent in every closed group the server lists with that
 * agent seated. A group that cannot be reseated is reported, never retried; an
 * agent whose group list cannot be read is reported once, with no group id.
 */
export async function reseatClosedGroups(
	client: HttpClient,
	configDir: string,
	agentIds: readonly string[],
): Promise<GroupReseat[]> {
	const reseats: GroupReseat[] = [];
	for (const agentId of agentIds) {
		let groups: GroupRead[];
		try {
			groups = await seatedMlsGroups(client, agentId);
		} catch (err) {
			reseats.push(
				outcome(
					agentId,
					null,
					ReseatStatus.Failed,
					err instanceof Error ? err.message : String(err),
				),
			);
			continue;
		}
		for (const group of groups) {
			reseats.push(await reseatGroup(client, configDir, agentId, group.id));
		}
	}
	return reseats;
}
