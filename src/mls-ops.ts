import type { CommitBundle, MlsGroup } from "@rine-network/mls";
import { claimKeyPackages, mlsFromBase64, mlsInit } from "./crypto/mls-api.js";
import { mlsGroupIdBytes, openMlsClient, openMlsGroup } from "./crypto/mls.js";
import type { HttpClient } from "./http.js";
import { type Joiner, postMlsCommit } from "./mls-commit.js";
import { replenishMlsKeyPackages } from "./mls-keypackages.js";

export { syncMlsGroup } from "./mls-ops-sync.js";
export type { MlsSyncResult } from "./mls-ops-sync.js";
export { externalJoinMlsGroup, processMlsWelcomes } from "./mls-ops-join.js";
export {
	ensureMlsKeyPackages,
	publishMlsKeyPackages,
	replenishMlsKeyPackages,
	MLS_KEY_PACKAGE_LOW_WATER,
	MLS_KEY_PACKAGE_MAX_BATCH,
	MLS_KEY_PACKAGE_TARGET,
} from "./mls-keypackages.js";
export type { MlsKeyPackageStatus } from "./mls-keypackages.js";
export {
	cutoverMlsKeyPackages,
	drainAndRepublishMlsKeyPackages,
	needsMlsKeyPackageCutover,
} from "./mls-cutover.js";
export type { MlsCutoverResult } from "./mls-cutover.js";

/**
 * Founding members admitted per commit.
 *
 * The native core admits every founding member in a single commit, so this is
 * not about epochs — it is about the request body. One `POST /mls/commit`
 * carries the commit plus one Welcome per member, and neither the server nor
 * the proxy in front of it declares a body limit. Measured on the post-quantum
 * suite, a 17-member founding commit is ~57 kB base64 with a ~33 kB Welcome
 * each, so the body grows roughly with the square of the batch. 16 keeps a
 * founding POST under ~600 kB; a larger group is founded across several commits
 * rather than in one body nobody has sized.
 */
const MLS_FOUNDING_MEMBERS_PER_COMMIT = 16;

function commitBatches(joiners: Joiner[]): Joiner[][] {
	if (joiners.length === 0) return [[]];
	const batches: Joiner[][] = [];
	for (let i = 0; i < joiners.length; i += MLS_FOUNDING_MEMBERS_PER_COMMIT) {
		batches.push(joiners.slice(i, i + MLS_FOUNDING_MEMBERS_PER_COMMIT));
	}
	return batches;
}

/**
 * Initialize an MLS group: create the group with every member who has published
 * a key package admitted in the founding commit, and post that commit plus its
 * welcomes to the server.
 *
 * Local state is saved only after the server accepts a commit, so a rejected
 * commit leaves no forked state behind.
 */
export async function initMlsGroup(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number; membersAdded: number }> {
	// Every MLS operation doubles as the heartbeat that keeps this agent's own
	// key package inventory above its low-water mark, so the agent never becomes
	// un-addable to a future group.
	await replenishMlsKeyPackages(configDir, agentId, client);
	const initResp = await mlsInit(client, groupId, extraHeaders);

	const agentIdLower = agentId.toLowerCase();
	const joiners: Joiner[] = [];
	for (const member of initResp.members) {
		if (!member.has_key_package) continue;
		if (member.agent_id.toLowerCase() === agentIdLower) continue;
		const claimed = await claimKeyPackages(client, member.agent_id);
		const first = claimed.packages[0];
		if (!first) continue;
		joiners.push({
			agentId: member.agent_id,
			keyPackage: mlsFromBase64(first),
		});
	}

	const mls = openMlsClient(configDir, agentId);
	let group: MlsGroup | null = null;
	let epoch = 0;
	let membersAdded = 0;
	for (const batch of commitBatches(joiners)) {
		const keyPackages = batch.map((j) => j.keyPackage);
		let bundle: CommitBundle;
		if (group === null) {
			group = mls.createGroupWithMembers(mlsGroupIdBytes(groupId), keyPackages);
			const init = group.lastCommit();
			if (!init) {
				throw new Error(
					`MLS group ${groupId} was created without an init commit`,
				);
			}
			bundle = init;
		} else {
			bundle = group.addMembers(keyPackages);
		}
		epoch = await postMlsCommit(
			client,
			groupId,
			group,
			bundle,
			batch,
			extraHeaders,
		);
		group.save();
		membersAdded += batch.length;
	}

	return { epoch, membersAdded };
}

/**
 * Add a single member to an existing MLS group by claiming their key package
 * and posting an add commit + welcome.
 */
export async function addMlsGroupMember(
	configDir: string,
	agentId: string,
	groupId: string,
	memberAgentId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number }> {
	const group = openMlsGroup(configDir, agentId, groupId);

	// Heartbeat replenishment of OUR inventory (see initMlsGroup). The member's
	// own inventory is theirs to replenish — a client can only publish key
	// packages for an agent whose signing key it holds.
	await replenishMlsKeyPackages(configDir, agentId, client);
	const claimed = await claimKeyPackages(client, memberAgentId);
	const first = claimed.packages[0];
	if (!first) {
		throw new Error(`No key packages available for ${memberAgentId}`);
	}

	const joiner: Joiner = {
		agentId: memberAgentId,
		keyPackage: mlsFromBase64(first),
	};
	const bundle = group.addMember(joiner.keyPackage);
	const epoch = await postMlsCommit(
		client,
		groupId,
		group,
		bundle,
		[joiner],
		extraHeaders,
	);
	group.save();

	return { epoch };
}

/**
 * Remove a member from an MLS group by leaf index and post the remove commit.
 * The evicted member reads no message committed after this epoch.
 */
export async function removeMlsGroupMember(
	configDir: string,
	agentId: string,
	groupId: string,
	leafIndex: number,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number }> {
	const group = openMlsGroup(configDir, agentId, groupId);
	const bundle = group.removeMember(leafIndex);
	const epoch = await postMlsCommit(
		client,
		groupId,
		group,
		bundle,
		[],
		extraHeaders,
	);
	group.save();
	return { epoch };
}
