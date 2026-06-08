import {
	addMemberToMlsGroup,
	createMlsGroup,
	generateMlsKeyPackage,
} from "./crypto/mls.js";
import {
	claimKeyPackages,
	mlsCommit,
	mlsFromBase64,
	mlsInit,
	mlsToBase64,
	uploadKeyPackages,
} from "./crypto/mls-api.js";
import { loadMlsState, saveMlsState, savePrivateKeyPackages } from "./crypto/mls-state.js";
import { loadAgentKeys } from "./crypto/keys.js";
import type { HttpClient } from "./http.js";

export { processMlsWelcomes, removeMlsGroupMember, syncMlsGroup } from "./mls-ops-sync.js";
export { externalJoinMlsGroup } from "./mls-ops-join.js";

/**
 * Generate and upload MLS key packages for an agent, enabling other agents
 * to add them to MLS groups.
 */
export async function publishMlsKeyPackages(
	configDir: string,
	agentId: string,
	client: HttpClient,
	count = 10,
): Promise<{ stored: number }> {
	const keys = loadAgentKeys(configDir, agentId);
	const packages: string[] = [];
	const privatePackages: Array<{ ref: Uint8Array; publicBlob: Uint8Array; privateBlob: Uint8Array }> = [];
	for (let i = 0; i < count; i++) {
		const kp = await generateMlsKeyPackage(keys.signing.privateKey);
		packages.push(mlsToBase64(kp.publicBlob));
		privatePackages.push({ ref: kp.keyPackageRef, publicBlob: kp.publicBlob, privateBlob: kp.privateBlob });
	}
	savePrivateKeyPackages(configDir, agentId, privatePackages);
	return uploadKeyPackages(client, agentId, packages);
}

/**
 * Initialize an MLS group: create the group state, add all members who have
 * uploaded key packages, and post the initial commit + welcomes to the server.
 */
export async function initMlsGroup(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number; membersAdded: number }> {
	const initResp = await mlsInit(client, groupId, extraHeaders);
	const keys = loadAgentKeys(configDir, agentId);

	const { stateBlob, groupInfo, commitBlob, epoch: createEpoch } = await createMlsGroup(
		keys.signing.privateKey,
	);

	const agentIdLower = agentId.toLowerCase();
	const eligibleMembers = initResp.members.filter(
		(m) =>
			m.has_key_package && m.agent_id.toLowerCase() !== agentIdLower,
	);

	let currentState = stateBlob;
	let currentCommit = commitBlob;
	// Track the GroupInfo for the group's CURRENT epoch. Each add advances the
	// epoch, so we must publish the LATEST GroupInfo (single-use per epoch,
	// RFC 9420 §12.4.3.2) so the next external joiner targets the right epoch.
	let currentGroupInfo = groupInfo;
	// The epoch is owned by the crypto state: createMlsGroup leaves us at epoch 1,
	// and each add advances it by exactly 1. We send the committed epoch so the
	// server can compare-and-swap its authoritative per-group epoch.
	let currentEpoch = createEpoch;
	const welcomes: { agent_id: string; welcome: string }[] = [];

	for (const member of eligibleMembers) {
		const claimed = await claimKeyPackages(client, member.agent_id);
		const firstPackage = claimed.packages[0];
		if (!firstPackage) continue;
		const kpBlob = mlsFromBase64(firstPackage);
		const result = await addMemberToMlsGroup(currentState, kpBlob);
		welcomes.push({
			agent_id: member.agent_id,
			welcome: mlsToBase64(result.welcomeBlob),
		});
		currentState = result.updatedState;
		currentCommit = result.commitBlob;
		currentGroupInfo = result.groupInfo;
		currentEpoch = result.epoch;
	}

	const commitResp = await mlsCommit(
		client,
		groupId,
		{
			commit: mlsToBase64(currentCommit),
			welcomes,
			group_info: mlsToBase64(currentGroupInfo),
			cipher_suite: 0x0001,
			epoch: currentEpoch,
		},
		extraHeaders,
	);

	const epoch = commitResp.epoch ?? currentEpoch;
	saveMlsState(configDir, agentId, groupId, currentState, {
		groupId,
		epoch,
		cipherSuite: 0x0001,
	});

	return { epoch, membersAdded: welcomes.length };
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
	const stored = loadMlsState(configDir, agentId, groupId);
	if (!stored) throw new Error(`No MLS state for group ${groupId}`);

	const claimed = await claimKeyPackages(client, memberAgentId);
	const firstPackage = claimed.packages[0];
	if (!firstPackage) {
		throw new Error(`No key packages available for ${memberAgentId}`);
	}
	const kpBlob = mlsFromBase64(firstPackage);

	const { commitBlob, welcomeBlob, updatedState, groupInfo, epoch: commitEpoch } =
		await addMemberToMlsGroup(stored.stateBlob, kpBlob);

	const commitResp = await mlsCommit(
		client,
		groupId,
		{
			commit: mlsToBase64(commitBlob),
			welcomes: [{ agent_id: memberAgentId, welcome: mlsToBase64(welcomeBlob) }],
			group_info: mlsToBase64(groupInfo),
			epoch: commitEpoch,
		},
		extraHeaders,
	);

	const epoch = commitResp.epoch ?? commitEpoch;
	saveMlsState(configDir, agentId, groupId, updatedState, {
		...stored.metadata,
		epoch,
	});

	return { epoch };
}

