// Recovery from the 24-word phrase: the agents' keys are rebuilt,
// then each restored agent is reseated in its closed groups (`recover-reseat.ts`).
import { orgSigner } from "./assertion.js";
import type { AgentKeysResponse, AgentRead, ListResponse } from "./api-types.js";
import { cacheToken } from "./config.js";
import type { CustodyDirs } from "./custody.js";
import {
	type AgentKeys,
	type BranchKeys,
	agentKeysFromDerived,
	deriveAgent,
	deriveBranch,
	deriveOrg,
	entropyFromPhrase,
	loadAgentKeys,
	orgWords,
	saveAgentKeys,
} from "./crypto/index.js";
import { pinsFor } from "./crypto/key-pins.js";
import { RineApiError, namesClockSkew } from "./errors.js";
import { HttpClient } from "./http.js";
import { type GapMarker, listGapMarkers } from "./mls-escrow-gap-list.js";
import { assertFreshOwnerDir } from "./owner.js";
import { principalString } from "./principal.js";
import { saveOwnerIdentity } from "./recover-owner.js";
import { type GroupReseat, reseatClosedGroups } from "./recover-reseat.js";
import { mismatchReason } from "./recover-verify.js";
import { fetchOAuthToken } from "./token.js";

export const AgentRecoveryStatus = {
	Restored: "restored",
	Mismatch: "mismatch",
} as const;
export type AgentRecoveryStatus =
	(typeof AgentRecoveryStatus)[keyof typeof AgentRecoveryStatus];

export interface AgentRecovery {
	agent_id: string;
	name: string;
	branch: string;
	key_gen: number;
	status: AgentRecoveryStatus;
	/** Why a mismatching agent was refused; absent when restored. */
	reason?: string;
}

export interface RecoveryReport {
	org_id: string;
	org_words: string;
	branches: string[];
	agents: AgentRecovery[];
	/** One row per closed group a restored agent held a seat in. */
	closed_groups: GroupReseat[];
	/** Every escrow gap marker on disk for the restored agents, not only this run's. */
	gap_markers: GapMarker[];
	/** What the report must tell the user. */
	notes: readonly string[];
}

export const NO_ORG_FOR_PHRASE =
	"no org matches this phrase: check each word, or the org was erased";

export const RECOVERY_NOTES: readonly string[] = [
	"Closed-group seats are restored from the current epoch on. Your local copy of earlier closed-group messages is gone; the org reader still shows every escrowed epoch.",
	"Sender-key open groups redistribute keys on the next send.",
	"Wallet keys are random and are not recovered.",
	"1:1 history at every generation is readable again.",
];

/**
 * A server that rolls recovery back reports an old generation as current while
 * still holding the newer ones; the next generation answering 200 proves it.
 */
async function servesNewerGeneration(
	client: HttpClient,
	agentId: string,
	keyGen: number,
): Promise<boolean> {
	try {
		await client.get(`/agents/${agentId}/keys`, { gen: keyGen + 1 });
		return true;
	} catch (err) {
		if (err instanceof RineApiError && err.status === 404) return false;
		throw err;
	}
}

/** The generation of the leaf keys already on this device for `agentId`, if any. */
export function heldKeyGen(configDir: string, agentId: string): number | undefined {
	try {
		return loadAgentKeys(configDir, agentId).keyGen;
	} catch {
		return undefined;
	}
}

/** An agent's report row, with the keys to write once every agent has been checked. */
interface CheckedAgent {
	recovery: AgentRecovery;
	keys?: AgentKeys;
}

/**
 * Check one agent against the phrase without writing anything. A server that
 * answers with an older generation than this device already holds would roll
 * the agent back onto superseded keys, so it is refused.
 */
async function checkAgent(
	client: HttpClient,
	configDir: string,
	orgId: string,
	branches: Map<string, BranchKeys>,
	agent: AgentRead,
): Promise<CheckedAgent> {
	const server = (await client.get(
		`/agents/${agent.id}/keys`,
	)) as AgentKeysResponse;
	const base = {
		agent_id: agent.id,
		name: agent.name,
		branch: server.branch,
		key_gen: server.key_gen,
	};
	const refused = (reason: string): CheckedAgent => ({
		recovery: { ...base, status: AgentRecoveryStatus.Mismatch, reason },
	});
	const branch = branches.get(server.branch);
	if (branch === undefined) return refused("branch is not derivable from this phrase");
	const held = heldKeyGen(configDir, agent.id);
	if (held !== undefined && server.key_gen < held) {
		return refused("the server's key generation is older than the one held on this device");
	}
	if (await servesNewerGeneration(client, agent.id, server.key_gen)) {
		return refused("the server reports a current key generation below one it also serves");
	}
	const derived = deriveAgent(branch, agent.id, server.key_gen);
	const reason = mismatchReason(orgId, branch, derived, server);
	if (reason !== undefined) return refused(reason);
	return {
		recovery: { ...base, status: AgentRecoveryStatus.Restored },
		keys: agentKeysFromDerived(derived),
	};
}

/**
 * Rebuild an org and its agents from the recovery phrase. `onOrgWords` runs before
 * any network call so the user can check the words against a record. The phrase is
 * never echoed: no error or report string contains any of it.
 */
export async function performRecovery(
	apiUrl: string,
	dirs: CustodyDirs,
	profile: string,
	phrase: string,
	onOrgWords?: (words: string) => void,
): Promise<RecoveryReport> {
	assertFreshOwnerDir(dirs.ownerDir, dirs.configDir);
	const root = entropyFromPhrase(phrase);
	const org = deriveOrg(root);
	const words = orgWords(org.orgId);
	onOrgWords?.(words);

	const signer = orgSigner(org);
	let token: { access_token: string; expires_in: number };
	try {
		token = await fetchOAuthToken(apiUrl, signer);
	} catch (err) {
		if (
			err instanceof RineApiError &&
			err.status === 401 &&
			!namesClockSkew(err.status, err.body)
		) {
			throw new Error(NO_ORG_FOR_PHRASE);
		}
		throw err;
	}
	const client = new HttpClient({
		apiUrl,
		tokenFn: async () => token.access_token,
		canRefresh: false,
		ownIdentity: { orgId: org.orgId, agentIds: [] },
	});

	const { branches: views } = (await client.get("/orgs/me/branches")) as {
		branches: { name: string; revoked_at: string | null }[];
	};
	const { items } = (await client.get("/agents")) as ListResponse<AgentRead>;
	const derivedBranches = new Map(
		views.map((view) => [view.name, deriveBranch(org, view.name)]),
	);

	// Every agent is checked before any key is written, so a failure partway
	// through leaves the device's keys as they were.
	const checked: CheckedAgent[] = [];
	for (const agent of items) {
		checked.push(
			await checkAgent(client, dirs.configDir, org.orgId, derivedBranches, agent),
		);
	}
	for (const { recovery, keys } of checked) {
		if (keys !== undefined) saveAgentKeys(dirs.configDir, recovery.agent_id, keys);
	}
	const agents = checked.map((entry) => entry.recovery);

	const restored = agents
		.filter((agent) => agent.status === AgentRecoveryStatus.Restored)
		.map((agent) => agent.agent_id);
	for (const agentId of restored) pinsFor(client).ownAgentIds.add(agentId);
	const closedGroups = await reseatClosedGroups(client, dirs.configDir, restored);

	saveOwnerIdentity(dirs.ownerDir, profile, root, org.orgId);
	cacheToken(dirs.ownerDir, principalString(signer.principal), token);

	return {
		org_id: org.orgId,
		org_words: words,
		branches: views.map((view) => view.name),
		agents,
		closed_groups: closedGroups,
		gap_markers: restored.flatMap((agentId) => listGapMarkers(dirs.configDir, agentId)),
		notes: RECOVERY_NOTES,
	};
}
