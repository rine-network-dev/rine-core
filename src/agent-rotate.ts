import { agentRotateRequest } from "./agent-body.js";
import type { AgentRead } from "./api-types.js";
import { type CustodyDirs, loadCustody } from "./custody.js";
import {
	KeyChainError,
	pinsFor,
	saveAgentKeys,
	verifyKeyChain,
} from "./crypto/index.js";
import { getPublishedKeys } from "./crypto/published-keys.js";
import { heldKeyGen } from "./recover.js";
import type { ApiPoster } from "./spiffe.js";

export interface ApiGetPoster extends ApiPoster {
	get(path: string): Promise<unknown>;
}

/**
 * Rotate an agent to its next key generation. The branch and the current
 * generation come from `GET /agents/{id}/keys`, which is chain-verified like any
 * peer read before either is trusted: the response must belong to this org's
 * custody and may not report a generation below the one this host holds. The new
 * keys are derived from the org's custody for that branch, so no new secret is
 * stored beyond the leaf files.
 */
export async function performKeyRotation(
	client: ApiGetPoster,
	dirs: CustodyDirs,
	agentId: string,
): Promise<AgentRead> {
	const current = verifyKeyChain(
		await getPublishedKeys(client, agentId),
		{ agentId },
		pinsFor(client),
	);
	const custody = loadCustody(dirs, current.branch);
	if (current.orgId !== custody.orgId) throw new KeyChainError("own_org_pin");
	const held = heldKeyGen(dirs.configDir, agentId);
	if (held !== undefined && current.keyGen < held) {
		throw new KeyChainError("key_gen_rollback");
	}
	const { body, keys } = agentRotateRequest(custody, agentId, current.keyGen + 1);
	const agent = (await client.post(`/agents/${agentId}/keys`, body)) as AgentRead;
	saveAgentKeys(dirs.configDir, agentId, keys);
	return agent;
}
