import { agentCreateRequest } from "./agent-body.js";
import type { AgentRead } from "./api-types.js";
import { type Custody, type CustodyDirs, loadCustody } from "./custody.js";
import { type AgentKeys, saveAgentKeys } from "./crypto/index.js";
import { AgentIdMismatchError } from "./errors.js";
import { publishMlsKeyPackages } from "./mls-ops.js";
import { MAIN_BRANCH, PrincipalKind, principalString } from "./principal.js";
import { addProfileIfAbsent } from "./profiles.js";
import {
	type ApiPoster,
	type VerifyIdentityResult,
	verifyNewAgent,
} from "./spiffe.js";

export type CreatedAgent = AgentRead & {
	identity?: VerifyIdentityResult;
	identityError?: string;
};

/**
 * What every create path does once the server has accepted the agent: refuse an
 * agent created under another id than the one minted (the keys and certificate
 * are bound to the minted id, so nothing is saved), save the leaf keys, publish
 * the first MLS KeyPackages, and name the agent in a runtime profile when
 * `profile` is free. The keys are derived, so a crash before the save
 * loses nothing: `rine org recover` rebuilds the files.
 *
 * KeyPackages are best-effort: the agent works on sender-key groups without them
 * and they can be republished later, so a failure must never abort creation.
 * Only `.post` is used on `client`.
 */
export async function persistCreatedAgent(
	client: ApiPoster,
	dirs: CustodyDirs,
	profile: string,
	custody: Custody,
	agent: { id: string; poll_url?: string | null },
	mintedId: string,
	keys: AgentKeys,
): Promise<void> {
	if (agent.id !== mintedId) throw new AgentIdMismatchError(mintedId, agent.id);
	saveAgentKeys(dirs.configDir, agent.id, keys);
	try {
		await publishMlsKeyPackages(dirs.configDir, agent.id, client);
	} catch {
		// non-fatal — agent is usable; KeyPackages can be published later
	}
	addProfileIfAbsent(dirs.configDir, profile, {
		org_id: custody.orgId,
		principal: principalString({ kind: PrincipalKind.Agent, agentId: agent.id }),
		branch: custody.branch.name,
		agent_id: agent.id,
		...(agent.poll_url ? { poll_url: agent.poll_url } : {}),
	});
}

/**
 * Create an agent under `params.branch` (default `main`): derive its generation-0
 * keys from the org's custody and POST the client-minted id with the keys and cert.
 * `profile` names the runtime profile written for the new agent, if that name is free.
 */
export async function performAgentCreation(
	client: ApiPoster,
	dirs: CustodyDirs,
	profile: string,
	params: {
		name: string;
		branch?: string;
		humanOversight?: boolean;
		unlisted?: boolean;
		/**
		 * Run SPIFFE identity verification after the agent is created. Auto-enabled
		 * by the caller when `SPIFFE_ENDPOINT_SOCKET` is present or `--verify-identity`
		 * is passed. The verification result is returned alongside the agent.
		 */
		verifyIdentity?: boolean;
		/** Caller-supplied JWT-SVID for the verification step (see verifyIdentitySpiffe). */
		svid?: string;
		log?: (message: string) => void;
	},
): Promise<CreatedAgent> {
	const custody = loadCustody(dirs, params.branch ?? MAIN_BRANCH);
	const mintedId = crypto.randomUUID();
	const { body, keys } = agentCreateRequest(custody, mintedId, params);
	const agent = (await client.post("/agents", body)) as CreatedAgent;
	await persistCreatedAgent(client, dirs, profile, custody, agent, mintedId, keys);
	return { ...agent, ...(await verifyNewAgent(client, agent.id, params)) };
}
