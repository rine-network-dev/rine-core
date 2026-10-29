// The own-org pin source: what a client is told about itself, read off
// the config dir rather than off the wire. `HttpClientOptions.ownIdentity`
// seeds the key-chain pins, and the escrow read needs the same
// answer to know which org a branch escrow key must belong to.
import type { ResolvedAuth } from "./auth-resolve.js";
import { localAgentIds } from "./custody.js";
import { seedOwnPins } from "./http.js";
import { loadProfiles } from "./profiles.js";

/**
 * The caller's own org and agent ids, in the shape `HttpClientOptions.ownIdentity`
 * takes. `auth` is the already-resolved principal, so a client that memoises its
 * resolution does not read the config dir twice.
 */
export function ownIdentityFor(
	configDir: string,
	auth: Pick<ResolvedAuth, "orgId"> | undefined,
): { orgId: string; agentIds: string[] } | undefined {
	if (auth?.orgId === undefined) return undefined;
	return { orgId: auth.orgId, agentIds: localAgentIds(configDir) };
}

/**
 * Seed `client`'s key-chain pins with the caller's own org and agent ids, so a
 * peer-key response that places one of our agents under another org is refused
 * instead of trusted on first use. `resolve` is called here, not by the caller,
 * because resolving can throw: an org claim the key material contradicts makes
 * every request fail with that refusal at the token step, so there is nothing
 * to pin and this returns quietly. A principal with no resolved org pins nothing.
 */
export function pinOwnIdentity(
	client: object,
	configDir: string,
	resolve: () => Pick<ResolvedAuth, "orgId"> | undefined,
): void {
	let own: ReturnType<typeof ownIdentityFor>;
	try {
		own = ownIdentityFor(configDir, resolve());
	} catch {
		return;
	}
	if (own) seedOwnPins(client, own);
}

/**
 * The org an agent of this config dir belongs to: the `org_id` of the profile
 * whose `agent_id` is `agentId`, else the sole `org_id` every profile agrees
 * on, else undefined.
 *
 * The fallback exists because a config dir that acts as one org's agent may
 * carry no profile naming that agent — an owner-dir profile names the org
 * principal, not the agent — and a dir whose profiles all agree on one org is
 * unambiguous about which org its agents are in. Two profiles naming different
 * orgs is a dir that cannot answer, and guessing would pin the wrong org.
 */
export function orgIdOfAgent(
	configDir: string,
	agentId: string,
): string | undefined {
	const entries = Object.values(loadProfiles(configDir));
	const named = entries.find((entry) => entry.agent_id === agentId);
	if (named !== undefined) return named.org_id;
	const orgIds = new Set(entries.map((entry) => entry.org_id));
	return orgIds.size === 1 ? [...orgIds][0] : undefined;
}
