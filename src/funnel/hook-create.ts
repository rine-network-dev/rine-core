// rine Funnel hook allocation, shared by every surface that creates a hook.
// The HMAC secret is generated client-side and saved BEFORE the POST, because
// the allocation is not idempotent; the POST carries only the hook name and the
// tier, never the secret. A failed POST puts the local secret file back the way
// it was: the prior secret of an existing hook survives, and a new name leaves
// no orphan secret behind.

import type { FunnelTier, HookCreated } from "../api-types.js";
import type { ApiPoster } from "../spiffe.js";
import {
	deleteHookSecret,
	generateHookSecret,
	loadHookSecret,
	saveHookSecret,
} from "./hook-key-store.js";

export interface HookCreateResult {
	/** The server's record of the allocated hook. */
	created: HookCreated;
	/** The new 64-hex HMAC secret; shown to the operator once. */
	secret: string;
	/** Where the secret is stored on this machine. */
	storedAt: string;
}

/**
 * Allocate a funnel hook for `agentId`. With no `tier` the POST sends `null`,
 * which lets the server resolve the default for the org's trust tier.
 */
export async function createHook(
	client: ApiPoster,
	configDir: string,
	agentId: string,
	name: string,
	tier?: FunnelTier,
): Promise<HookCreateResult> {
	const prior = loadHookSecret(configDir, agentId, name);
	const secret = generateHookSecret();
	const storedAt = saveHookSecret(configDir, agentId, name, secret);
	try {
		const created = (await client.post(`/agents/${agentId}/funnel/hooks`, {
			hook_name: name,
			tier: tier ?? null,
		})) as HookCreated;
		return { created, secret, storedAt };
	} catch (err) {
		try {
			if (prior === undefined) deleteHookSecret(configDir, agentId, name);
			else saveHookSecret(configDir, agentId, name, prior);
		} catch {
			// The POST error is the one the caller acts on; a secret file that
			// cannot be put back is a local leftover, never a reason to hide why
			// the create failed.
		}
		throw err;
	}
}
