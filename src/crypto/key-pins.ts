// The pins a client keeps across key responses. The chain
// verifier that feeds them lives in key-chain.ts.
import { KeyChainError, type VerifiedAgentKeys } from "./key-chain.js";

/**
 * The pins a client keeps across key responses. `check`
 * records nothing when it throws, so a refused response leaves the pins intact.
 */
export class KeyPins {
	ownOrgId: string | undefined;
	readonly ownAgentIds: Set<string> = new Set();
	private readonly agentOrg = new Map<string, string>();
	private readonly agentGen = new Map<string, number>();
	private readonly handleOrg = new Map<string, string>();

	check(verified: VerifiedAgentKeys, opts: { current: boolean }): void {
		const { agentId, orgId, keyGen } = verified;
		if (
			this.ownOrgId !== undefined &&
			this.ownAgentIds.has(agentId) &&
			orgId !== this.ownOrgId
		) {
			throw new KeyChainError("own_org_pin");
		}
		const pinnedOrg = this.agentOrg.get(agentId);
		if (pinnedOrg !== undefined && pinnedOrg !== orgId) {
			throw new KeyChainError("agent_org_pin");
		}
		const highest = this.agentGen.get(agentId);
		if (opts.current && highest !== undefined && keyGen < highest) {
			throw new KeyChainError("key_gen_rollback");
		}
		this.agentOrg.set(agentId, orgId);
		if (highest === undefined || keyGen > highest) {
			this.agentGen.set(agentId, keyGen);
		}
	}

	/** Warn-only handle pin: returns the previous org id when the handle moved. */
	noteHandleOrg(handle: string, orgId: string): string | undefined {
		const previous = this.handleOrg.get(handle);
		this.handleOrg.set(handle, orgId);
		return previous !== undefined && previous !== orgId ? previous : undefined;
	}
}

const pinsByClient = new WeakMap<object, KeyPins>();

/** One {@link KeyPins} per client object, unless the client was given a shared set. */
export function pinsFor(client: object): KeyPins {
	const existing = pinsByClient.get(client);
	if (existing !== undefined) return existing;
	const pins = new KeyPins();
	pinsByClient.set(client, pins);
	return pins;
}

/**
 * Make `client` use `pins`. A caller that spawns a short-lived client per
 * operation holds one {@link KeyPins} and hands it to each, so a peer's
 * `agent_id -> org_id` and highest `key_gen` stay pinned across operations
 * instead of resetting with every client.
 */
export function sharePins(client: object, pins: KeyPins): void {
	pinsByClient.set(client, pins);
}
