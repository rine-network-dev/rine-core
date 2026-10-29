import type { AllowedIdentities } from "@rine-network/mls";
import { fetchAgentKeys } from "./crypto/agent-keys.js";
import { ascii } from "./crypto/bytes.js";
import { KeyChainError } from "./crypto/key-chain.js";
import { MLS_ERR_ALLOWED_GENERATION_CONFLICT, mlsErrorCode } from "./crypto/mls-errors.js";
import { admissionKey } from "./mls-admission.js";
import type { PeerActor } from "./mls-allowed.js";

/**
 * A peer's history generation, or `null` when the server's answer does not
 * chain-verify.
 *
 * A generation that fails the chain is skipped, never fatal: an old leaf can
 * still sit in a tree this device has to read, but a generation the server
 * cannot prove is not one this client will accept. Any other error (network,
 * malformed response) is a real failure and propagates.
 */
async function verifiedGeneration(
	actor: PeerActor,
	agentId: string,
	gen: number,
) {
	try {
		const { keys } = await fetchAgentKeys(actor.client, agentId, { gen });
		return keys;
	} catch (err) {
		if (err instanceof KeyChainError) return null;
		throw err;
	}
}

/**
 * Insert every chain-verified history generation of one agent, below `keyGen`.
 * A generation that does not verify is skipped (see {@link verifiedGeneration}),
 * and so is one whose leaf key equals another generation of the same agent: the
 * server refuses that at rotation, and if one reaches a client anyway it must
 * not abort the admission of the agent's other, valid generations. The set keeps
 * the first pair it was given, which is the current one. Every other error from
 * an insert propagates.
 */
export async function admitHistory(
	actor: PeerActor,
	allowed: AllowedIdentities,
	agentId: string,
	keyGen: number,
): Promise<void> {
	const id = admissionKey(agentId);
	for (let gen = 0; gen < keyGen; gen++) {
		const history = await verifiedGeneration(actor, agentId, gen);
		if (!history) continue;
		try {
			allowed.insert(ascii(id), history.mls, gen);
		} catch (err) {
			if (mlsErrorCode(err) !== MLS_ERR_ALLOWED_GENERATION_CONFLICT) throw err;
		}
	}
}
