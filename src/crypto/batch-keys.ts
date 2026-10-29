import type { AgentKeysResponse } from "../api-types.js";
import { type VerifiedAgentKeys, verifyKeyChain } from "./key-chain.js";
import { pinsFor } from "./key-pins.js";

/**
 * Ids one `GET /agents/keys` accepts. The server refuses 201 in a single call
 * ("Maximum 200 IDs per request"), so anything past 200 members has to be
 * fetched in chunks — asking for all of them at once made a group send fail
 * outright at 201 members, before a single distribution was attempted.
 *
 * Both readers of that route chunk on it: `fetchVerifiedBatchKeys` in
 * `mls-admission-tree.ts`, and the sender-key distribution's own fetch in
 * `sender-key-ops.ts`. It is not the batch claim's cap (`MLS_CLAIM_AGENTS_MAX`),
 * which bounds a different route and equals this one only by coincidence.
 */
export const BATCH_KEYS_MAX_IDS = 200;

/**
 * Chain-verify every entry of a batch `GET /agents/keys` response (every
 * consumer verifies, no fallback). An entry that fails the chain or a pin is
 * dropped, so its agent reads as one that published no keys; the batch is
 * server-supplied, so a failure here is a refusal to use that key and never an
 * error for the rest of the batch.
 */
export function verifyBatchKeys(
	client: object,
	keys: Record<string, AgentKeysResponse> | undefined,
): Map<string, VerifiedAgentKeys> {
	const pins = pinsFor(client);
	const verified = new Map<string, VerifiedAgentKeys>();
	for (const [agentId, response] of Object.entries(keys ?? {})) {
		try {
			verified.set(agentId, verifyKeyChain(response, { agentId }, pins));
		} catch {
			// Dropped: an entry that does not verify is never used.
		}
	}
	return verified;
}
