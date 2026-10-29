/**
 * Whether the key this device holds is the key the agent publishes now.
 *
 * Two things must never run from a device holding a superseded generation: a
 * self-update, which would only move a leaf to that stale key, and a key-package
 * drain, which would replace the agent's published pool with packages the
 * server refuses. Both ask this one question, chain-verified, so no copy of the
 * predicate exists.
 */
import { equalBytes } from "./crypto/bytes.js";
import { loadAgentKeys } from "./crypto/keys.js";
import { fetchVerifiedBatchKeys } from "./mls-admission-tree.js";
import type { PeerActor } from "./mls-allowed.js";

/**
 * True when the disk keys' generation and MLS public key equal the agent's
 * chain-verified current ones. A read that fails propagates: a caller that
 * cannot tell "not current" from an outage must not report either.
 */
export async function diskKeyIsCurrent(actor: PeerActor): Promise<boolean> {
	const { configDir, agentId, client, extraHeaders } = actor;
	const keys = loadAgentKeys(configDir, agentId);
	const verified = (await fetchVerifiedBatchKeys(client, [agentId], extraHeaders)).get(agentId);
	return (
		verified !== undefined &&
		verified.keyGen === keys.keyGen &&
		equalBytes(verified.mls, keys.mls.publicKey)
	);
}
