import { agentIdFromKid, fromBase64Url } from "./keys.js";
import type { DecryptResult } from "./message.js";
import type { SenderKeyState } from "./sender-keys.js";
import { loadSenderKeyStates, saveSenderKeyState } from "./sender-keys-helpers.js";

/**
 * Auto-ingest a sender key distribution from a decrypted message.
 * Only ingests if the message is a `rine.v1.sender_key_distribution`,
 * the signature was verified, and the key ID is not already known.
 *
 * Returns true if a new key was ingested.
 */
export function ingestSenderKeyDistribution(
	configDir: string,
	agentId: string,
	messageType: string,
	result: DecryptResult,
): boolean {
	if (messageType !== "rine.v1.sender_key_distribution") return false;

	// Only ingest sender keys from verified senders to prevent poisoning
	if (!result.verified) return false;

	try {
		const dist = JSON.parse(result.plaintext) as {
			group_id: string;
			sender_key_id: string;
			chain_key: string;
			message_index: number;
			sender_agent_id: string;
		};
		const existing = loadSenderKeyStates(configDir, agentId, dist.group_id);
		if (existing.some((s) => s.senderKeyId === dist.sender_key_id)) {
			return false;
		}
		const newState: SenderKeyState = {
			senderKeyId: dist.sender_key_id,
			groupId: dist.group_id,
			senderAgentId: agentIdFromKid(result.senderKid),
			chainKey: fromBase64Url(dist.chain_key),
			messageIndex: dist.message_index,
		};
		saveSenderKeyState(configDir, agentId, dist.group_id, [...existing, newState]);
		return true;
	} catch {
		return false;
	}
}
