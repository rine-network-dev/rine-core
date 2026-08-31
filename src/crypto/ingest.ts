import { agentIdFromKid, fromBase64Url } from "./keys.js";
import type { MessageDecryptResult } from "./message.js";
import type { SenderKeyState } from "./sender-keys.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
	senderKeysRetired,
} from "./sender-keys-helpers.js";

/**
 * Auto-ingest a sender key distribution from a decrypted message.
 * Only ingests if the message is a `rine.v1.sender_key_distribution`,
 * the signature was verified, the group's keys have not been retired, and the
 * key ID is not already known.
 *
 * Returns true if a new key was ingested.
 *
 * This is the ONE place any surface takes delivery of a sender key — the CLI's
 * `read` and `stream`, rine-mcp's decrypt path and
 * `fetchAndIngestPendingSKDistributions` all route through here — so the
 * REFUSAL belongs here and nowhere else. A second copy would be the thing that
 * drifts. Spending a retirement is the other half and cannot live here: it turns
 * on who the server says the group holds now, and this function is local, has no
 * client and learns the group id only after the DM is open. That half is
 * `fetchAndIngestPendingSKDistributions`, which every read path calls.
 */
export function ingestSenderKeyDistribution(
	configDir: string,
	agentId: string,
	messageType: string,
	result: MessageDecryptResult,
): boolean {
	if (messageType !== "rine.v1.sender_key_distribution") return false;

	// Only ingest sender keys from verified senders to prevent poisoning. A
	// refused envelope is unverified AND carries no text — group key material is
	// never taken from a message whose author the recipient cannot place.
	if (!result.verified || result.plaintext === undefined) return false;

	try {
		const dist = JSON.parse(result.plaintext) as {
			group_id: string;
			sender_key_id: string;
			chain_key: string;
			message_index: number;
			sender_agent_id: string;
		};
		// A group this agent retired never takes key material again, however the
		// distribution reaches it. The DMs that carried these keys are still in the
		// inbox after a leave, so without this the wipe holds only until the next
		// group read that misses. A malformed group id throws out of
		// `validatePathId` into the catch below, so the refusal fails closed.
		if (senderKeysRetired(configDir, agentId, dist.group_id)) return false;

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
		saveSenderKeyState(configDir, agentId, dist.group_id, [
			...existing,
			newState,
		]);
		return true;
	} catch {
		return false;
	}
}
