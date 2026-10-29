import { SENDER_KEY_DISTRIBUTION_TYPE } from "../control-frames.js";
import { parseSigningKid } from "./keys.js";
import type { MessageDecryptResult } from "./message.js";
import {
	distributionGroupId,
	parseSenderKeyDistribution,
} from "./sk-distribution.js";
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
 *
 * 🔴 It takes no lock on the state file it appends to, and it must stay
 * SYNCHRONOUS for that to be sound: with no `await` between the load and the
 * save, nothing else in this process can run between them, so two ingests
 * cannot both read the same array and each write one key. Adding an `await`
 * anywhere in this body — or making it `async` — reopens exactly the lost
 * update that made a group's history come back sealed. What protects it from
 * the OTHER direction, a lock holder that saves a snapshot taken before its own
 * network call, is `sender-keys-store.ts`'s `mergeSenderKeyStates`.
 */
export function ingestSenderKeyDistribution(
	configDir: string,
	agentId: string,
	messageType: string,
	result: MessageDecryptResult,
): boolean {
	if (messageType !== SENDER_KEY_DISTRIBUTION_TYPE) return false;

	// Only ingest sender keys from verified senders to prevent poisoning. A
	// refused envelope is unverified AND carries no text — group key material is
	// never taken from a message whose author the recipient cannot place.
	if (!result.verified || result.plaintext === undefined) return false;

	try {
		// Every field below `sender_agent_id` — which is read from the verified kid
		// and never from here — is the sender's own plaintext, chosen freely by any
		// agent that can DM this one. `unknown` rather than the shape it claims,
		// because the claim is the thing under attack.
		const dist = JSON.parse(result.plaintext) as Record<string, unknown>;
		// A group this agent retired never takes key material again, however the
		// distribution reaches it. The DMs that carried these keys are still in the
		// inbox after a leave, so without this the wipe holds only until the next
		// group read that misses. A malformed group id throws out of
		// `validatePathId` into the catch below, so the refusal fails closed.
		const groupId = distributionGroupId(dist);
		if (senderKeysRetired(configDir, agentId, groupId)) return false;

		const senderAgentId = parseSigningKid(result.senderKid).agentId;
		const newState = parseSenderKeyDistribution(dist, groupId, senderAgentId);
		if (newState === null) return false;

		// 🔴 Per SENDER, never per key id alone. A sender key id is minted by whoever
		// sends it, so a check that asks only "do I hold this id" makes the first
		// distribution to claim an id the owner of that slot for good: an attacker
		// who reads a peer's id out of its own copy of that peer's distribution, then
		// sends one of its own, silently displaces the genuine key. The inbox lists
		// newest-first and the scan imposes no ordering, so the later DM is processed
		// first and no race is needed. The peer's group posts then refuse to open,
		// permanently — re-scanning re-skips the DM that would have fixed it — and
		// the refusal reads as a crypto regression. Agent ids compare
		// case-insensitively, as the own-row test in `sender-key-ops.ts` already
		// does: `parseSigningKid` preserves whatever case the signer put in its kid.
		// Twin: `alreadyHeld` in `rine-sdk/src/rine/_crypto/sk_distribution.py`.
		const existing = loadSenderKeyStates(configDir, agentId, groupId);
		const sender = senderAgentId.toLowerCase();
		if (
			existing.some(
				(s) =>
					s.senderKeyId === newState.senderKeyId &&
					s.senderAgentId.toLowerCase() === sender,
			)
		) {
			return false;
		}
		saveSenderKeyState(configDir, agentId, groupId, [...existing, newState]);
		return true;
	} catch {
		return false;
	}
}
