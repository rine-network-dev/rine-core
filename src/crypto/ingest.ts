import { agentIdFromKid, fromBase64Url, validatePathId } from "./keys.js";
import type { MessageDecryptResult } from "./message.js";
import type { SenderKeyState } from "./sender-keys.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
	senderKeysRetired,
} from "./sender-keys-helpers.js";

/**
 * Bytes in a chain key. It is an HMAC-SHA256 ratchet root and every honest
 * producer mints exactly this many (`generateSenderKey`), but HMAC accepts a key
 * of any length — so nothing downstream would ever notice a 0-byte or a 1 MiB
 * one, and the reader would store what it was sent.
 */
const CHAIN_KEY_SIZE = 32;

/**
 * The largest index the wire format can name: it carries the message index in a
 * big-endian uint32, so a state above this can never be reached by a real
 * message, and one below zero can never be reached at all.
 */
const MAX_MESSAGE_INDEX = 0xffffffff;

/**
 * One UUID out of the payload, spelled the one way every other reader spells it.
 *
 * 🔴 Lower-casing is not cosmetic. `validatePathId` accepts either case, and the
 * group id from a distribution becomes a FILENAME — while the retirement marker
 * and the group read cache both lower-case theirs, and every honest reader passes
 * the server's own lower-case spelling. Leaving the payload's spelling intact gave
 * a single logical group one state-file namespace per casing: a file no reader
 * looks in, no leave-time cleanup unlinks, and whose contents do not count as
 * "already held" against the canonical file.
 *
 * Twin: `_canonical_id` in `rine-sdk/src/rine/_crypto/sk_distribution.py`.
 */
function canonicalId(value: unknown, label: string): string {
	if (typeof value !== "string") {
		throw new Error(`Invalid ${label}: expected a UUID string`);
	}
	validatePathId(value, label);
	return value.toLowerCase();
}

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
	if (messageType !== "rine.v1.sender_key_distribution") return false;

	// Only ingest sender keys from verified senders to prevent poisoning. A
	// refused envelope is unverified AND carries no text — group key material is
	// never taken from a message whose author the recipient cannot place.
	if (!result.verified || result.plaintext === undefined) return false;

	try {
		// Every field below `sender_agent_id` — which is read from the verified kid
		// and never from here — is the sender's own plaintext, chosen freely by any
		// agent that can DM this one. `unknown` rather than the shape it claims,
		// because the claim is the thing under attack.
		const dist = JSON.parse(result.plaintext) as {
			group_id: unknown;
			sender_key_id: unknown;
			chain_key: unknown;
			message_index?: unknown;
		};
		// A group this agent retired never takes key material again, however the
		// distribution reaches it. The DMs that carried these keys are still in the
		// inbox after a leave, so without this the wipe holds only until the next
		// group read that misses. A malformed group id throws out of
		// `validatePathId` into the catch below, so the refusal fails closed.
		const groupId = canonicalId(dist.group_id, "group id");
		if (senderKeysRetired(configDir, agentId, groupId)) return false;

		if (typeof dist.chain_key !== "string") {
			throw new Error("Invalid chain_key: expected a base64url string");
		}
		const chainKey = fromBase64Url(dist.chain_key);
		if (chainKey.length !== CHAIN_KEY_SIZE) {
			throw new Error(
				`Invalid chain_key: expected ${CHAIN_KEY_SIZE} bytes, got ${chainKey.length}`,
			);
		}
		// `=== undefined`, not `??`: absent means "starts at zero" and is the only
		// spelling an honest producer emits, while an explicit `null` is a value the
		// sender chose. Coalescing the two would make this the one field where TS
		// accepts what `_crypto/sk_distribution.py` refuses.
		const messageIndex = dist.message_index === undefined ? 0 : dist.message_index;
		if (
			!Number.isInteger(messageIndex) ||
			(messageIndex as number) < 0 ||
			(messageIndex as number) > MAX_MESSAGE_INDEX
		) {
			throw new Error(
				`Invalid message_index: ${String(messageIndex)} is not a uint32 the wire can carry`,
			);
		}
		const senderAgentId = agentIdFromKid(result.senderKid);
		const senderKeyId = canonicalId(dist.sender_key_id, "sender key id");

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
		// does: `agentIdFromKid` preserves whatever case the signer put in its kid.
		// Twin: `alreadyHeld` in `rine-sdk/src/rine/_crypto/sk_distribution.py`.
		const existing = loadSenderKeyStates(configDir, agentId, groupId);
		const sender = senderAgentId.toLowerCase();
		if (
			existing.some(
				(s) =>
					s.senderKeyId === senderKeyId &&
					s.senderAgentId.toLowerCase() === sender,
			)
		) {
			return false;
		}
		const newState: SenderKeyState = {
			senderKeyId,
			groupId,
			senderAgentId,
			chainKey,
			messageIndex: messageIndex as number,
		};
		saveSenderKeyState(configDir, agentId, groupId, [...existing, newState]);
		return true;
	} catch {
		return false;
	}
}
