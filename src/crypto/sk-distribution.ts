import { fromBase64Url, validatePathId } from "./keys.js";
import type { SenderKeyState } from "./sender-keys.js";

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

/** The group a distribution names, in the spelling everything else uses. Throws on a malformed id. */
export function distributionGroupId(payload: Record<string, unknown>): string {
	return canonicalId(payload.group_id, "group id");
}

/**
 * One peer's ratchet state, built from a distribution payload, or null when the
 * payload cannot be trusted. Pure: no disk, no retirement check, no dedup.
 *
 * Every field except the two arguments is the sender's own plaintext, chosen
 * freely by any agent that can DM the reader — `unknown` rather than the shape it
 * claims, because the claim is the thing under attack. `senderId` is the identity
 * the envelope's signature established, never `payload.sender_agent_id`.
 *
 * Twin: `sender_key_state_from_distribution` in
 * `rine-sdk/src/rine/_crypto/sk_distribution.py`.
 */
export function parseSenderKeyDistribution(
	payload: Record<string, unknown>,
	groupId: string,
	senderId: string,
): SenderKeyState | null {
	try {
		if (typeof payload.chain_key !== "string") return null;
		const chainKey = fromBase64Url(payload.chain_key);
		if (chainKey.length !== CHAIN_KEY_SIZE) return null;
		// `=== undefined`, not `??`: absent means "starts at zero" and is the only
		// spelling an honest producer emits, while an explicit `null` is a value the
		// sender chose. Coalescing the two would make this the one field where TS
		// accepts what `_crypto/sk_distribution.py` refuses.
		const messageIndex =
			payload.message_index === undefined ? 0 : payload.message_index;
		// Known divergence from Python: `JSON.parse` turns the literal `5.0` into
		// the integer 5 before this code sees it, so TS accepts an index that
		// `json.loads` (a float) makes Python refuse. The source token is not
		// recoverable here; the divergence is recorded in the hostile parity divergences.
		if (
			typeof messageIndex !== "number" ||
			!Number.isInteger(messageIndex) ||
			messageIndex < 0 ||
			messageIndex > MAX_MESSAGE_INDEX
		) {
			return null;
		}
		return {
			senderKeyId: canonicalId(payload.sender_key_id, "sender key id"),
			groupId,
			senderAgentId: senderId,
			chainKey,
			messageIndex,
		};
	} catch {
		return null;
	}
}
