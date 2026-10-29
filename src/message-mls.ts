/**
 * The MLS half of a group message: sealing an application message, and opening
 * one against this agent's local group state, recovering that state once when
 * the read finds it behind or missing.
 */
import { ACTING_AGENT_HEADER } from "./actor.js";
import { type GroupRow, authenticateEnvelope } from "./crypto/group-envelope.js";
import { recordGroupRead } from "./crypto/group-read-cache.js";
import { encodeEnvelope } from "./crypto/envelope.js";
import { loadAgentKeys, signingKid, toBase64Url } from "./crypto/keys.js";
import type { DecryptResult, EncryptResult } from "./crypto/message.js";
import { loadMlsState } from "./crypto/mls-state.js";
import { isRecoverableMlsRead, openMlsGroup } from "./crypto/mls.js";
import { signMessage } from "./crypto/sign.js";
import { ENCRYPTION_VERSIONS } from "./encryption-versions.js";
import { openPeerMlsGroup } from "./mls-allowed.js";
import { catchUpMlsGroup } from "./mls-catchup.js";
import { externalJoinMlsGroup } from "./mls-external-join.js";
import { processMlsWelcomes } from "./mls-ops-join.js";
import { syncMlsGroup } from "./mls-ops-sync.js";
import { admitSenderHistory } from "./mls-read-history.js";

/**
 * Encrypt a payload for an MLS-active group.
 *
 * Mirrors `encryptGroupMessage` (`crypto/sender-key-seal.ts`) but uses MLS
 * instead of sender keys. The signed inner envelope (kid + Ed25519 signature +
 * plaintext) is the MLS application-message payload, so
 * {@link readMlsGroupMessage} authenticates it with `authenticateEnvelope`
 * (`crypto/group-envelope.ts`), as the sender-key reader does. The MLS
 * ciphertext is prefixed with `VERSION_MLS` (0x04) and base64url-encoded to
 * match the version-byte dispatch in `decryptGroupMessage` (`message-group.ts`).
 *
 * State is keyed by the rine group UUID (`groupId`), the same identifier used by
 * `decryptGroupMessage` and the MLS API routes — never the opaque `mls_group_id`
 * latch or the MLS-internal group id.
 */
export async function encryptMlsGroupMessage(
	configDir: string,
	senderAgentId: string,
	groupId: string,
	payload: unknown,
): Promise<EncryptResult> {
	const group = openMlsGroup(configDir, senderAgentId, groupId);

	const keys = loadAgentKeys(configDir, senderAgentId);
	const plaintext = new TextEncoder().encode(JSON.stringify(payload));
	const kid = signingKid(senderAgentId, keys.keyGen);
	const signature = signMessage(
		keys.signing.privateKey,
		{ kind: "GroupSig", groupId },
		plaintext,
	);
	const envelope = encodeEnvelope(kid, signature, plaintext);

	// The native core frames the payload with VERSION_MLS itself and records the
	// envelope in its own self-read cache, so the sender can read back a message
	// its ratchet has already advanced past.
	const ciphertext = group.encryptApplicationMessage(envelope);
	group.save();

	return {
		encrypted_payload: toBase64Url(ciphertext),
		encryption_version: ENCRYPTION_VERSIONS.MLS_V1,
		sender_signing_kid: kid,
	};
}

async function decryptMlsMessage(row: GroupRow): Promise<DecryptResult> {
	const {
		configDir,
		recipientAgentId,
		groupId,
		encrypted: payload,
		client,
		fromAgentId,
		createdAt,
	} = row;
	// The shared allowed set, not the device's own keys alone: the history
	// admitted below must be the set this handle's decrypt consults.
	const actor = {
		configDir,
		agentId: recipientAgentId,
		client,
		extraHeaders: { [ACTING_AGENT_HEADER]: recipientAgentId },
	};
	const group = openPeerMlsGroup(actor, groupId);
	await admitSenderHistory(actor, group, payload, fromAgentId);
	// A message this member sent comes back from the core's self-read cache; the
	// payload carries its own version tag, so it is passed through whole.
	const { envelope } = group.decryptApplicationMessage(payload);
	group.save();
	// The refusal inside lands AFTER the ratchet is saved: a refused message
	// consumes its key exactly like an accepted one, so retrying it reveals
	// nothing.
	const result = await authenticateEnvelope(
		envelope,
		client,
		fromAgentId,
		groupId,
		createdAt,
	);
	recordGroupRead(configDir, recipientAgentId, groupId, payload, envelope);
	return result;
}

/**
 * Open an MLS group row, then bring this agent's copy of the group up to date.
 *
 * A read that works runs the rate-limited catch-up and reports what it did. A
 * read that fails on a recoverable error gets one recovery — Welcomes, then an
 * external join when there is still no state, then a sync — and one retry.
 */
export async function readMlsGroupMessage(row: GroupRow): Promise<DecryptResult> {
	const { configDir, recipientAgentId, groupId, client } = row;
	// Every group-scoped MLS route below resolves its actor with
	// `get_acting_agent`, which falls back to "the org's single active agent"
	// and answers 422 "Multiple active agents" when the org has two or more
	// (`api/agent_identity.py`). The reader is named right here, so it is
	// pinned on every one of them. Without it the eager catch-up is a silent
	// no-op for a multi-agent org — it swallows failures by contract and has
	// already stamped its 60 s gate — and the recovery calls below fail loudly
	// on a header this function could always have supplied.
	const asReader = { [ACTING_AGENT_HEADER]: recipientAgentId };
	let decrypted: DecryptResult | null = null;
	try {
		decrypted = await decryptMlsMessage(row);
	} catch (err) {
		// Sync-then-retry covers both "behind" (epoch sync) and "no state"
		// (external join). A self-read miss and a local store failure are not
		// recoverable this way and surface as themselves.
		if (!isRecoverableMlsRead(err)) throw err;
	}
	if (decrypted !== null) {
		// A read that worked is the ordinary case, and the catch-up here is what
		// keeps a member who only ever reads successfully from drifting behind the
		// group's epoch. It is rate-limited and never throws, so the answer above
		// is returned either way, carrying what the catch-up did.
		const caughtUp = await catchUpMlsGroup(
			configDir,
			recipientAgentId,
			groupId,
			client,
			asReader,
		);
		return caughtUp === null ? decrypted : { ...decrypted, catchUp: caughtUp };
	}
	// One-shot recovery: install pending Welcomes (establishes state for
	// newly-joined groups) then sync pending commits (advances epoch).
	// If neither produces local state, attempt an external join as last
	// resort (open-enrollment groups where the original join didn't
	// establish MLS state).
	// Scoped, because a refusal names ONE group and this recovery establishes
	// ONE group's state: without `forGroup` a substituted Welcome for any other
	// group aborts this decrypt, which is a group the refusal has nothing to do
	// with. The Python twin scopes the same call the same way
	// (`_mls/join.py` `install_mls_state`).
	await processMlsWelcomes(configDir, recipientAgentId, client, {
		forGroup: groupId,
	});
	if (!loadMlsState(configDir, recipientAgentId, groupId)) {
		await externalJoinMlsGroup(
			configDir,
			recipientAgentId,
			groupId,
			client,
			asReader,
		);
	}
	const recovered = await syncMlsGroup(
		configDir,
		recipientAgentId,
		groupId,
		client,
		asReader,
	);
	// Recovery can have just established local MLS state. Nothing is reset
	// here: `processMlsWelcomes` and `externalJoinMlsGroup` invalidate at the
	// establishment itself, so the guard below already sees the new answer.
	//
	// This sync is the same fact as the catch-up's on the ordinary path — the
	// work a read did to make itself possible — so it is reported the same
	// way. A recovering read is the one most likely to have applied a large
	// backlog, and the one where a reader most wants to know it.
	return {
		...(await decryptMlsMessage(row)),
		catchUp: recovered,
	};
}
