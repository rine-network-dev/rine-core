import { ACTING_AGENT_HEADER } from "../actor.js";
import type { HttpClient } from "../http.js";
import { externalJoinMlsGroup, processMlsWelcomes } from "../mls-ops-join.js";
import { catchUpMlsGroup } from "../mls-catchup.js";
import { type MlsSyncResult, syncMlsGroup } from "../mls-ops-sync.js";
import { type SenderKeyChange, verifyEnvelopeSender } from "./agent-keys.js";
import { decodeEnvelope, encodeEnvelope } from "./envelope.js";
import { lookupGroupRead, recordGroupRead } from "./group-read-cache.js";
import { open, seal } from "./hpke.js";
import { VERSION_HYBRID, openHybrid, sealHybrid } from "./hybrid.js";
import {
	type AgentKeys,
	type PqJWK,
	fromBase64Url,
	loadAgentKeys,
	pqPublicKeyToJWK,
	signingPublicKeyToJWK,
	toBase64Url,
} from "./keys.js";
import { assertNoMlsDowngrade } from "./mls-downgrade.js";
import { loadMlsState } from "./mls-state.js";
import { VERSION_MLS, isRecoverableMlsRead, openMlsGroup } from "./mls.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
	senderKeysRetired,
} from "./sender-keys-helpers.js";
import {
	type SenderKeyState,
	deriveMessageKey,
	openGroup,
	sealGroup,
} from "./sender-keys.js";
import { signPayload } from "./sign.js";

export interface EncryptResult {
	encrypted_payload: string;
	encryption_version: string;
	sender_signing_kid: string;
	/**
	 * A second ciphertext of the same signed envelope, sealed to the SENDER's own
	 * encryption key(s), enabling sender self-read of 1:1 messages. Only produced
	 * by {@link encryptMessage} (1:1 `hpke-v1`/`hpke-hybrid-v1`); the group encrypt
	 * paths leave it `undefined` (groups already self-read via client caches).
	 * Hybrid when the sender publishes a PQ key, classical otherwise — independent
	 * of the recipient's negotiated version (it seals to the sender's keys).
	 */
	self_encrypted_payload?: string;
}

/**
 * Outcome of checking a message's inner envelope.
 *
 * - `verified` — signed by the agent the server says sent the message.
 * - `invalid` — the signature does not check out against that agent's key.
 * - `sender-mismatch` — the signature is well-formed but names a different agent
 *   than the one the server authenticated as the sender.
 * - `unverifiable` — the verdict could not be reached (key lookup failed, or no
 *   server-authenticated sender was available for the row).
 */
export type VerificationStatus =
	"verified" | "invalid" | "sender-mismatch" | "unverifiable";

/**
 * True when the status means the content must not be trusted as authentic:
 * either the bytes do not match the signature, or they are attributed to the
 * wrong agent. `unverifiable` is deliberately excluded — it is a transient
 * lookup outcome, not a verdict, and callers surface it as such.
 *
 * Every authenticity comparison goes through this predicate; an equality check
 * against a single member silently accepts the others.
 */
export function isAuthenticityFailure(status: VerificationStatus): boolean {
	return status === "invalid" || status === "sender-mismatch";
}

/**
 * A group message refused because its author cannot be trusted, carrying the
 * verdict that produced it. A group decrypt throws where the 1:1 path degrades,
 * so without the verdict on the error a caller's `catch` cannot tell an active
 * misattribution from a transient key-lookup miss. The message text tells the
 * two authenticity failures apart for an operator reading a log.
 */
export class GroupAuthenticityError extends Error {
	constructor(public readonly verificationStatus: VerificationStatus) {
		super(
			verificationStatus === "sender-mismatch"
				? "Envelope sender does not match the message sender"
				: "Sender signature verification failed",
		);
		this.name = "GroupAuthenticityError";
	}
}

/**
 * Refuse an inauthentic group message. Unlike the 1:1 path, a group transcript
 * never carries a degraded turn — tampered bytes and a misattributed author both
 * throw a {@link GroupAuthenticityError}.
 */
function assertGroupAuthenticity(status: VerificationStatus): void {
	if (!isAuthenticityFailure(status)) return;
	throw new GroupAuthenticityError(status);
}

export interface DecryptResult {
	plaintext: string;
	senderKid: string;
	verified: boolean;
	verificationStatus: VerificationStatus;
	/**
	 * Set when the sender's published signing key no longer matches the copy this
	 * client had cached — a rotation the recipient may want to notice rather than
	 * silently accept.
	 */
	keyChanged?: SenderKeyChange;
	/**
	 * What the MLS catch-up behind this read actually did: the epoch it left
	 * this agent on, the commits it applied to get there, and whether one of
	 * them evicted this agent.
	 *
	 * Present only on an MLS row whose read ran a sync — absent on a 1:1 row, a
	 * sender-key row, a replay served from the read cache, and a read whose
	 * catch-up the 60 s floor declined or whose sync failed. Absent therefore
	 * means "nothing was done", never "you are current".
	 *
	 * It reports the work, not the distance: asking how far behind this agent
	 * still is costs a round trip per read, and the explicit catch-up verb is
	 * where that question is asked.
	 */
	catchUp?: MlsSyncResult;
}

/**
 * A decrypt that withheld its own content because the envelope's author cannot
 * be trusted. The verdict and the kid the envelope named still come back — an
 * operator has to be able to say WHY a row is closed — but the text does not, so
 * bytes attributed to an agent that did not sign them never reach a transcript,
 * a model or a payment decision.
 */
export interface RefusedDecrypt extends Omit<DecryptResult, "plaintext"> {
	plaintext?: undefined;
}

/**
 * What the 1:1 decrypt returns: the opened message, or a refusal carrying the
 * verdict in place of the text. Narrow with {@link isRefusedDecrypt} before
 * reading content — the group paths refuse the same content by throwing, so this
 * union is where the 1:1 half of that one refusal shows up in the type system.
 */
export type MessageDecryptResult = DecryptResult | RefusedDecrypt;

/**
 * True when a 1:1 decrypt refused to hand back its content: the author is one of
 * the {@link isAuthenticityFailure} verdicts, or the text is absent for any other
 * reason. Narrowing on this predicate is how a caller reaches `plaintext` as a
 * `string` — writing the two terms out by hand at each site is how one of them
 * gets dropped, which is the same trap {@link isAuthenticityFailure} exists to
 * close one level down.
 */
export function isRefusedDecrypt(
	result: MessageDecryptResult,
): result is RefusedDecrypt {
	return (
		isAuthenticityFailure(result.verificationStatus) ||
		result.plaintext === undefined
	);
}

// fetchRecipientKeys / verifyEnvelopeSender (and the per-agent key cache the
// latter reads through) live in ./agent-keys.js; re-exported here so existing
// "./message.js" import sites keep working.
export {
	fetchAgentKeys,
	fetchRecipientKeys,
	sameAgentId,
	verifyEnvelopeSender,
} from "./agent-keys.js";
export type {
	RecipientKeys,
	SenderKeyChange,
	SenderVerification,
} from "./agent-keys.js";

function signingKid(agentId: string): string {
	return `rine:${agentId}`;
}

export async function encryptMessage(
	configDir: string,
	senderAgentId: string,
	recipientEncryptionPk: Uint8Array,
	payload: unknown,
	recipientPqEncryptionPk?: Uint8Array,
): Promise<EncryptResult> {
	const keys = loadAgentKeys(configDir, senderAgentId);
	const plaintext = new TextEncoder().encode(JSON.stringify(payload));
	const kid = signingKid(senderAgentId);
	const signature = signPayload(keys.signing.privateKey, plaintext);
	const envelope = encodeEnvelope(kid, signature, plaintext);

	// Self-seal: a second ciphertext of the same envelope, sealed to the SENDER's
	// own key(s), so the sender can later self-read its own 1:1 message. The
	// self-seal negotiates on the SENDER's PQ capability (hybrid when the sender
	// publishes an ML-KEM key, classical otherwise) — independent of the recipient
	// version below. Purely additive: the recipient output is unchanged.
	const selfSealed = keys.pqEncryption
		? await sealHybrid(
				keys.encryption.publicKey,
				keys.pqEncryption.publicKey,
				envelope,
			)
		: await seal(keys.encryption.publicKey, envelope);
	const self_encrypted_payload = toBase64Url(selfSealed);

	// Auto-negotiate: use hybrid PQ when the recipient publishes an ML-KEM key,
	// otherwise fall back to classical HPKE. hpke-v1 output stays byte-for-byte.
	if (recipientPqEncryptionPk && recipientPqEncryptionPk.length > 0) {
		const encrypted = await sealHybrid(
			recipientEncryptionPk,
			recipientPqEncryptionPk,
			envelope,
		);
		return {
			encrypted_payload: toBase64Url(encrypted),
			encryption_version: "hpke-hybrid-v1",
			sender_signing_kid: kid,
			self_encrypted_payload,
		};
	}

	const encrypted = await seal(recipientEncryptionPk, envelope);
	return {
		encrypted_payload: toBase64Url(encrypted),
		encryption_version: "hpke-v1",
		sender_signing_kid: kid,
		self_encrypted_payload,
	};
}

/**
 * Open a 1:1 ciphertext with the recipient's own keys and report on its sender.
 *
 * `fromAgentId` is the server-authenticated `from_agent_id` of the row being
 * opened — for a self-sealed blob a sender re-reads, that is the caller's own
 * agent id. It must never be taken from the envelope, the plaintext or a
 * client-supplied header: those are the inputs the check exists to distrust.
 *
 * Authenticity is reported rather than thrown, but it is never returned as
 * readable content: an envelope signed by an agent other than the one the server
 * attributes the row to comes back as
 * `{ verified: false, verificationStatus: "sender-mismatch" }` with NO
 * `plaintext`, so a caller renders a closed row and says why. The group paths
 * refuse the same content by throwing; both derive the refusal from
 * {@link isAuthenticityFailure}, so gate on that rather than on a single status
 * value.
 */
export async function decryptMessage(
	configDir: string,
	recipientAgentId: string,
	encryptedPayloadB64: string,
	client: HttpClient,
	fromAgentId: string,
): Promise<MessageDecryptResult> {
	const keys = loadAgentKeys(configDir, recipientAgentId);
	const encrypted = fromBase64Url(encryptedPayloadB64);

	// Dispatch on the version byte: 0x03 → hybrid PQ, otherwise classical HPKE.
	let envelopeBytes: Uint8Array;
	if (encrypted[0] === VERSION_HYBRID) {
		if (!keys.pqEncryption) {
			throw new Error(
				"received hpke-hybrid-v1 message but recipient has no PQ encryption key",
			);
		}
		envelopeBytes = await openHybrid(
			keys.encryption.privateKey,
			keys.pqEncryption.privateKey,
			encrypted,
		);
	} else {
		envelopeBytes = await open(keys.encryption.privateKey, encrypted);
	}
	const decoded = decodeEnvelope(envelopeBytes);

	const verification = await verifyEnvelopeSender(decoded, client, fromAgentId);
	// Withhold before decoding: content whose author cannot be trusted is not
	// content, so the caller gets the verdict and nothing to render.
	if (isAuthenticityFailure(verification.verificationStatus)) {
		return { senderKid: decoded.kid, ...verification };
	}

	const plaintext = new TextDecoder("utf-8", { fatal: true }).decode(
		decoded.payload,
	);
	return { plaintext, senderKid: decoded.kid, ...verification };
}

export async function encryptGroupMessage(
	configDir: string,
	senderAgentId: string,
	groupId: string,
	senderKeyState: SenderKeyState,
	payload: unknown,
): Promise<{ result: EncryptResult; updatedState: SenderKeyState }> {
	const keys = loadAgentKeys(configDir, senderAgentId);
	const plaintext = new TextEncoder().encode(JSON.stringify(payload));
	const kid = signingKid(senderAgentId);

	// Derive the message key before sealGroup consumes the chain key, so it can be
	// cached for sender self-read.
	const selfReadKey = deriveMessageKey(senderKeyState.chainKey).messageKey;
	const selfReadIndex = senderKeyState.messageIndex;

	const { encryptedPayload, updatedState } = await sealGroup(
		keys.signing.privateKey,
		kid,
		senderKeyState,
		plaintext,
	);

	// Cache the message key so the sender can decrypt their own message.
	// Without this, the ratchet advances past the index and the key is lost.
	updatedState.skippedKeys = {
		...(updatedState.skippedKeys ?? {}),
		[selfReadIndex]: toBase64Url(selfReadKey),
	};
	selfReadKey.fill(0);

	const allStates = loadSenderKeyStates(configDir, senderAgentId, groupId);
	const otherStates = allStates.filter(
		(s) => s.senderKeyId !== updatedState.senderKeyId,
	);
	saveSenderKeyState(configDir, senderAgentId, groupId, [
		...otherStates,
		updatedState,
	]);

	return {
		result: {
			encrypted_payload: toBase64Url(encryptedPayload),
			encryption_version: "sender-key-v1",
			sender_signing_kid: kid,
		},
		updatedState,
	};
}

/**
 * Encrypt a payload for an MLS-active group.
 *
 * Mirrors {@link encryptGroupMessage} but uses MLS instead of sender keys.
 * The signed inner envelope (kid + Ed25519 signature + plaintext) is the MLS
 * application-message payload, so {@link decryptGroupMessage}'s 0x04 branch can
 * run `decodeEnvelope` + `verifyEnvelopeSender` unchanged. The MLS ciphertext is
 * prefixed with {@link VERSION_MLS} (0x04) and base64url-encoded to match the
 * version-byte dispatch in `decryptGroupMessage`.
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
	const kid = signingKid(senderAgentId);
	const signature = signPayload(keys.signing.privateKey, plaintext);
	const envelope = encodeEnvelope(kid, signature, plaintext);

	// The native core frames the payload with VERSION_MLS itself and records the
	// envelope in its own self-read cache, so the sender can read back a message
	// its ratchet has already advanced past.
	const ciphertext = group.encryptApplicationMessage(envelope);
	group.save();

	return {
		encrypted_payload: toBase64Url(ciphertext),
		encryption_version: "mls-v1",
		sender_signing_kid: kid,
	};
}

async function decryptMlsMessage(
	configDir: string,
	recipientAgentId: string,
	groupId: string,
	payload: Uint8Array,
	client: HttpClient,
	fromAgentId: string,
): Promise<DecryptResult> {
	const group = openMlsGroup(configDir, recipientAgentId, groupId);
	// A message this member sent comes back from the core's self-read cache; the
	// payload carries its own version tag, so it is passed through whole.
	const { envelope } = group.decryptApplicationMessage(payload);
	group.save();
	// The refusal inside lands AFTER the ratchet is saved: a refused message
	// consumes its key exactly like an accepted one, so retrying it reveals
	// nothing.
	const result = await authenticateEnvelope(envelope, client, fromAgentId);
	recordGroupRead(configDir, recipientAgentId, groupId, payload, envelope);
	return result;
}

/**
 * Turn a signed inner envelope into a decrypt result, refusing anything the
 * row's server-authenticated sender did not sign.
 *
 * The one place a group envelope becomes an answer, whichever regime unwrapped
 * it and whether it came from a live ratchet or from the read cache. That
 * matters for the cache: a replay is verified exactly like a first read, so
 * nothing about the row's attribution is remembered from the read before.
 */
async function authenticateEnvelope(
	innerEnvelope: Uint8Array,
	client: HttpClient,
	fromAgentId: string,
): Promise<DecryptResult> {
	const decoded = decodeEnvelope(innerEnvelope);
	const plaintext = new TextDecoder("utf-8", { fatal: true }).decode(
		decoded.payload,
	);
	const verification = await verifyEnvelopeSender(decoded, client, fromAgentId);
	assertGroupAuthenticity(verification.verificationStatus);
	return { plaintext, senderKid: decoded.kid, ...verification };
}

/**
 * Open a group ciphertext (sender-key or MLS) and refuse anything inauthentic.
 *
 * `fromAgentId` is the row's server-authenticated `from_agent_id`, checked against
 * the envelope's own claim of authorship. Unlike the 1:1 path this one throws
 * rather than degrades, so a group transcript can never hold content attributed
 * to an agent that did not sign it.
 */
export async function decryptGroupMessage(
	configDir: string,
	recipientAgentId: string,
	groupId: string,
	encryptedPayloadB64: string,
	client: HttpClient,
	fromAgentId: string,
): Promise<DecryptResult> {
	const states = loadSenderKeyStates(configDir, recipientAgentId, groupId);
	const stateMap = new Map<string, SenderKeyState>();
	for (const s of states) stateMap.set(s.senderKeyId, s);

	const encrypted = fromBase64Url(encryptedPayloadB64);
	const isMls = encrypted[0] === VERSION_MLS;
	// A sender-key row IS the server saying this group is not MLS, so the guard
	// takes `false` for that claim. Holding local MLS state contradicts it, and
	// the contradiction is refused before the ratchet is touched — and before the
	// cache below is consulted, so a replay cannot answer a row the guard would
	// have refused. Holding none is not evidence of anything: a billboard group, a
	// member whose Welcome has not landed and a fresh install all hold none, and
	// all decrypt below.
	if (!isMls) {
		assertNoMlsDowngrade(configDir, recipientAgentId, groupId, false);
	}

	// A row this agent has already opened is answered from its own read cache.
	// Both regimes spend a one-time key at the first decrypt, so without this the
	// second read of an inbox entry is an error about a key that is simply gone.
	// The envelope is re-verified below exactly as a first read is.
	//
	// 🔴 A retirement marker closes the cache with everything else. A
	// leave already deletes it, so this is the case where the two disagree: a
	// message opened while the marker was absent must stop opening when it is
	// back, or the marker would be a thing that cannot be re-armed.
	const replayed = senderKeysRetired(configDir, recipientAgentId, groupId)
		? null
		: lookupGroupRead(configDir, recipientAgentId, groupId, encrypted);
	if (replayed !== null) {
		return await authenticateEnvelope(replayed, client, fromAgentId);
	}

	if (isMls) {
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
			decrypted = await decryptMlsMessage(
				configDir,
				recipientAgentId,
				groupId,
				encrypted,
				client,
				fromAgentId,
			);
		} catch (err) {
			// Sync-then-retry covers both "behind" (epoch sync) and "no state"
			// (external join). A self-read miss and a local store failure are not
			// recoverable this way and surface as themselves.
			if (!isRecoverableMlsRead(err)) throw err;
		}
		if (decrypted !== null) {
			// A read that worked is the ordinary case, and it is the one that used to
			// leave a member drifting: nothing here ever advanced the epoch unless a
			// decrypt had already failed. The catch-up is rate-limited and never
			// throws, so the answer above is returned either way — now carrying what
			// the catch-up did, which this function used to compute and discard.
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
			...(await decryptMlsMessage(
				configDir,
				recipientAgentId,
				groupId,
				encrypted,
				client,
				fromAgentId,
			)),
			catchUp: recovered,
		};
	}

	const { innerEnvelope, updatedState, messageIndex } = await openGroup(
		stateMap,
		encrypted,
	);

	// Verify BEFORE persisting ratchet state, and refuse before the save below, so
	// a rejected message leaves the ratchet exactly where it was.
	const result = await authenticateEnvelope(innerEnvelope, client, fromAgentId);

	// Only now persist state — signature is verified or unverifiable (transient)
	// For the reader's own sender key, preserve skipped keys so re-reads work.
	if (updatedState.senderAgentId === recipientAgentId) {
		const prev = stateMap.get(updatedState.senderKeyId);
		const prevCached = prev?.skippedKeys?.[messageIndex];
		if (prevCached && !updatedState.skippedKeys?.[messageIndex]) {
			updatedState.skippedKeys = {
				...(updatedState.skippedKeys ?? {}),
				[messageIndex]: prevCached,
			};
		}
	}

	stateMap.set(updatedState.senderKeyId, updatedState);
	saveSenderKeyState(
		configDir,
		recipientAgentId,
		groupId,
		Array.from(stateMap.values()),
	);

	recordGroupRead(
		configDir,
		recipientAgentId,
		groupId,
		encrypted,
		innerEnvelope,
	);
	return result;
}

export function getAgentPublicKeys(
	configDir: string,
	agentId: string,
	agentKeys?: AgentKeys,
) {
	const keys = agentKeys ?? loadAgentKeys(configDir, agentId);
	const result: {
		signing_public_key: ReturnType<typeof signingPublicKeyToJWK>;
		encryption_public_key: { kty: string; crv: string; x: string };
		pq_encryption_public_key?: PqJWK;
	} = {
		signing_public_key: signingPublicKeyToJWK(keys.signing.publicKey),
		encryption_public_key: {
			kty: "OKP",
			crv: "X25519",
			x: toBase64Url(keys.encryption.publicKey),
		},
	};
	if (keys.pqEncryption) {
		result.pq_encryption_public_key = pqPublicKeyToJWK(
			keys.pqEncryption.publicKey,
		);
	}
	return result;
}
