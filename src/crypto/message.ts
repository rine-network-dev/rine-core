import type { AgentKeysResponse } from "../api-types.js";
import type { HttpClient } from "../http.js";
import { decodeEnvelope, encodeEnvelope } from "./envelope.js";
import type { InnerEnvelope } from "./envelope.js";
import { open, seal } from "./hpke.js";
import { VERSION_HYBRID, openHybrid, sealHybrid } from "./hybrid.js";
import { MlsError } from "ts-mls";
import { VERSION_MLS, decryptMlsAppMessage, encryptMlsAppMessage } from "./mls.js";
import { loadMlsState, saveMlsState, cacheMlsSelfRead, lookupMlsSelfRead } from "./mls-state.js";
import { processMlsWelcomes, syncMlsGroup } from "../mls-ops-sync.js";
import { externalJoinMlsGroup } from "../mls-ops-join.js";
import {
	type AgentKeys,
	type PqJWK,
	agentIdFromKid,
	fromBase64Url,
	jwkToPqPublicKey,
	jwkToPublicKey,
	loadAgentKeys,
	pqPublicKeyToJWK,
	signingPublicKeyToJWK,
	toBase64Url,
} from "./keys.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
} from "./sender-keys-helpers.js";
import {
	type SenderKeyState,
	deriveMessageKey,
	openGroup,
	sealGroup,
} from "./sender-keys.js";
import { signPayload, verifySignature } from "./sign.js";

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

export type VerificationStatus = "verified" | "invalid" | "unverifiable";

export interface DecryptResult {
	plaintext: string;
	senderKid: string;
	verified: boolean;
	verificationStatus: VerificationStatus;
}

async function verifyEnvelopeSender(
	decoded: InnerEnvelope,
	client: HttpClient,
): Promise<{ verified: boolean; verificationStatus: VerificationStatus }> {
	let verified = false;
	let verificationStatus: VerificationStatus = "unverifiable";
	try {
		const senderAgentId = agentIdFromKid(decoded.kid);
		const senderKeys = (await client.get(
			`/agents/${senderAgentId}/keys`,
		)) as AgentKeysResponse;
		const senderSigningPk = jwkToPublicKey(senderKeys.signing_public_key);
		verified = verifySignature(
			senderSigningPk,
			decoded.payload,
			decoded.signature,
		);
		verificationStatus = verified ? "verified" : "invalid";
	} catch {
		// Could not fetch sender's key — signature unverifiable
	}
	return { verified, verificationStatus };
}

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

export interface RecipientKeys {
	encryption: Uint8Array;
	pqEncryption?: Uint8Array;
}

/** Fetch a recipient's encryption keys, including the optional PQ key for hybrid mode. */
export async function fetchRecipientKeys(
	client: HttpClient,
	agentId: string,
): Promise<RecipientKeys> {
	const data = (await client.get(
		`/agents/${agentId}/keys`,
	)) as AgentKeysResponse;
	const out: RecipientKeys = {
		encryption: jwkToPublicKey(data.encryption_public_key),
	};
	if (data.pq_encryption_public_key) {
		out.pqEncryption = jwkToPqPublicKey(data.pq_encryption_public_key as PqJWK);
	}
	return out;
}

export async function decryptMessage(
	configDir: string,
	recipientAgentId: string,
	encryptedPayloadB64: string,
	client: HttpClient,
): Promise<DecryptResult> {
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

	const plaintext = new TextDecoder("utf-8", { fatal: true }).decode(
		decoded.payload,
	);
	const { verified, verificationStatus } = await verifyEnvelopeSender(
		decoded,
		client,
	);

	return { plaintext, senderKid: decoded.kid, verified, verificationStatus };
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

	// Derive the message key before sealGroup consumes the chain key,
	// so we can cache it for sender self-read (BUG-1 fix).
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
	const stored = loadMlsState(configDir, senderAgentId, groupId);
	if (!stored) throw new Error(`No MLS state for group ${groupId}`);

	const keys = loadAgentKeys(configDir, senderAgentId);
	const plaintext = new TextEncoder().encode(JSON.stringify(payload));
	const kid = signingKid(senderAgentId);
	const signature = signPayload(keys.signing.privateKey, plaintext);
	const envelope = encodeEnvelope(kid, signature, plaintext);

	const { ciphertext, updatedState } = await encryptMlsAppMessage(
		stored.stateBlob,
		envelope,
	);
	saveMlsState(configDir, senderAgentId, groupId, updatedState, stored.metadata);

	// Prefix the version byte so decryptGroupMessage dispatches to the MLS branch.
	const tagged = new Uint8Array(1 + ciphertext.length);
	tagged[0] = VERSION_MLS;
	tagged.set(ciphertext, 1);

	const encrypted_payload = toBase64Url(tagged);
	// MLS forward secrecy prevents self-read (sender ratchet advances past the
	// generation used for encryption). Cache the envelope so the sender can
	// decrypt their own message via cache lookup instead of MLS decrypt.
	cacheMlsSelfRead(configDir, senderAgentId, groupId, encrypted_payload, envelope);

	return {
		encrypted_payload,
		encryption_version: "mls-v1",
		sender_signing_kid: kid,
	};
}

async function decryptMlsMessage(
	configDir: string,
	recipientAgentId: string,
	groupId: string,
	mlsCiphertext: Uint8Array,
	client: HttpClient,
): Promise<DecryptResult> {
	const stored = loadMlsState(configDir, recipientAgentId, groupId);
	if (!stored) throw new Error(`No MLS state for group ${groupId}`);
	const { plaintext: mlsPlain, updatedState } = await decryptMlsAppMessage(
		stored.stateBlob, mlsCiphertext,
	);
	saveMlsState(configDir, recipientAgentId, groupId, updatedState, stored.metadata);
	const mlsEnvelope = decodeEnvelope(mlsPlain);
	const mlsText = new TextDecoder("utf-8", { fatal: true }).decode(mlsEnvelope.payload);
	const { verified, verificationStatus } = await verifyEnvelopeSender(mlsEnvelope, client);
	if (verificationStatus === "invalid") {
		throw new Error("Sender signature verification failed");
	}
	return { plaintext: mlsText, senderKid: mlsEnvelope.kid, verified, verificationStatus };
}

export async function decryptGroupMessage(
	configDir: string,
	recipientAgentId: string,
	groupId: string,
	encryptedPayloadB64: string,
	client: HttpClient,
): Promise<DecryptResult> {
	const states = loadSenderKeyStates(configDir, recipientAgentId, groupId);
	const stateMap = new Map<string, SenderKeyState>();
	for (const s of states) stateMap.set(s.senderKeyId, s);

	const encrypted = fromBase64Url(encryptedPayloadB64);
	if (encrypted[0] === VERSION_MLS) {
		// Self-read fast path: the sender's ratchet has advanced past the
		// generation used for encryption, so MLS decrypt fails.  Check the
		// local cache first (populated by encryptMlsGroupMessage).
		const cached = lookupMlsSelfRead(configDir, recipientAgentId, groupId, encryptedPayloadB64);
		if (cached) {
			const env = decodeEnvelope(cached);
			const text = new TextDecoder("utf-8", { fatal: true }).decode(env.payload);
			const { verified, verificationStatus } = await verifyEnvelopeSender(env, client);
			if (verificationStatus === "invalid") throw new Error("Sender signature verification failed");
			return { plaintext: text, senderKid: env.kid, verified, verificationStatus };
		}

		const mlsCiphertext = encrypted.slice(1);
		try {
			return await decryptMlsMessage(configDir, recipientAgentId, groupId, mlsCiphertext, client);
		} catch (err) {
			// Sync-then-retry for any MLS or "No MLS state" error.  The recovery
			// path handles both "behind" (epoch sync) and "no state" (external
			// join) cases.
			const isRecoverable = err instanceof MlsError ||
				(err instanceof Error && err.message.startsWith("No MLS state for group"));
			if (!isRecoverable) throw err;
		}
		// One-shot recovery: install pending Welcomes (establishes state for
		// newly-joined groups) then sync pending commits (advances epoch).
		// If neither produces local state, attempt an external join as last
		// resort (open-enrollment groups where the original join didn't
		// establish MLS state).
		await processMlsWelcomes(configDir, recipientAgentId, client);
		if (!loadMlsState(configDir, recipientAgentId, groupId)) {
			await externalJoinMlsGroup(configDir, recipientAgentId, groupId, client);
		}
		await syncMlsGroup(configDir, recipientAgentId, groupId, client);
		return await decryptMlsMessage(configDir, recipientAgentId, groupId, mlsCiphertext, client);
	}
	const { innerEnvelope, updatedState, messageIndex } = await openGroup(
		stateMap,
		encrypted,
	);

	const decoded = decodeEnvelope(innerEnvelope);
	const plaintext = new TextDecoder("utf-8", { fatal: true }).decode(
		decoded.payload,
	);

	// Verify signature BEFORE persisting ratchet state
	const { verified, verificationStatus } = await verifyEnvelopeSender(
		decoded,
		client,
	);

	// Reject invalid signatures without advancing ratchet state
	if (verificationStatus === "invalid") {
		throw new Error("Sender signature verification failed");
	}

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

	return { plaintext, senderKid: decoded.kid, verified, verificationStatus };
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
