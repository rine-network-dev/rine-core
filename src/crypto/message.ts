import type { AgentKeysResponse } from "../api-types.js";
import type { HttpClient } from "../http.js";
import { decodeEnvelope, encodeEnvelope } from "./envelope.js";
import { open, seal } from "./hpke.js";
import {
	type AgentKeys,
	agentIdFromKid,
	fromBase64Url,
	jwkToPublicKey,
	loadAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
} from "./keys.js";
import {
	type SenderKeyState,
	deriveMessageKey,
	openGroup,
	sealGroup,
} from "./sender-keys.js";
import { loadSenderKeyStates, saveSenderKeyState } from "./sender-keys-helpers.js";
import type { InnerEnvelope } from "./envelope.js";
import { signPayload, verifySignature } from "./sign.js";

export interface EncryptResult {
	encrypted_payload: string;
	encryption_version: string;
	sender_signing_kid: string;
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
): Promise<EncryptResult> {
	const keys = loadAgentKeys(configDir, senderAgentId);
	const plaintext = new TextEncoder().encode(JSON.stringify(payload));
	const kid = signingKid(senderAgentId);
	const signature = signPayload(keys.signing.privateKey, plaintext);
	const envelope = encodeEnvelope(kid, signature, plaintext);
	const encrypted = await seal(recipientEncryptionPk, envelope);

	return {
		encrypted_payload: toBase64Url(encrypted),
		encryption_version: "hpke-v1",
		sender_signing_kid: kid,
	};
}

export async function fetchRecipientEncryptionKey(
	client: HttpClient,
	agentId: string,
): Promise<Uint8Array> {
	const data = (await client.get(
		`/agents/${agentId}/keys`,
	)) as AgentKeysResponse;
	return jwkToPublicKey(data.encryption_public_key);
}

export async function decryptMessage(
	configDir: string,
	recipientAgentId: string,
	encryptedPayloadB64: string,
	client: HttpClient,
): Promise<DecryptResult> {
	const keys = loadAgentKeys(configDir, recipientAgentId);
	const encrypted = fromBase64Url(encryptedPayloadB64);
	const envelopeBytes = await open(keys.encryption.privateKey, encrypted);
	const decoded = decodeEnvelope(envelopeBytes);

	const plaintext = new TextDecoder("utf-8", { fatal: true }).decode(decoded.payload);
	const { verified, verificationStatus } = await verifyEnvelopeSender(decoded, client);

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
	const otherStates = allStates.filter(s => s.senderKeyId !== updatedState.senderKeyId);
	saveSenderKeyState(configDir, senderAgentId, groupId, [...otherStates, updatedState]);

	return {
		result: {
			encrypted_payload: toBase64Url(encryptedPayload),
			encryption_version: "sender-key-v1",
			sender_signing_kid: kid,
		},
		updatedState,
	};
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
	const { innerEnvelope, updatedState, messageIndex } = await openGroup(stateMap, encrypted);

	const decoded = decodeEnvelope(innerEnvelope);
	const plaintext = new TextDecoder("utf-8", { fatal: true }).decode(decoded.payload);

	// Verify signature BEFORE persisting ratchet state
	const { verified, verificationStatus } = await verifyEnvelopeSender(decoded, client);

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
	saveSenderKeyState(configDir, recipientAgentId, groupId, Array.from(stateMap.values()));

	return { plaintext, senderKid: decoded.kid, verified, verificationStatus };
}

export function getAgentPublicKeys(configDir: string, agentId: string, agentKeys?: AgentKeys) {
	const keys = agentKeys ?? loadAgentKeys(configDir, agentId);
	return {
		signing_public_key: signingPublicKeyToJWK(keys.signing.publicKey),
		encryption_public_key: {
			kty: "OKP",
			crv: "X25519",
			x: toBase64Url(keys.encryption.publicKey),
		},
	};
}
