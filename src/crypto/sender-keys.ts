import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { encodeEnvelope } from "./envelope.js";
import { fromBase64Url, toBase64Url } from "./keys.js";
import { bytesToUuid, uuidToBytes } from "./sender-keys-helpers.js";
import { signPayload } from "./sign.js";

const ROTATION_MESSAGE_LIMIT = 100;
const ROTATION_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export interface SenderKeyState {
	senderKeyId: string;
	groupId: string;
	senderAgentId: string;
	chainKey: Uint8Array;
	messageIndex: number;
	skippedKeys?: Record<number, string>; // messageIndex -> base64url(messageKey)
	distributedTo?: string[]; // agent IDs that received this sender key
	createdAt?: number; // epoch ms when this sender key was generated
}

export function needsRotation(state: SenderKeyState): boolean {
	if (state.messageIndex >= ROTATION_MESSAGE_LIMIT) return true;
	if (state.createdAt && Date.now() - state.createdAt > ROTATION_AGE_MS) return true;
	return false;
}

const VERSION_SENDER_KEY = 0x02;
const SENDER_KEY_ID_SIZE = 16;
const MESSAGE_INDEX_SIZE = 4;
const NONCE_SIZE = 12;
const MAX_SKIP = 1000;

/** Copy Uint8Array into a plain ArrayBuffer-backed Uint8Array (required by Web Crypto). */
function toPlainBuffer(src: Uint8Array): Uint8Array<ArrayBuffer> {
	const buf = new Uint8Array(src.length);
	buf.set(src);
	return buf;
}

export function generateSenderKey(
	groupId: string,
	senderAgentId: string,
): SenderKeyState {
	const chainKey = new Uint8Array(32);
	crypto.getRandomValues(chainKey);
	return {
		senderKeyId: crypto.randomUUID(),
		groupId,
		senderAgentId,
		chainKey,
		messageIndex: 0,
		createdAt: Date.now(),
	};
}

export function deriveMessageKey(chainKey: Uint8Array): {
	messageKey: Uint8Array;
	nextChainKey: Uint8Array;
} {
	const messageKey = hmac(sha256, chainKey, new Uint8Array([0x01]));
	const nextChainKey = hmac(sha256, chainKey, new Uint8Array([0x02]));
	return { messageKey, nextChainKey };
}

export function advanceChain(
	state: SenderKeyState,
	targetIndex: number,
): { updatedState: SenderKeyState; skippedKeys: Map<number, Uint8Array> } {
	if (targetIndex - state.messageIndex > MAX_SKIP) {
		throw new Error(
			`too many skipped messages: ${targetIndex - state.messageIndex} (max ${MAX_SKIP})`,
		);
	}
	const skippedKeys = new Map<number, Uint8Array>();
	let chainKey = state.chainKey;
	let index = state.messageIndex;

	while (index < targetIndex) {
		const { messageKey, nextChainKey } = deriveMessageKey(chainKey);
		skippedKeys.set(index, messageKey);
		chainKey = nextChainKey;
		index++;
	}

	return {
		updatedState: { ...state, chainKey, messageIndex: index },
		skippedKeys,
	};
}

/** Build AAD for sender-key encryption: binds ciphertext to sender_key_id and message_index. */
function buildSenderKeyAad(senderKeyId: Uint8Array, messageIndex: number): Uint8Array {
	const aad = new Uint8Array(SENDER_KEY_ID_SIZE + MESSAGE_INDEX_SIZE);
	aad.set(senderKeyId, 0);
	new DataView(aad.buffer).setUint32(SENDER_KEY_ID_SIZE, messageIndex, false);
	return aad;
}

export async function sealGroup(
	senderSigningPrivateKey: Uint8Array,
	senderSigningKid: string,
	state: SenderKeyState,
	plaintext: Uint8Array,
): Promise<{ encryptedPayload: Uint8Array; updatedState: SenderKeyState }> {
	const signature = signPayload(senderSigningPrivateKey, plaintext);
	const innerEnvelope = encodeEnvelope(senderSigningKid, signature, plaintext);

	const { messageKey, nextChainKey } = deriveMessageKey(state.chainKey);

	const nonce = new Uint8Array(NONCE_SIZE);
	crypto.getRandomValues(nonce);

	const idBytes = uuidToBytes(state.senderKeyId);
	const aad = buildSenderKeyAad(idBytes, state.messageIndex);

	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		toPlainBuffer(messageKey),
		"AES-GCM",
		false,
		["encrypt"],
	);
	const ciphertext = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: nonce, additionalData: toPlainBuffer(aad) },
			cryptoKey,
			toPlainBuffer(innerEnvelope),
		),
	);
	messageKey.fill(0);
	const out = new Uint8Array(
		1 +
			SENDER_KEY_ID_SIZE +
			MESSAGE_INDEX_SIZE +
			NONCE_SIZE +
			ciphertext.length,
	);
	let offset = 0;
	out[offset++] = VERSION_SENDER_KEY;
	out.set(idBytes, offset);
	offset += SENDER_KEY_ID_SIZE;
	new DataView(out.buffer).setUint32(offset, state.messageIndex, false);
	offset += MESSAGE_INDEX_SIZE;
	out.set(nonce, offset);
	offset += NONCE_SIZE;
	out.set(ciphertext, offset);

	return {
		encryptedPayload: out,
		updatedState: {
			...state,
			chainKey: nextChainKey,
			messageIndex: state.messageIndex + 1,
		},
	};
}

export async function openGroup(
	senderKeyStates: Map<string, SenderKeyState>,
	encryptedPayload: Uint8Array,
): Promise<{
	innerEnvelope: Uint8Array;
	senderKeyId: string;
	messageIndex: number;
	updatedState: SenderKeyState;
}> {
	const minLen = 1 + SENDER_KEY_ID_SIZE + MESSAGE_INDEX_SIZE + NONCE_SIZE;
	if (encryptedPayload.length < minLen) {
		throw new Error("encrypted payload too short");
	}
	const version = encryptedPayload[0];
	if (version !== VERSION_SENDER_KEY) {
		throw new Error(
			`unsupported version: 0x${version?.toString(16).padStart(2, "0")}`,
		);
	}

	let offset = 1;
	const senderKeyId = bytesToUuid(
		encryptedPayload.slice(offset, offset + SENDER_KEY_ID_SIZE),
	);
	offset += SENDER_KEY_ID_SIZE;
	const messageIndex = new DataView(
		encryptedPayload.buffer,
		encryptedPayload.byteOffset,
	).getUint32(offset, false);
	offset += MESSAGE_INDEX_SIZE;
	const nonce = encryptedPayload.slice(offset, offset + NONCE_SIZE);
	offset += NONCE_SIZE;
	const ciphertext = encryptedPayload.slice(offset);

	const state = senderKeyStates.get(senderKeyId);
	if (!state) throw new Error(`unknown sender key id: ${senderKeyId}`);

	let messageKey: Uint8Array;
	let updatedState: SenderKeyState;

	if (messageIndex < state.messageIndex) {
		// Past message — look up in skipped key cache
		const cached = state.skippedKeys?.[messageIndex];
		if (!cached) {
			throw new Error("message key expired or already consumed");
		}
		messageKey = fromBase64Url(cached);
		// Remove consumed key from cache
		const newSkipped = { ...state.skippedKeys };
		delete newSkipped[messageIndex];
		updatedState = { ...state, skippedKeys: newSkipped };
	} else if (messageIndex === state.messageIndex) {
		// Current message — derive key normally
		const { messageKey: mk, nextChainKey } = deriveMessageKey(state.chainKey);
		messageKey = mk;
		updatedState = {
			...state,
			chainKey: nextChainKey,
			messageIndex: state.messageIndex + 1,
		};
	} else {
		// Future message — advance chain and cache skipped keys
		const { updatedState: advanced, skippedKeys: newSkipped } = advanceChain(state, messageIndex);
		const { messageKey: mk, nextChainKey } = deriveMessageKey(advanced.chainKey);
		messageKey = mk;

		// Merge skipped keys into state
		const mergedSkipped: Record<number, string> = { ...(state.skippedKeys ?? {}) };
		for (const [idx, key] of newSkipped) {
			mergedSkipped[idx] = toBase64Url(key);
			key.fill(0);
		}

		// Enforce cap: max 1000 cached skipped keys
		const entries = Object.entries(mergedSkipped);
		if (entries.length > MAX_SKIP) {
			entries.sort((a, b) => Number(a[0]) - Number(b[0]));
			const excess = entries.length - MAX_SKIP;
			for (let i = 0; i < excess; i++) {
				delete mergedSkipped[Number(entries[i]![0])];
			}
		}

		updatedState = {
			...advanced,
			chainKey: nextChainKey,
			messageIndex: messageIndex + 1,
			skippedKeys: mergedSkipped,
		};
	}

	const idBytes = encryptedPayload.slice(1, 1 + SENDER_KEY_ID_SIZE);
	const aad = buildSenderKeyAad(idBytes, messageIndex);

	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		toPlainBuffer(messageKey),
		"AES-GCM",
		false,
		["decrypt"],
	);
	const innerEnvelope = new Uint8Array(
		await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: nonce, additionalData: toPlainBuffer(aad) },
			cryptoKey,
			toPlainBuffer(ciphertext),
		),
	);
	messageKey.fill(0);

	return { innerEnvelope, senderKeyId, messageIndex, updatedState };
}
