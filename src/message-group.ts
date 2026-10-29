/**
 * Opening a group message: the one public decrypt that routes a group row to
 * whichever regime sealed it, and the sender-key read. The sender-key seal is
 * `crypto/sender-key-seal.ts`; the MLS seal and read are `message-mls.ts`.
 */
import { type GroupRow, authenticateEnvelope } from "./crypto/group-envelope.js";
import { lookupGroupRead, recordGroupRead } from "./crypto/group-read-cache.js";
import { fromBase64Url } from "./crypto/keys.js";
import type { DecryptResult } from "./crypto/message.js";
import { assertNoMlsDowngrade } from "./crypto/mls-downgrade.js";
import { VERSION_MLS } from "./crypto/mls.js";
import {
	loadSenderKeyStates,
	senderKeysRetired,
} from "./crypto/sender-keys-helpers.js";
import {
	mergeSenderKeyStates,
	statesFromSender,
	withSenderKeyStates,
} from "./crypto/sender-keys-store.js";
import { type SenderKeyState, openGroup } from "./crypto/sender-keys.js";
import type { HttpClient } from "./http.js";
import { readMlsGroupMessage } from "./message-mls.js";

/**
 * Open a group ciphertext (sender-key or MLS) and refuse anything inauthentic.
 *
 * `fromAgentId` is the row's server-authenticated `from_agent_id`, checked against
 * the envelope's own claim of authorship. Unlike the 1:1 path this one throws
 * rather than degrades, so a group transcript can never hold content attributed
 * to an agent that did not sign it.
 *
 * `createdAt` is the row's server `created_at`; a signature under a sender key
 * generation since rotated away verifies only for a row stamped before the
 * rotation, and without it such a message is refused.
 */
export async function decryptGroupMessage(
	configDir: string,
	recipientAgentId: string,
	groupId: string,
	encryptedPayloadB64: string,
	client: HttpClient,
	fromAgentId: string,
	createdAt?: string,
): Promise<DecryptResult> {
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
		return await authenticateEnvelope(
			replayed,
			client,
			fromAgentId,
			groupId,
			createdAt,
		);
	}

	const row: GroupRow = {
		configDir,
		recipientAgentId,
		groupId,
		encrypted,
		client,
		fromAgentId,
		createdAt,
	};
	return isMls
		? await readMlsGroupMessage(row)
		: await readSenderKeyGroupMessage(row);
}

/**
 * Open a sender-key group row under the lock on this group's state file.
 */
async function readSenderKeyGroupMessage(row: GroupRow): Promise<DecryptResult> {
	const {
		configDir,
		recipientAgentId,
		groupId,
		encrypted,
		client,
		fromAgentId,
		createdAt,
	} = row;
	// 🔴 Everything below is one read-modify-write of this group's state file
	// across a network verify, so it runs under that file's lock and loads INSIDE
	// it. A transcript render opens many rows against one ratchet: without the
	// lock each row loads the same state, advances its own copy and writes the
	// whole array back, so every advance but the last is discarded — and a peer
	// key an ingest installed during the verify goes with it. What the reader is
	// then shown is the sealed-message refusal, which claims no later message
	// reopens the row; the next render opens it, so the refusal is a falsehood
	// the product hands its own user.
	return await withSenderKeyStates(
		configDir,
		recipientAgentId,
		groupId,
		async () => {
			// 🔴 A row from `fromAgentId` — the sender the SERVER stamped on this
			// message — WINS any sender key id it shares. The file may legitimately
			// hold two rows under one id, because `ingestSenderKeyDistribution`
			// scopes its already-held check to the (sender, key) pair so that
			// claiming a peer's id first cannot take its slot; a map built over the
			// whole array in one pass then keeps whichever landed last, which is an
			// attacker's row by construction. The honest peer's posts open against
			// the wrong chain key and stop rendering, and re-planting after every
			// decrypt makes it permanent — a refusal that reads as a crypto
			// regression.
			//
			// Expressed as a preference rather than a filter, and both halves are
			// deliberate. Preferring rather than keying the map on the pair keeps
			// `openGroup`'s contract, which sees only the key id the wire carries.
			// Preferring rather than FILTERING keeps the refusals this path already
			// gives: a message whose key belongs to an agent other than the one the
			// server named still opens far enough to be refused as a sender
			// mismatch, which is the true sentence about it, instead of becoming an
			// absent-key refusal that invites the reader to ask the sender to post
			// again. A reader's own posts name the reader, so self-read is
			// unaffected.
			const onDisk = loadSenderKeyStates(configDir, recipientAgentId, groupId);
			const stateMap = new Map<string, SenderKeyState>();
			for (const s of onDisk) {
				stateMap.set(s.senderKeyId, s);
			}
			for (const s of statesFromSender(onDisk, fromAgentId)) {
				stateMap.set(s.senderKeyId, s);
			}

			const { innerEnvelope, updatedState, messageIndex } = await openGroup(
				stateMap,
				encrypted,
			);

			// Verify BEFORE persisting ratchet state, and refuse before the save
			// below, so a rejected message leaves the ratchet exactly where it was.
			const result = await authenticateEnvelope(
				innerEnvelope,
				client,
				fromAgentId,
				groupId,
				createdAt,
			);

			// Only now persist state — signature is verified or unverifiable
			// (transient). For the reader's own sender key, preserve skipped keys so
			// re-reads work.
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

			// Merge rather than assert the map: `ingestSenderKeyDistribution` is
			// synchronous and takes no lock, so it can install a peer's key while
			// the verify above awaits. This row knows about one sender key and says
			// so; it says nothing about the rest of the file.
			mergeSenderKeyStates(configDir, recipientAgentId, groupId, [
				updatedState,
			]);

			recordGroupRead(
				configDir,
				recipientAgentId,
				groupId,
				encrypted,
				innerEnvelope,
			);
			return result;
		},
	);
}
