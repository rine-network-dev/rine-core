/**
 * Sealing a group message under this agent's sender key, and writing the
 * ratchet it advanced back to the group's state file.
 */
import { ENCRYPTION_VERSIONS } from "../encryption-versions.js";
import { loadAgentKeys, signingKid, toBase64Url } from "./keys.js";
import type { EncryptResult } from "./message.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
	senderKeysRetired,
} from "./sender-keys-helpers.js";
import { statesFromSender } from "./sender-keys-store.js";
import {
	type SenderKeyState,
	deriveMessageKey,
	sealGroup,
} from "./sender-keys.js";

/**
 * A group send handed a sender key that is on no disk this agent owns.
 *
 * {@link encryptGroupMessage} writes the state it advanced back IN PLACE and
 * writes nothing at all when the row is gone, because gone means RETIRED: a
 * rotation dropped it, or a `group leave` removed the file. Both are silent on
 * purpose. This is the third case, and it is none of the agent's history — the
 * file names no key of this agent's at all and the group is not retired, so
 * nothing ever persisted the state the caller passed in.
 *
 * That is a caller defect, not a race, and it is silent in the worst way: the
 * message is sealed and transmittable while the ratchet advance and the
 * self-read cache it produced go nowhere. The sender cannot re-read its own
 * post, and the next send under a freshly minted key starts from message index
 * zero again. Every in-repo caller takes its state from `getOrCreateSenderKey`,
 * which persists before returning — but `encryptGroupMessage`,
 * `generateSenderKey` and `saveSenderKeyState` are all in the public
 * `@rine-network/core` barrel, so composing the first two without the third is
 * a shape any consumer can produce, so it is refused here rather than sealed.
 *
 * 🔴 One narrow race reaches this refusal honestly: a leave lifts its own
 * retirement marker on re-admission (`liftRetirementIfMember`), so a send whose
 * fan-out spans leave → rejoin → another send's lift can arrive here with
 * neither the file nor the marker. It is refused rather than guessed at: the
 * alternative is the silent discard above, and the send is retried honestly
 * against the state the rejoin wrote.
 */
export class UnpersistedSenderKeyStateError extends Error {
	constructor(
		readonly senderKeyId: string,
		readonly groupId: string,
	) {
		super(
			`rine sealed a group message for ${groupId} under sender key ` +
				`${senderKeyId}, but this agent holds no sender-key state file ` +
				"naming that key or any other key of its own for that group, and " +
				"the group is not retired — so nothing persisted the state this " +
				"send was given. The ratchet advance and the self-read key for this " +
				"message would have been discarded, leaving the sender unable to " +
				"read back its own post. Obtain the sender key through " +
				"getOrCreateSenderKey, which saves it before returning, or save a " +
				"freshly generated one with saveSenderKeyState before encrypting " +
				"with it.",
		);
		this.name = "UnpersistedSenderKeyStateError";
	}
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
	const kid = signingKid(senderAgentId, keys.keyGen);

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

	// 🔴 One of the two read-modify-writes of this group's state file that take
	// no lock (both named in `sender-keys-store.ts`), and the only one in an
	// `async` function — `sealGroup` above is an await. It is sound because load and save below have no await BETWEEN them:
	// nothing in this process can run in the gap, so this cannot lose anyone
	// else's entry. Putting an await between them reopens exactly the lost update
	// `sender-keys-store.ts` exists to close, with nothing here to catch it.
	//
	// 🔴 The reverse direction is a KNOWN RESIDUAL and is not closed: a decrypt
	// of this agent's own past post holds the file's lock across its network
	// verify and merges under this same `senderKeyId`, so a send landing in that
	// window is overwritten by the holder's pre-network copy — a message index
	// re-used across two posts, and the sender's own self-read key for one of
	// them gone. Taking the lock here would order the two writes and still not
	// fix it: `sealGroup` already consumed the chain key from the snapshot this
	// function was handed. Closing it means the send re-deriving under the lock,
	// which is a design change to the send path, not a lock placement.
	//
	// 🔴 Written back IN PLACE, and NOT written back at all if the row is gone.
	// `sender-key-ops.ts` reads the LAST own entry as the current key, so position
	// here is not cosmetic — it decides what the next send seals under.
	// Filtering the row out and re-appending it last would be wrong in both
	// directions once a concurrent rotation lands during a send:
	//
	//   * The rotation retains the state it superseded BELOW the new one, so
	//     re-appending this row would move a SUPERSEDED key back to last and the
	//     next send would seal under a key this agent already rotated away from.
	//   * Where the rotation did not retain it, a re-append would RESURRECT a row
	//     the rotation deliberately dropped, with the same result, and re-create
	//     the state file of a group this agent already left.
	//
	// So the row is found by id and replaced where it already sits, and if it is
	// not there, nothing is written. A key rotated away or
	// retired mid-send has nothing worth recording — the message it sealed is
	// already out, and its chain advance is only meaningful to a key nobody will
	// send under again. Absent therefore means retired, never new: the state was
	// saved by `getOrCreateSenderKey` before this function ever saw it. This is
	// the shape `mergeSenderKeyStates` takes for an own row too — it skips one
	// whose (sender, key) pair is not already on disk, for exactly this reason.
	// Twin: `rine-sdk/src/rine/_crypto/message.py`.
	//
	// 🔴 "Absent means retired" is a claim about WHICH absence, and the three
	// cases are told apart rather than collapsed. A row gone from a file that
	// still names other keys of this agent's was dropped by a rotation; a group
	// with no file and a retirement marker was left. Both are silent, because
	// both are the state file correctly having moved on. Absent with NO own row
	// anywhere and NO retirement is neither: nothing ever persisted the state
	// this call was handed, so the ratchet advance and the self-read key are
	// about to be discarded for a message that is already sealed. Refused
	// instead — see {@link UnpersistedSenderKeyStateError}.
	const allStates = loadSenderKeyStates(configDir, senderAgentId, groupId);
	// 🔴 By the (sender, key) pair, never the key id alone: a peer may legitimately
	// hold a row under an id this agent also uses, and a write that matched on the
	// id would overwrite THAT peer's chain key with this agent's own state — losing
	// the peer's key for good, on an ordinary send.
	const own = statesFromSender(allStates, senderAgentId);
	const target = own.find((s) => s.senderKeyId === updatedState.senderKeyId);
	if (target) {
		saveSenderKeyState(
			configDir,
			senderAgentId,
			groupId,
			allStates.map((s) => (s === target ? updatedState : s)),
		);
	} else if (
		own.length === 0 &&
		!senderKeysRetired(configDir, senderAgentId, groupId)
	) {
		throw new UnpersistedSenderKeyStateError(updatedState.senderKeyId, groupId);
	}

	return {
		result: {
			encrypted_payload: toBase64Url(encryptedPayload),
			encryption_version: ENCRYPTION_VERSIONS.SENDER_KEY_V1,
			sender_signing_kid: kid,
		},
		updatedState,
	};
}
