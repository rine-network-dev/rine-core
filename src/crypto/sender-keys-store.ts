import { resolve } from "node:path";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
	senderKeyStateExists,
	senderKeysRetired,
} from "./sender-keys-helpers.js";
import type { SenderKeyState } from "./sender-keys.js";

/**
 * Serialised, merge-safe access to ONE group's sender-key state file.
 *
 * Every sender-key operation is a read-modify-write of a single JSON array, and
 * three of them span a network call: a group decrypt verifies the envelope's
 * signer between loading the ratchet and saving it, and a group send fans the
 * key out to every member between the two. A whole-array write taken from a
 * pre-network snapshot therefore discards everything that landed in the file
 * while the network was in flight — another row's ratchet advance, or a peer's
 * key an ingest had just installed. The reader is then told the group is sealed
 * and that no later message reopens it, which is false in every clause: the
 * next render reads the lot.
 *
 * The two halves below are deliberately separate because they close different
 * holes and neither subsumes the other:
 *
 * - {@link withSenderKeyStates} serialises holders against each other, which is
 *   the only thing that can make two decrypts of the same sender key advance
 *   the ratchet twice instead of once. No merge can recover that.
 * - {@link mergeSenderKeyStates} keeps entries the holder never touched. It is
 *   what survives `ingestSenderKeyDistribution`, which is synchronous — so it
 *   cannot interleave with itself, but it CAN land between a holder's load and
 *   its save, in the window the holder is awaiting the network.
 *
 * 🔴 TWO writers take no lock, not one: `ingestSenderKeyDistribution`
 * (`crypto/ingest.ts`) and the tail of `encryptGroupMessage` (`crypto/message.ts`).
 * Both are sound only because their load and save have no `await` between them,
 * both say so at the site, and both would silently reopen a lost update the day
 * one grows an await. Anyone reading "the file's writes are serialised" should
 * read it as "serialised, plus two synchronous writers that cannot interleave" —
 * and `encryptGroupMessage` additionally carries a residual this module does NOT
 * close, described there.
 */

/**
 * Tail of the in-flight chain per state file. An entry exists only while a
 * holder is queued or running; the last one out removes it, so a long-lived
 * process does not retain a row per group it has ever read.
 */
const chains = new Map<string, Promise<void>>();

function fileKey(configDir: string, agentId: string, groupId: string): string {
	// The (configDir, agentId, groupId) triple IS the file path — the agent owns
	// the directory and the group names the file — so the triple is the lock
	// identity, and no path has to be built to key on it. The directory is
	// resolved first because it is the one component a caller supplies verbatim:
	// `resolveConfigDir` hands back `RINE_CONFIG_DIR` as written and the SDK's
	// `HttpClient` stores what it was constructed with, so `.rine` and
	// `/abs/path/.rine` reach the same file through two different keys — two
	// locks over one file, which is no lock at all, and it fails silently.
	return JSON.stringify([resolve(configDir), agentId, groupId]);
}

/**
 * Run `fn` with exclusive in-process access to one group's sender-key state.
 *
 * 🔴 The lock is NOT reentrant: `fn` must not reach another
 * `withSenderKeyStates` for the same file, directly or through anything it
 * calls, or it waits on itself for ever. The recovery path is the case to keep
 * in mind — it re-enters `decryptGroupMessage` — and it may only do so from
 * OUTSIDE this call, which is why the decrypt takes the lock inside itself
 * rather than the recovery taking it around both.
 *
 * 🔴 It is also in-process only. Two processes against one config dir — a
 * `rine stream` and a `rine thread` in separate terminals — still race, and
 * nothing here closes that.
 */
export function withSenderKeyStates<T>(
	configDir: string,
	agentId: string,
	groupId: string,
	fn: () => Promise<T>,
): Promise<T> {
	const key = fileKey(configDir, agentId, groupId);
	const prior = chains.get(key) ?? Promise.resolve();
	const run = prior.then(fn);
	// The chain must never reject: a holder that throws still releases, and a
	// rejected tail would otherwise fail every caller queued behind it.
	const released = run.then(
		() => undefined,
		() => undefined,
	);
	chains.set(key, released);
	void released.then(() => {
		if (chains.get(key) === released) chains.delete(key);
	});
	return run;
}

/**
 * Write back only the states this caller derived, keyed by `senderKeyId`,
 * leaving every other entry as the file currently holds it.
 *
 * A holder that saves `Array.from(itsOwnMap.values())` asserts the whole file,
 * including the parts it never looked at — which is how one peer's key
 * disappears when two arrive at once. Replacing by id asserts only what the
 * caller actually knows. Insertion order is preserved for ids already on disk,
 * so the "last own state is the current one" ordering `sender-key-ops.ts`
 * depends on survives a merge; a genuinely new PEER id appends.
 *
 * 🔴 An OWN row whose id is not already on disk is DROPPED, not appended, and
 * that asymmetry is the whole of the protection for the last-own reader.
 * Installing a peer key this agent did not have is what the merge is for; an own
 * row is different in kind. Every own row on disk was put there by
 * {@link getOrCreateSenderKey}, which is also the only writer that removes one,
 * so an own id the file no longer holds is one a rotation RETIRED — the same
 * "absent means retired, never new" rule `encryptGroupMessage`'s tail applies.
 * Appending it puts it at the END, where the reader takes it as current, and the
 * next send seals the group under a key the group has already moved on from:
 * either with no fan-out at all (no trigger re-fires, because the rotation's own
 * RETENTION drops a row without any trigger having fired), or — where a trigger
 * does fire — with the resurrected row retained in place of the row the agent
 * was actually sending under, destroying the self-read the retention exists for.
 * Both were reproduced on both stacks before this rule was written.
 *
 * Nothing legitimate needs the merge to CREATE an own row: its only caller
 * (`decryptGroupMessage`) merges the state it loaded inside this file's own
 * lock, and the writer that mints own rows asserts its whole array through
 * `saveSenderKeyState`, never through this. Own-vs-peer is decided
 * case-insensitively, exactly as `sender-key-ops.ts` decides it — a row the
 * merge calls a peer and the reader calls own is the hole this closes.
 *
 * This does NOT express a deletion of anything else — a caller that must drop
 * states (a rotation retiring superseded keys) re-derives its whole array from a
 * fresh read inside {@link withSenderKeyStates} instead.
 *
 * 🔴 A merge never RE-CREATES a retired group's file. `deleteSenderKey` unlinks
 * it and marks the group retired in one synchronous step, so a holder that
 * entered before the leave and resumes after it always sees the marker — and
 * without this check its merge re-reads nothing, appends the state it is still
 * holding, and puts live chain material back on disk that the leave had just
 * removed. The marker survives, so no NEW distribution is ingested; what comes
 * back is the very key the in-flight decrypt was using, which goes on opening
 * that peer's later traffic. "Retiring the group is removing that file"
 * ({@link deleteSenderKey}) has to hold for the writer already running.
 *
 * The refusal is deliberately narrow — retired AND no file. A retired group
 * whose file exists again was re-created by a writer that is not this one
 * (`getOrCreateSenderKey` lifts a retirement only for a current member and
 * saves either way), and silently dropping that writer's updates would be a
 * second bug rather than a fix for this one.
 */
/**
 * The pair that names one row of a state file: its sender, then its key id.
 *
 * 🔴 A `senderKeyId` is NOT unique within the file, and keying anything by it
 * alone silently deletes a row. The id is minted by whoever sends it, so
 * `ingestSenderKeyDistribution` admits a distribution carrying an id this agent
 * already holds when it comes from a DIFFERENT sender — scoped to the pair
 * precisely so that claiming a genuine peer's id first cannot take its slot. Two
 * rows sharing one id is therefore the intended state of a file under attack, and
 * a `Map` built over `senderKeyId` keeps whichever landed last: rebuilding the
 * array from that map's values writes the honest peer's key out of existence,
 * permanently, with no error anywhere.
 *
 * Agent ids compare case-insensitively, exactly as the ingest compares them:
 * `agentIdFromKid` preserves whatever case the signer put in its kid, and the
 * ingest files the row under that spelling. Key ids need no folding — the ingest
 * canonicalises them and every local mint is a lower-case UUID — but a pair is
 * only as good as its weaker half, so both halves are decided here and nowhere
 * else. A `Map` key must be primitive, so the two are joined by a NUL, which a
 * validated id cannot contain; the Python twin returns a tuple and needs no
 * separator at all (`sender_key_identity` in `_crypto/sender_keys_store.py`).
 */
export function senderKeyIdentity(state: SenderKeyState): string {
	return `${state.senderAgentId.toLowerCase()}\u0000${state.senderKeyId}`;
}

/**
 * Only the rows `agentId` filed, out of a whole group's state file.
 *
 * The counterpart to {@link senderKeyIdentity} for the sites that already know
 * whose row they want: a search by key id alone answers with whatever row landed
 * last under that id, which is not necessarily the one this caller means.
 */
export function statesFromSender(
	states: readonly SenderKeyState[],
	agentId: string,
): SenderKeyState[] {
	const sender = agentId.toLowerCase();
	return states.filter((s) => s.senderAgentId.toLowerCase() === sender);
}

export function mergeSenderKeyStates(
	configDir: string,
	agentId: string,
	groupId: string,
	touched: readonly SenderKeyState[],
): void {
	if (
		senderKeysRetired(configDir, agentId, groupId) &&
		!senderKeyStateExists(configDir, agentId, groupId)
	) {
		return;
	}
	const merged = new Map<string, SenderKeyState>();
	for (const s of loadSenderKeyStates(configDir, agentId, groupId)) {
		merged.set(senderKeyIdentity(s), s);
	}
	const selfId = agentId.toLowerCase();
	const applicable = touched.filter(
		(s) =>
			merged.has(senderKeyIdentity(s)) ||
			s.senderAgentId.toLowerCase() !== selfId,
	);
	// Nothing to assert is not the same as asserting the file as it stands: a
	// save here would CREATE an empty state file for a group this agent holds no
	// material for, and `senderKeyStateExists` — which a leave reads to say which
	// encryption it just retired — answers off that file's existence.
	if (applicable.length === 0) return;
	for (const s of applicable) merged.set(senderKeyIdentity(s), s);
	saveSenderKeyState(configDir, agentId, groupId, Array.from(merged.values()));
}
