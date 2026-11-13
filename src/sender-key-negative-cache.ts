/**
 * Which sender keys a scan has already failed to find, so a reader does not
 * list the whole distribution inbox again for every post that needs one.
 *
 * A group post whose sender key never arrives (the sender's org refuses our
 * keys, or its distribution was never sent) makes every read of that sender's
 * posts run one list call plus a GET and a decrypt per pending distribution.
 * An agent reading twenty such posts paid the scan twenty times. One empty scan
 * is the answer for all of them until something could have changed it.
 *
 * In memory and per process, on purpose: no on-disk state and no lock. A
 * long-running agent scans once per {@link NEGATIVE_TTL_MS} per missing key; a
 * one-shot CLI call scans once, as it always did.
 *
 * Keyed by (agent, group, sender, key id), never by `refused_members`: the
 * cache records what a scan found, not what a group rule says.
 */

/** How long an empty scan stays the answer. */
export const NEGATIVE_TTL_MS = 15 * 60 * 1000;

/** Oldest entries go first once the map is this full. */
export const NEGATIVE_MAX_ENTRIES = 1000;

/**
 * How many scans in a row one distribution row may fail before it stops
 * vetoing a recorded miss. A transient failure (a dropped GET) heals inside
 * this many scans and keeps the scan incomplete meanwhile; a row that never
 * opens (a garbled or badly signed distribution, which stays in the listing
 * for good) would otherwise keep the cache off for the whole process.
 */
export const ROW_FAILURE_LIMIT = 3;

/** One missing key: the reader, where the post lives, who sent it, and which key. */
export interface MissingSenderKey {
	agentId: string;
	groupId: string;
	senderAgentId: string;
	keyId: string;
}

/** Entry key to the time it stops being the answer. Insertion order is age. */
const expiries = new Map<string, number>();

/** Ids compare case-insensitively, as the ingest guard does. */
function entryKey(k: MissingSenderKey): string {
	return JSON.stringify([
		k.agentId.toLowerCase(),
		k.groupId.toLowerCase(),
		k.senderAgentId.toLowerCase(),
		k.keyId,
	]);
}

/**
 * Whether a scan already found this key missing within the last 15 minutes.
 * Read-only, so OpenClaw's sweep can ask without touching an entry.
 */
export function isCached(
	agentId: string,
	groupId: string,
	senderAgentId: string,
	keyId: string,
): boolean {
	const key = entryKey({ agentId, groupId, senderAgentId, keyId });
	const expiry = expiries.get(key);
	if (expiry === undefined) return false;
	if (expiry > Date.now()) return true;
	expiries.delete(key);
	return false;
}

/** Remember that a scan ran and did not bring this key. */
export function recordMissing(k: MissingSenderKey): void {
	const key = entryKey(k);
	// Re-insert so a repeat entry counts as the newest.
	expiries.delete(key);
	if (expiries.size >= NEGATIVE_MAX_ENTRIES) {
		const oldest = expiries.keys().next();
		if (!oldest.done) expiries.delete(oldest.value);
	}
	expiries.set(key, Date.now() + NEGATIVE_TTL_MS);
}

/**
 * Forget every entry for this sender as seen by this agent: a distribution
 * from them was just ingested, so what was missing may be here now.
 */
export function clearSender(agentId: string, senderAgentId: string): void {
	const agent = agentId.toLowerCase();
	const sender = senderAgentId.toLowerCase();
	for (const key of [...expiries.keys()]) {
		const [a, , s] = JSON.parse(key) as string[];
		if (a === agent && s === sender) expiries.delete(key);
	}
}

/** (agent, message id) to the scans in a row that row has failed. Insertion order is age. */
const rowFailures = new Map<string, number>();

/**
 * Fold one scan's per-row outcome into the failure counts and say how many of
 * its failed rows still count against the scan's completeness: a row that
 * opened loses its count, a row that threw gains one, and a row past
 * {@link ROW_FAILURE_LIMIT} consecutive failures is no longer counted.
 */
export function settleRowFailures(
	agentId: string,
	openedIds: readonly string[],
	failedIds: readonly string[],
): number {
	const keyOf = (id: string) =>
		JSON.stringify([agentId.toLowerCase(), id.toLowerCase()]);
	const failedSet = new Set(failedIds);
	for (const id of openedIds) {
		if (!failedSet.has(id)) rowFailures.delete(keyOf(id));
	}
	let counted = 0;
	for (const id of failedSet) {
		const key = keyOf(id);
		const streak = (rowFailures.get(key) ?? 0) + 1;
		rowFailures.delete(key);
		if (rowFailures.size >= NEGATIVE_MAX_ENTRIES) {
			const oldest = rowFailures.keys().next();
			if (!oldest.done) rowFailures.delete(oldest.value);
		}
		rowFailures.set(key, streak);
		if (streak <= ROW_FAILURE_LIMIT) counted++;
	}
	return counted;
}
