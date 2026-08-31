/**
 * An agent's local MLS group state, as rine's surfaces see it.
 *
 * The state itself — current epoch, retained epoch secrets, the KeyPackage
 * pool, the self-read cache — lives in the native core's store under
 * {@link mlsStoreRoot}. Nothing here reads or writes those files directly:
 * this module is the small read-only view the CLI, the MCP server and the TS
 * SDK use to answer "has this agent joined the MLS group yet?", plus the
 * explicit retirement of a group's state.
 *
 * It also owns the memoized form of that answer ({@link holdsMlsState}) and its
 * invalidation ({@link noteMlsStateChanged}), because the memo and the state it
 * remembers have to be retired together. The Python mirror is
 * `rine/_mls/group_access.py`, with the same three names and the same per-key
 * semantics: a memo whose staleness differs per stack is the same defect class
 * as a guard whose input differs per stack.
 *
 * 🔴 {@link holdsAnyMlsState} is the FOURTH name and is deliberately TypeScript
 * only. Its sole consumer is one CLI sentence — the pointer `rine group get`
 * offers a caller whose group reference answered to nothing — so a
 * Python twin would be a name nothing calls, and an untwinned name is honest
 * where an uncalled one is not. If a Python surface ever needs the same
 * pointer, mint the twin then; do not mint it now against the paragraph above.
 * It is re-exported from here rather than declared here: it reads the store the
 * way {@link ./mls-store-probe.js} reads it, and shares no memo with anything
 * below.
 */
import { type MlsGroup, loadMlsGroup, mlsGroupIdBytes, openMlsClient } from "./mls.js";
import { stateStamp } from "./mls-store-probe.js";

export { holdsAnyMlsState } from "./mls-store-probe.js";

export interface MlsGroupState {
	groupId: string;
	epoch: number;
	/** The group's own suite, read from its group context — what the server stores as `mls_cipher_suite`. */
	cipherSuite: number;
}

function describe(groupId: string, group: MlsGroup): MlsGroupState {
	return {
		groupId,
		epoch: group.epoch(),
		cipherSuite: group.cipherSuite(),
	};
}

/**
 * This agent's state for one group, or null when it holds none — it was never
 * added, its Welcome has not been processed, or the group was retired.
 */
export function loadMlsState(
	configDir: string,
	agentId: string,
	groupId: string,
): MlsGroupState | null {
	const group = loadMlsGroup(openMlsClient(configDir, agentId), groupId);
	return group ? describe(groupId, group) : null;
}

/** One memo entry: the answer, and {@link stateStamp} when it was taken. */
interface Remembered {
	stamp: string | null;
	held: boolean;
}

/**
 * The remembered answers to {@link holdsMlsState}, per
 * `(configDir, agentId, groupId)`. `configDir` is part of the key because one
 * process can serve two config directories and they are two different agents'
 * key material, not two views of one.
 *
 * Bounded by the number of distinct groups the process has asked about.
 */
const heldByKey = new Map<string, Remembered>();

function memoKey(configDir: string, agentId: string, groupId: string): string {
	return JSON.stringify([configDir, agentId, groupId]);
}

/**
 * Whether this agent holds local MLS state for a group.
 *
 * Memoized because the downgrade guard asks it once per row on a group read,
 * and answering it from the native store means opening that store per row. An
 * entry is served only while the group's state file still looks exactly as it
 * did when the answer was taken, so the memo cannot outlive what it remembers:
 * the state is on disk and SHARED — `rine` on the command line and a
 * long-running `rine-mcp` routinely hold one config dir — and no in-process
 * invalidation reaches across that. A join taken from the CLI changes the file,
 * so the server's next read re-asks the store instead of answering "holds none"
 * until it is restarted.
 *
 * {@link noteMlsStateChanged} remains the in-process contract, enforced over
 * the source by `test/crypto/mls-state-writers.test.ts`. It is the tighter of
 * the two — it needs no filesystem evidence — and it covers a state file
 * rewritten so fast that its size and mtime are unchanged.
 */
export function holdsMlsState(
	configDir: string,
	agentId: string,
	groupId: string,
): boolean {
	const key = memoKey(configDir, agentId, groupId);
	const stamp = stateStamp(configDir, agentId, groupId);
	const cached = heldByKey.get(key);
	if (cached !== undefined && cached.stamp === stamp) return cached.held;
	const held = loadMlsState(configDir, agentId, groupId) !== null;
	// No lock, deliberately: this function and everything it calls are
	// synchronous, so nothing in this process runs between the read above and
	// this write — no `await` for the event loop to interleave at, no second
	// thread to preempt it. The Python mirror cannot lean on that (the SDK is
	// used from threads), which is why BOTH stacks key the entry on the stamp
	// sampled BEFORE the read: an entry a mutation overtook stops matching
	// rather than being served. Should this ever become async, that stamp is
	// the only thing left keeping the write-back honest.
	heldByKey.set(key, { stamp, held });
	return held;
}

/**
 * Forget the remembered answer for one group, because this agent's local state
 * for it was just established or retired.
 *
 * Per-key on purpose: a mutating path always knows its own
 * `(configDir, agentId, groupId)`, and a blunt process-wide clear invites
 * "reset it somewhere afterwards" in place of invalidating at the mutation.
 */
export function noteMlsStateChanged(
	configDir: string,
	agentId: string,
	groupId: string,
): void {
	heldByKey.delete(memoKey(configDir, agentId, groupId));
}

/**
 * Retire one group's local state: current state, every retained epoch secret,
 * and the plaintext its self-read cache held.
 *
 * Not recoverable — the epoch secrets are the only copy and no peer can re-send
 * them, so rejoining is the only way back in. Retiring a group that was never
 * there is not an error.
 *
 * This is the only sanctioned retirement point, and it invalidates the memo
 * itself, so no leave path can retire state and leave a stale "holds MLS state"
 * behind to refuse a legitimate billboard read for the rest of the process.
 */
export function deleteMlsState(
	configDir: string,
	agentId: string,
	groupId: string,
): void {
	try {
		openMlsClient(configDir, agentId).deleteGroupState(
			mlsGroupIdBytes(groupId),
		);
	} finally {
		// In `finally`: a delete that threw part-way may still have removed the
		// state, and a memo that outlives it is the stale-positive failure.
		noteMlsStateChanged(configDir, agentId, groupId);
	}
}
