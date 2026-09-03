/**
 * The key-package heartbeat: the one call that makes *"every MLS operation
 * replenishes"* true.
 *
 * Its own module rather than a section of `mls-keypackages.ts`, because it is a
 * different thing from the publishing it wraps — a pace and a process-local
 * floor, not an inventory policy — and because the Python twin is one file
 * about exactly this (`rine-sdk/src/rine/_mls/heartbeat.py`). The two are
 * edited together by rule, so they are shaped alike.
 */

import type { HttpClient } from "./http.js";
import { ensureMlsKeyPackages } from "./mls-keypackages.js";

/** The agent an MLS operation acts as, and the client it acts through. */
export interface MlsActor {
	configDir: string;
	agentId: string;
	client: HttpClient;
}

/**
 * How a heartbeat treats the per-process floor.
 *
 * `gated` is the structural beat: every commit and every sync carries one, so
 * it must be cheap when it has nothing to do. `forced` is for the paths that
 * have just SPENT a key package — founding, adding members, resuming an
 * admission, processing a Welcome — where the inventory provably moved and
 * waiting out a floor would leave the agent short in exactly the window a peer
 * is most likely to add it. Spelled at every call site rather than defaulted:
 * a verb added later has to answer the question rather than inherit an answer.
 */
export type MlsHeartbeatPace = "gated" | "forced";

/**
 * Shortest gap between two gated heartbeats for one (config dir, agent) in one
 * process. Keyed on the agent and not on the group because the inventory is
 * per-agent: ten groups draw down one pool.
 */
export const MLS_HEARTBEAT_MIN_INTERVAL_MS = 60_000;

const lastHeartbeat = new Map<string, number>();

/**
 * Top this agent's key-package inventory back up as a side effect of doing MLS
 * work.
 *
 * It is invoked from {@link postMlsCommit} and {@link syncMlsGroup} rather than
 * from each of the eleven MLS verbs, so a verb added later inherits the
 * heartbeat instead of having to remember it. Without it, zero is an absorbing
 * state: peers claim key packages to mint Welcomes, the pool drains, every
 * further admission degrades to a self-join, and a self-join processes no
 * Welcome — so the agent that most needs a top-up is the one that never gets
 * one, is seated on the roster by a carried vote with no leaf in the ratchet
 * tree, and can read nothing the group says.
 *
 * **Why the floor.** Founding a 500-member group posts one commit per batch of
 * thirteen joiners, so an ungated beat inside `postMlsCommit` would open the
 * store, sweep it twice and derive three asymmetric public keys thirty-nine
 * times for one founding. The first (forced) beat of that founding stamps the
 * gate, so the thirty-nine that follow cost nothing. Per process and
 * deliberately not persisted: a one-shot CLI invocation beats exactly once,
 * which is what is wanted there, and only a long-lived client can spin.
 *
 * 🔴 **The floor is lifted again by a beat that failed.** The stamp is a claim
 * that the maintenance has been done, and a top-up that hit a 429 or a 5xx did
 * not do it. Leaving the stamp standing would hold an agent at inventory zero
 * for the rest of the minute with nothing said, because the failure is
 * swallowed here by design. Stamped BEFORE the call and cleared after, so a
 * batch of commits issued back to back still does not each start a top-up while
 * the first is in flight.
 *
 * Best-effort by contract: it runs behind work that has already succeeded, so
 * it never throws.
 */
export async function mlsHeartbeat(
	actor: MlsActor,
	pace: MlsHeartbeatPace,
): Promise<void> {
	const key = `${actor.configDir} ${actor.agentId}`;
	const previous = lastHeartbeat.get(key);
	const now = Date.now();
	if (
		pace === "gated" &&
		previous !== undefined &&
		now - previous < MLS_HEARTBEAT_MIN_INTERVAL_MS
	) {
		return;
	}
	lastHeartbeat.set(key, now);
	try {
		await ensureMlsKeyPackages(actor.configDir, actor.agentId, actor.client);
	} catch {
		// Retried on the next MLS operation rather than at the end of the floor.
		lastHeartbeat.delete(key);
	}
}

/** Forget every gate. Test-only: a process boundary is what clears it in life. */
export function resetMlsHeartbeatGate(): void {
	lastHeartbeat.clear();
}
