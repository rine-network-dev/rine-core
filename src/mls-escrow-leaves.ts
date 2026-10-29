/**
 * One orphan reclamation when a group's tree outgrew the escrow bound.
 *
 * The native core cannot escrow an epoch whose ratchet tree holds more leaves
 * than the bound, and files it as a `too_many_leaves` gap. Orphaned leaves
 * (members who left without committing their own removal) are the usual reason
 * a tree is larger than its roster, so a send that meets such a gap runs the
 * reclamation once for the group, then drains the epoch it produced and looks
 * again.
 *
 * Once per (config dir, agent, group, gap epoch) per process: a reclamation is
 * one O(N) commit per orphan, billed to every member, so it is never repeated to
 * see whether the gap went away. A later, distinct gap is a new case and gets its
 * own; a failed attempt counts as the one for its gap. The Python twin is
 * `reclaim_once_for_gap` in `rine/_mls/escrow_leaves.py`.
 */
import type { PeerActor } from "./mls-allowed.js";
import { reclaimOrphanLeaves } from "./mls-orphans.js";
import { ProcessGate, actorGateKey } from "./process-gate.js";

const attempted = new ProcessGate();

/**
 * Run the orphan reclamation unless this process already did for the gap at
 * `epoch`. Best effort: a reclamation that fails or declines leaves the gap
 * standing, and the send reports it.
 *
 * @returns true when a reclamation ran now, so the caller should drain and look again.
 */
export async function reclaimOnceForGap(
	actor: PeerActor,
	groupId: string,
	epoch: number,
): Promise<boolean> {
	const gate = actorGateKey(actor, groupId, epoch);
	if (attempted.has(gate)) return false;
	attempted.set(gate, true);
	try {
		await reclaimOrphanLeaves(
			actor.configDir,
			actor.agentId,
			groupId,
			actor.client,
			actor.extraHeaders,
		);
	} catch {
		// Best effort by design: the gap stands and the send reports it.
	}
	return true;
}
