/**
 * Every gap marker on disk for an agent.
 *
 * The markers ({@link ./mls-escrow-gap.js}) are what remembers an epoch with no
 * escrow, so a surface that reports a recovery lists them from here rather than
 * relying on news a background sweep kept in memory: a process that exits before
 * a result carried that news loses only the memory, never the marker. The Python
 * twin is `rine/_mls/escrow_gap_list.py`.
 */
import type { GapReason } from "./mls-escrow-gap.js";
import { groupMarkers } from "./mls-escrow-markers.js";
import { groupPendingDir, pendingGroupDirs } from "./mls-escrow-pending.js";

/**
 * One marker: an epoch of a group with no escrow, and why. The keys are
 * snake-case, as in the recovery report that carries it and in the Python twin.
 */
export interface GapMarker {
	agent_id: string;
	group_id: string;
	epoch: number;
	/** The fork's fingerprint (32 hex), when the marker names one. */
	fork?: string;
	reason: GapReason;
}

/**
 * Every gap marker on disk for `agentId`, across its groups, sorted by group,
 * then name. A marker whose text names no known reason is left out, as
 * `readGap` leaves it out.
 */
export function listGapMarkers(configDir: string, agentId: string): GapMarker[] {
	return pendingGroupDirs(configDir, agentId)
		.sort()
		.flatMap((groupId) =>
			groupMarkers(groupPendingDir(configDir, agentId, groupId)).map(
				(marker) => ({ agent_id: agentId, group_id: groupId, ...marker }),
			),
		);
}

/**
 * The markers in one line (`<group> epoch 4 (refused), ...`), for a surface that
 * prints prose. A marker that names a fork carries its first eight hex digits,
 * so two forks of one epoch read as two.
 */
export function describeGapMarkers(markers: readonly GapMarker[]): string {
	return markers
		.map(
			({ group_id, epoch, fork, reason }) =>
				`${group_id} epoch ${epoch}${fork === undefined ? "" : ` fork ${fork.slice(0, 8)}`} (${reason})`,
		)
		.join(", ");
}
