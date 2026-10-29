/**
 * The epochs a background sweep lost, held until the next result for their group
 * reports them.
 *
 * A sweep runs on its own, with no caller waiting for a result, so the epochs it
 * gives up have nowhere to go: the gap markers on disk record them, but the next
 * sync, join or admission result is what a caller reads. This holds those epochs
 * in memory between the two, keyed by the config dir and agent and tagged with
 * their group, so the next result for that group can report them and clear
 * them, and no other group's result claims them. Memory only: a crash loses
 * nothing that the markers do not already hold.
 *
 * The Python twin is `rine/_mls/escrow_handoff.py`.
 */
import type { DrainGap } from "./mls-escrow-gap.js";
import { ProcessGate, actorGateKey } from "./process-gate.js";

/** An epoch with no escrow, and the group it belongs to. */
export interface GroupGap {
	groupId: string;
	gap: DrainGap;
}

const unreported = new ProcessGate<GroupGap[]>();

/** Hold the epochs a sweep lost until the next result for their group reports them. */
export function noteUnreported(
	configDir: string,
	agentId: string,
	gaps: Iterable<GroupGap>,
): void {
	const noted = [...gaps];
	if (noted.length === 0) return;
	const k = actorGateKey({ configDir, agentId });
	unreported.set(k, [...(unreported.get(k) ?? []), ...noted]);
}

/** The epochs of `groupId` noted since the last take, in order, clearing them; other groups' stay. */
export function takeUnreported(
	configDir: string,
	agentId: string,
	groupId: string,
): DrainGap[] {
	const k = actorGateKey({ configDir, agentId });
	const held = unreported.get(k) ?? [];
	const mine = held.filter((entry) => entry.groupId === groupId);
	if (mine.length === 0) return [];
	const rest = held.filter((entry) => entry.groupId !== groupId);
	if (rest.length === 0) unreported.delete(k);
	else unreported.set(k, rest);
	return mine.map((entry) => entry.gap);
}
