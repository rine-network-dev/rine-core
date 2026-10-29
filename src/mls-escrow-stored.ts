import type { PeerActor } from "./mls-allowed.js";
import { readHead } from "./mls-escrow-head.js";
import { listPending } from "./mls-escrow-pending.js";

/**
 * Whether an epoch's escrow is stored: the drain sealed it (the head is at the
 * epoch, so a deferral or a gap leaves it behind) and no file of that epoch
 * still waits for an upload. Other epochs' files say nothing about it.
 */
export function epochEscrowStored(
	actor: PeerActor,
	groupId: string,
	epoch: number,
): boolean {
	const head = readHead(actor.configDir, actor.agentId, groupId);
	return (
		head?.epoch === epoch &&
		!listPending(actor.configDir, actor.agentId, groupId).some(
			(pending) => pending.epoch === epoch,
		)
	);
}
