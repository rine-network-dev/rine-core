import { type GroupTree, fetchGroupTree } from "./mls-admission-tree.js";
import { type PeerActor, admitPeers } from "./mls-allowed.js";

/**
 * Admit everyone the server says may hold a leaf in this group: its members and
 * its outstanding vouchers.
 *
 * The wider `outstanding` set is deliberate here — unlike the admit set of a
 * batch, this is the population that may already occupy a leaf, and a leaf this
 * client cannot name is a message it cannot read. Errors from the tree read
 * propagate: an unreadable tree means the population is unknown, and admitting
 * a partial one would silently drop peers.
 *
 * `alsoRead` names agents to put into the same key read, whether or not their
 * keys live on this device, so a caller can learn whether the server still
 * serves them without a request of its own. Returns the ids whose keys the
 * server returned and that verified.
 */
export async function admitGroupPeers(
	actor: PeerActor,
	groupId: string,
	alsoRead: string[] = [],
): Promise<string[]> {
	return admitTree(
		actor,
		await fetchGroupTree(actor.client, groupId, actor.extraHeaders),
		alsoRead,
	);
}

/**
 * Admit the peers of a roster already read, shared by `admitGroupPeers`
 * and `admitWelcomePeers` (mls-welcome-admission.ts).
 */
export function admitTree(
	actor: PeerActor,
	tree: GroupTree,
	alsoRead: string[] = [],
): Promise<string[]> {
	return admitPeers(
		actor,
		[...new Set([...tree.members, ...tree.outstanding])],
		{ alsoRead },
	);
}
