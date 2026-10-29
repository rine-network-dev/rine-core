// The welcome pass classifies the roster read of a Welcome's group before
// opening it: the read's answer decides whether the Welcome can still be used,
// so it is returned as a value rather than thrown.
import { RineApiError } from "./errors.js";
import { type GroupTree, fetchGroupTree } from "./mls-admission-tree.js";
import { type PeerActor } from "./mls-allowed.js";
import { admitTree } from "./mls-allowed-tree.js";

/**
 * What a group's roster said when a Welcome's peers were admitted — the
 * closed set the welcome pass branches on, never collapsed to a boolean.
 *
 * - `admitted`: the roster was read and its chain-verified peers admitted.
 * - `not-seated` (403): this agent holds no seat it can read the roster with.
 *   An invitation it has not accepted yet is the ordinary case: the inviter's
 *   commit minted the Welcome at invite time, and accepting later needs that
 *   same Welcome, because no second one is minted.
 * - `group-gone` (404): the group no longer exists, so no later pass can use
 *   its Welcome.
 * - `unreachable`: anything else — a network failure, a 5xx, a peer key read
 *   that failed. The same read may succeed on the next pass.
 */
export type WelcomeAdmission =
	| "admitted"
	| "not-seated"
	| "group-gone"
	| "unreachable";

/**
 * {@link admitGroupPeers} for a Welcome about to be opened, with the roster
 * read's answer classified instead of thrown.
 *
 * Only the roster read is classified as definitive. A 403 or 404 from a peer's
 * key read says nothing about this agent's place in the group, so a failure
 * after the roster was read is `unreachable`.
 */
export async function admitWelcomePeers(
	actor: PeerActor,
	groupId: string,
): Promise<WelcomeAdmission> {
	let tree: GroupTree;
	try {
		tree = await fetchGroupTree(actor.client, groupId, actor.extraHeaders);
	} catch (err) {
		if (err instanceof RineApiError && err.status === 403) return "not-seated";
		if (err instanceof RineApiError && err.status === 404) return "group-gone";
		return "unreachable";
	}
	try {
		await admitTree(actor, tree);
		return "admitted";
	} catch {
		return "unreachable";
	}
}
