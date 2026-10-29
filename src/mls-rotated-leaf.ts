/**
 * The resync an agent cannot make while its leaf carries a key it has rotated
 * away from, said truthfully.
 *
 * A rotation moves the agent's own leaf to its new key from a device that holds
 * the group's state. Where that never happened (the update had not landed when
 * the device was lost, or the seat is one no update can move), the leaf still
 * carries the earlier key. A resync replaces the agent's own leaf and signs with
 * its current key, which the core refuses for a leaf of another generation,
 * either by naming the agent or as a resync that changes the key. This module
 * turns both refusals into a typed outcome carrying the remedy that exists: a
 * member removes the agent and invites it again.
 */
import {
	MLS_ERR_PEER_NOT_ADMITTED,
	MLS_ERR_RESYNC_CHANGES_KEY,
	MLS_ERR_ROTATED_LEAF,
	mlsErrorCode,
} from "./crypto/mls-errors.js";
import { admissionKey } from "./mls-admission.js";
import type { PeerActor } from "./mls-allowed.js";
import {
	type RefusalSource,
	admitRefusedPeers,
	refusedAgentId,
} from "./mls-commit-admission.js";

/** The sentence every surface shows for an agent whose leaf cannot be moved from this device. */
export function rotatedLeafMessage(agentId: string, groupId: string): string {
	return (
		`Agent ${agentId}'s leaf in group ${groupId} still carries a key it has ` +
		"since rotated away from, and this device holds no group state that can " +
		"move it; a member must remove the agent and invite it again before it " +
		"can resync."
	);
}

/**
 * A resync refused because the agent's leaf in the group is an older generation
 * of its key.
 *
 * It carries no `cause`, deliberately: every renderer concatenates an error with
 * its cause, and the core's sentence about an unadmitted leaf is the misleading
 * text this replaces.
 */
export class MlsRotatedLeafError extends Error {
	readonly code = MLS_ERR_ROTATED_LEAF;

	constructor(
		public readonly agentId: string,
		public readonly groupId: string,
	) {
		super(rotatedLeafMessage(agentId, groupId));
		this.name = "MlsRotatedLeafError";
	}
}

/** True for {@link MlsRotatedLeafError}, matched on its code. */
export function isMlsRotatedLeaf(err: unknown): boolean {
	return (
		(err as { code?: unknown } | null | undefined)?.code ===
		MLS_ERR_ROTATED_LEAF
	);
}

/** True when the core refused a resync by the acting agent that would change its leaf's key. */
function isOwnResyncKeyChange(err: unknown, agentId: string): boolean {
	return (
		mlsErrorCode(err) === MLS_ERR_RESYNC_CHANGES_KEY &&
		err instanceof Error &&
		err.message.toLowerCase().includes(admissionKey(agentId))
	);
}

/**
 * {@link admitRefusedPeers}, except that a final refusal naming the acting agent
 * itself, or a resync by it that would change its leaf's key, becomes a
 * {@link MlsRotatedLeafError}.
 *
 * The acting agent's current key is always in its own allowed set, so the core
 * refusing the agent's own id after the admission loop is final means the leaf
 * it sits on carries another generation of that key.
 */
export async function admitRefusingRotatedLeaf<T>(
	actor: PeerActor,
	source: RefusalSource,
	groupId: string,
	attempt: () => T,
): Promise<T> {
	try {
		return await admitRefusedPeers(actor, source, attempt);
	} catch (err) {
		if (
			(mlsErrorCode(err) === MLS_ERR_PEER_NOT_ADMITTED &&
				refusedAgentId(source) === admissionKey(actor.agentId)) ||
			isOwnResyncKeyChange(err, actor.agentId)
		) {
			throw new MlsRotatedLeafError(actor.agentId, groupId);
		}
		throw err;
	}
}
