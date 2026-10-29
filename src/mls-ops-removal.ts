/**
 * Taking one member out of an MLS group's ratchet tree, and declaring that the
 * commit did so.
 *
 * Two facts shape everything here. A `GroupMember` row is not an eviction — the
 * leaf stays in the tree and every epoch secret the evicted agent holds stays
 * valid — so a kick costs a real Remove commit. And the server
 * spends a **declaration**: `DELETE /groups/{id}/members/{id}` is authorised
 * only by a commit that named this target and has not been spent on them yet,
 * so a commit posted without `removes` can be named in no removal at all.
 */

import { ascii } from "./crypto/bytes.js";
import type { HttpClient } from "./http.js";
import { admissionKey } from "./mls-admission.js";
import { leafIndexOf } from "./mls-admission-tree.js";
import { openPeerMlsGroup } from "./mls-allowed.js";
import { admitGroupPeers } from "./mls-allowed-tree.js";
import { admitRefusedPeers } from "./mls-commit-admission.js";
import { postMlsCommit, retryOnEpochConflict } from "./mls-commit.js";
import { whenCommitPending } from "./mls-commit-pending.js";
import { drainEscrow } from "./mls-escrow-drain.js";
import { type EscrowReport, reportDrain } from "./mls-escrow-report.js";
import { syncMlsGroup } from "./mls-ops-sync.js";

/** What one Remove commit did, and what it was able to do. */
export interface MlsRemovalCommit {
	/**
	 * The epoch the commit landed at — what `mls_removal_epoch` must name on
	 * the DELETE, and only while it is still the group's current epoch.
	 */
	epoch: number;
	/**
	 * True when a leaf was actually taken out of the ratchet tree. False when no
	 * leaf carries the target's agent id and the commit only **declared** the
	 * removal — the stranded-removal rescue below. Surfaces that describe a
	 * removal must branch on it: telling an operator that a leaf was evicted when
	 * none was is a false report.
	 */
	removedLeaf: boolean;
	/** The escrow work this removal did, one drain for the commit it posted. */
	escrow: EscrowReport;
}

/**
 * Post one commit that declares the removal of `memberAgentId`, and adopt the
 * epoch it lands at.
 *
 * The leaf is resolved from the agent id: the credential identity of every leaf
 * is the id of the agent that holds it, and a rotation, a revoked agent or a
 * revoked branch changes none of that. So whenever a leaf names the target the
 * commit is an inline Remove and the leaf goes. When no leaf names it, the
 * commit is **path-only** — `addMembers([])`, a commit with no proposals but a
 * fresh UpdatePath — and it still declares the target.
 *
 * 🔴 **The path-only case is the point, not a degenerate corner.**
 * A removal whose commit landed and whose DELETE then failed is stuck
 * forever otherwise: the leaf is already out of the tree, so no further Remove
 * can be built for it, so the client can produce no epoch, so the server's gate
 * refuses every retry and the member row survives its own eviction. The
 * path-only commit is the honest way out. It does not claim to have evicted
 * anybody — the leaf was already gone, or the member was never seated — and
 * what it *does* prove is exactly what the gate is entitled to ask for: that
 * the caller is still an admitted member committing to this group at this
 * epoch, and that it named this target before it knew which DELETE would land.
 * Do not "simplify" it back to returning null when there is no leaf; that is the
 * defect.
 *
 * Both the local state and the leaf index are read fresh here rather than
 * passed in, and the leaf index is the load-bearing one: a refused commit
 * already mutated the handle that built it, and a leaf index read before
 * another commit landed is not the leaf index after it.
 */
async function commitRemoval(
	configDir: string,
	agentId: string,
	groupId: string,
	memberAgentId: string,
	memberIdentity: Uint8Array,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<MlsRemovalCommit> {
	const actor = { configDir, agentId, client, extraHeaders };
	// The Remove commit meets the other members' leaves, so the group's
	// chain-verified peers must be admitted before it is built.
	await admitGroupPeers(actor, groupId);
	const group = openPeerMlsGroup(actor, groupId);
	const leafIndex = leafIndexOf(group, memberIdentity);
	const bundle = await whenCommitPending(groupId, () =>
		admitRefusedPeers(actor, group, () =>
			leafIndex === null ? group.addMembers([]) : group.removeMember(leafIndex),
		),
	);
	const epoch = await postMlsCommit(
		{ configDir, agentId, client },
		groupId,
		bundle,
		[],
		extraHeaders,
		[memberAgentId],
	);
	// Adopted only after the server accepted it, so a refused commit leaves no
	// forked local state behind. The drain saves the group itself, after sealing
	// this epoch's escrow to disk.
	const outcome = await drainEscrow(actor, groupId, group);
	return { epoch, removedLeaf: leafIndex !== null, escrow: reportDrain(actor, groupId, outcome) };
}

/**
 * Remove one member from an MLS group and post the commit that authorises it.
 * The evicted member reads no message committed after this epoch.
 *
 * The target is named by its **agent id**, which is both what the declaration
 * carries and what the ratchet-tree leaf is resolved from: the leaf's
 * credential identity is that id, so the leaf that is taken and the name that
 * is declared can never be two different members. No key is read from the
 * server, so an agent the server publishes no keys for (revoked, on a revoked
 * branch, gone) and an agent that rotated are removed by a real Remove commit
 * as long as a leaf names them. A leaf index is never accepted from a caller,
 * because a leaf index is only true of the epoch it was read at.
 *
 * A member no leaf names takes the path-only commit instead, which still
 * declares the target, so a member whose leaf is already out can be dropped
 * from the group instead of being unremovable.
 *
 * The returned epoch is what `DELETE /groups/{id}/members/{agent_id}` must be
 * given as the **query parameter** `mls_removal_epoch`, and it must still be
 * the group's current epoch when that request lands. Sending it in a JSON body
 * — the shape every other rine mutation uses — binds nothing server-side, and
 * the removal is then refused for want of the commit the client just posted.
 *
 * Losing the epoch CAS is expected rather than exceptional: a removal is an
 * O(N) commit against a group that is free to move while it is in flight. The
 * lost race is answered by syncing to the group's current epoch and rebuilding
 * the commit once. A second failure is surfaced, not retried — and the member
 * row must stay put when it is: without a commit at the current epoch the
 * removal would rest on the server's delivery filter and nothing else.
 *
 * @throws when this agent holds no local state for the group, when its own leaf
 * has been evicted, or when the second attempt is refused too.
 */
export async function removeMlsGroupMember(
	configDir: string,
	agentId: string,
	groupId: string,
	memberAgentId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<MlsRemovalCommit> {
	const identity = ascii(admissionKey(memberAgentId));
	// The commit that won the race may have blanked this member's leaf, and a
	// later add may have refilled it with somebody else, so every attempt
	// re-reads the leaf from the identity rather than reusing the index an
	// earlier one resolved. Reusing it removes whoever now sits there.
	const attempt = () =>
		commitRemoval(
			configDir,
			agentId,
			groupId,
			memberAgentId,
			identity,
			client,
			extraHeaders,
		);
	let firstConflict: unknown;
	try {
		return await retryOnEpochConflict(attempt, async (conflict) => {
			await syncMlsGroup(configDir, agentId, groupId, client, extraHeaders);
			firstConflict = conflict;
		});
	} catch (err) {
		if (firstConflict === undefined) throw err;
		const detail = err instanceof Error ? err.message : String(err);
		throw new Error(
			`Removing a member's leaf from MLS group ${groupId} failed after one ` +
				`retry (a peer's commit landed first): ${detail}`,
			{ cause: firstConflict },
		);
	}
}
