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

import { openMlsGroup } from "./crypto/mls.js";
import type { HttpClient } from "./http.js";
import { fetchMlsIdentities, leafIndexOf } from "./mls-admission-tree.js";
import { isEpochConflict, postMlsCommit } from "./mls-commit.js";
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
	 * leaf carried the target's **currently published** signing key and the
	 * commit only **declared** the removal — the stranded-removal rescue below.
	 * Surfaces that describe a removal must branch on it: telling an operator that
	 * a leaf was evicted when none was is a false report.
	 *
	 * 🔴 `false` is not the same fact as "they hold no leaf". It is "no leaf
	 * matches the key they publish now", and the two come apart when the target
	 * rotated its signing key — see {@link commitRemoval}. Surfaces say the
	 * narrower thing.
	 */
	removedLeaf: boolean;
}

/**
 * Post one commit that declares the removal of `memberAgentId`, and adopt the
 * epoch it lands at.
 *
 * When that agent still holds a leaf, the commit is an inline Remove and the
 * leaf goes. When it holds none, the commit is **path-only** — `addMembers([])`,
 * a commit with no proposals but a fresh UpdatePath — and it still declares the
 * target.
 *
 * 🔴 **The path-only case is the point, not a degenerate corner.**
 * A removal whose commit landed and whose DELETE then failed is stuck
 * forever otherwise: the leaf is already out of the tree, so no further Remove
 * can be built for it, so the client can produce no epoch, so the server's gate
 * refuses every retry and the member row survives its own eviction. The
 * path-only commit is the honest way out. It does not claim to have evicted
 * anybody — the leaf was already gone — and what it *does* prove is exactly
 * what the gate is entitled to ask for: that the caller is still an admitted
 * member committing to this group at this epoch, and that it named this target
 * before it knew which DELETE would land. Do not "simplify" it back to
 * returning null when there is no leaf; that is the defect.
 *
 * Both the local state and the leaf index are read fresh here rather than
 * passed in, and the leaf index is the load-bearing one: a refused commit
 * already mutated the handle that built it, and a leaf index read before
 * another commit landed is not the leaf index after it.
 *
 * 🔴 **What "no leaf" actually means here, because it is narrower than it
 * reads.** The leaf is resolved from the signing key the target publishes
 * *now*, so three states arrive as one:
 *
 * 1. The server publishes no key for them at all — revoked, or gone. They hold
 *    no leaf this group can name, and the path-only commit is right.
 * 2. Their leaf is already out: the stranded-removal rescue, which is
 *    what this path exists for. Right again.
 * 3. They rotated their signing key. `POST /agents/{id}/keys` has no MLS guard,
 *    so the tree still carries a leaf under the credential they published
 *    before — and this removal completes as a delivery-filter removal with
 *    every epoch secret that leaf holds still valid, which is the state a real
 *    Remove commit exists to prevent.
 *
 * (2) and (3) are indistinguishable from here: there is no identity → agent
 * lookup, so an unattributed leaf cannot be attributed to this target. The
 * removal therefore proceeds — refusing would break the rescue this path was
 * built for — and every surface says the narrow, true thing: no leaf carries
 * the key they publish now. Closing (3) needs key rotation to commit a
 * self-update into every MLS group the agent is in; until it does,
 * `reclaimOrphanLeaves` declines to run at all on a group in this state and
 * names the member (`mls-orphans.ts`), which is where an operator sees it.
 */
async function commitRemoval(
	configDir: string,
	agentId: string,
	groupId: string,
	memberAgentId: string,
	memberIdentity: Uint8Array | null,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<MlsRemovalCommit> {
	const group = openMlsGroup(configDir, agentId, groupId);
	const leafIndex =
		memberIdentity === null ? null : leafIndexOf(group, memberIdentity);
	const bundle =
		leafIndex === null ? group.addMembers([]) : group.removeMember(leafIndex);
	const epoch = await postMlsCommit(
		client,
		groupId,
		group,
		bundle,
		[],
		extraHeaders,
		[memberAgentId],
	);
	group.save();
	return { epoch, removedLeaf: leafIndex !== null };
}

/**
 * Remove one member from an MLS group and post the commit that authorises it.
 * The evicted member reads no message committed after this epoch.
 *
 * The target is named by its **agent id**, which is both what the declaration
 * carries and what the ratchet-tree leaf is resolved from: this reads the
 * agent's MLS basic-credential identity — its raw Ed25519 signing key — through
 * {@link fetchMlsIdentities}, so the leaf that is taken and the name that is
 * declared can never be two different members. A leaf index is never accepted
 * from a caller, because a leaf index is only true of the epoch it was read at.
 *
 * An agent the server publishes no signing key for — revoked, or gone — has no
 * identity to resolve and therefore no leaf to name. That is not a failure and
 * no longer a dead end: the commit is path-only and still declares them, so a
 * revoked member can be dropped from the group instead of being unremovable.
 * An agent whose published key resolves but matches no leaf takes the same
 * path, and {@link commitRemoval} sets out why that is a weaker fact.
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
	const identity =
		(await fetchMlsIdentities(client, [memberAgentId], extraHeaders)).get(
			memberAgentId.toLowerCase(),
		) ?? null;
	try {
		return await commitRemoval(
			configDir,
			agentId,
			groupId,
			memberAgentId,
			identity,
			client,
			extraHeaders,
		);
	} catch (err) {
		if (!isEpochConflict(err)) throw err;
		await syncMlsGroup(configDir, agentId, groupId, client, extraHeaders);
		try {
			// The commit that won the race may have blanked this member's leaf, and a
			// later add may have refilled it with somebody else — so the retry
			// re-reads the leaf from the identity rather than reusing the index the
			// first attempt resolved. Reusing it removes whoever now sits there.
			return await commitRemoval(
				configDir,
				agentId,
				groupId,
				memberAgentId,
				identity,
				client,
				extraHeaders,
			);
		} catch (retryErr) {
			const detail =
				retryErr instanceof Error ? retryErr.message : String(retryErr);
			throw new Error(
				`Removing a member's leaf from MLS group ${groupId} failed after one ` +
					`retry (a peer's commit landed first): ${detail}`,
				{ cause: err },
			);
		}
	}
}
