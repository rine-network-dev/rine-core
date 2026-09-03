import { bytesToHex } from "@noble/curves/utils.js";
/**
 * Leaves the ratchet tree still carries for agents the group no longer
 * entitles, and the pass that retires them.
 *
 * An invitation takes a ratchet-tree leaf the moment its Welcome is minted, but
 * the reaper only frees the **seat** when the invitation lapses. The leaf
 * stays. So a group that churns no-show invitations inflates every later Welcome
 * and every later commit without bound — composed at the 500-member ceiling, 100
 * no-shows make every later commit ~19 % heavier for all 400 real members,
 * forever. A self-leave leaves the same residue: MLS gives nobody a way to
 * commit their own removal, so the leaver's row goes and their leaf does not.
 *
 * 🔴 **Reclamation is never automatic, and it is not admin-gated.** The server
 * holds no MLS keys, so it cannot mint the Remove commit; a group nobody runs
 * the resume verb on with reclamation asked for keeps accumulating leaves.
 * Posting the Remove commit takes membership and no role beyond it
 * (`mls.py:174-175`: "A non-init epoch-advancing commit only requires
 * membership, NOT admin"), so ANY member can run it and post one O(N) Remove
 * per orphan, billed to all. The deterrent is that cost, not a permission check
 * — do not write "admin-initiated". 🔴 Do NOT restate this as "every route this
 * pass calls is member-gated": the pass reads `GET /groups/{id}/members`, which
 * is ORG-gated (`has_read_access` admits any org holding a member agent), and
 * `GET /agents/keys`, which is unauthenticated; the epoch-conflict retry also
 * reads `GET /groups/{id}/mls/handshakes`, whose `require_handshake_reader`
 * grant is looser than membership. The conclusion is right and that reason is
 * not. Write "reclamation bounds the tree", never "expiry bounds the tree" —
 * expiry frees the seat only. A reclaimed leaf is genuinely re-occupiable (MEASURED,
 * `rine-mls-core/tests/leaf_reuse.rs`), which is what makes the bound real.
 *
 * The set is `{tree identities} \ {members ∪ live vouchers}`, and the second
 * half is read from `GET /groups/{id}/requests?outstanding=live` and nowhere
 * else. Computing it from members alone classifies every agent who was
 * legitimately invited and has not accepted yet as an orphan, and evicts all of
 * them.
 *
 * 🔴 **The subtraction is keyed by the signing key each entitled agent
 * publishes right now, and that is a narrower instrument than it looks.** Two
 * populations break it, and only one of them is detectable from here:
 *
 * * An entitled agent whose published key occupies no leaf — a key rotation is
 *   the ordinary cause. Detectable, and {@link reclaimOrphanLeaves} declines
 *   the whole pass and names them rather than reclaiming a seated member's
 *   leaf.
 * * A **revoked** member. `DELETE /agents/{id}` sets `revoked_at` and leaves
 *   both the `GroupMember` row and the ratchet-tree leaf where they are, and
 *   the row is then invisible to every read this pass has: `GET
 *   /groups/{id}/members` filters revoked agents out, and so does `GET
 *   /agents/keys`. So a revoked member enters neither the entitled set nor the
 *   unreadable set, and its leaf is reclaimed as an orphan. That leaves a
 *   member row with no leaf — recoverable, because the path-only rescue
 *   can still declare and remove it, but it costs an O(N) commit nobody asked
 *   for. Closing it needs a server view of membership that includes revoked
 *   agents; no client-side read distinguishes the two today, and no surface may
 *   claim this pass covers the revoked case.
 */
import type { MlsGroup } from "@rine-network/mls";
import { openMlsGroup } from "./crypto/mls.js";
import type { HttpClient } from "./http.js";
import {
	fetchGroupTree,
	fetchMlsIdentities,
	isSeated,
	leafIndexOf,
} from "./mls-admission-tree.js";
import { type MlsReclamationResult, admissionKey } from "./mls-admission.js";
import { isEpochConflict, postMlsCommit } from "./mls-commit.js";
import { syncMlsGroup } from "./mls-ops-sync.js";

/** A ratchet-tree leaf no membership and no live voucher entitles. */
export interface OrphanLeaf {
	/** The leaf's index at the epoch it was enumerated at. */
	index: number;
	/** Its occupant's MLS basic-credential identity — a raw Ed25519 key. */
	identity: Uint8Array;
}

/** Set-difference key for a raw identity, so byte arrays can be compared. */
function identityKey(identity: Uint8Array): string {
	return bytesToHex(identity);
}

/**
 * The leaves in `group`'s tree that none of `entitled` occupies.
 *
 * Local and exact: `memberIdentities()` enumerates every occupied leaf and no
 * blanked one, and each index it reports round-trips through `memberIndex`
 * (MEASURED on both suites). Before that enumeration existed the whole
 * tree-query surface was identity → index, so this set could not be constructed
 * by any client at all.
 *
 * This agent's own leaf is excluded unconditionally rather than by trusting the
 * membership read. An agent that self-evicts can neither commit nor recover, and
 * a reclamation pass is exactly where a mis-read member list would do it.
 */
export function orphanLeaves(
	group: MlsGroup,
	entitled: Iterable<Uint8Array>,
): OrphanLeaf[] {
	const keys = new Set<string>();
	for (const identity of entitled) keys.add(identityKey(identity));
	const own = group.currentMemberIndex();
	return group
		.memberIdentities()
		.filter(
			(leaf) => leaf.index !== own && !keys.has(identityKey(leaf.identity)),
		)
		.map((leaf) => ({ index: leaf.index, identity: leaf.identity }));
}

/**
 * Post one Remove commit for the leaf `identity` holds **right now**, and report
 * the epoch it landed at. `null` when that identity holds no leaf any more.
 *
 * State and leaf index are both re-read here rather than carried in: a leaf
 * index is only true of the epoch it was read at, and each removal in a pass
 * moves the epoch.
 *
 * Deliberately declares nothing. `removes` names **agent ids**, and an
 * orphan's leaf is precisely the one no server route can name — it holds no
 * member row and no live voucher, and there is no identity → agent lookup. A
 * commit that declares nothing can authorise no `DELETE`, which is the correct
 * answer here: an orphan has no member row to delete.
 */
async function commitOrphanRemoval(
	configDir: string,
	agentId: string,
	groupId: string,
	identity: Uint8Array,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<number | null> {
	const group = openMlsGroup(configDir, agentId, groupId);
	const leafIndex = leafIndexOf(group, identity);
	if (leafIndex === null) return null;
	const bundle = group.removeMember(leafIndex);
	const epoch = await postMlsCommit(
		{ configDir, agentId, client },
		groupId,
		group,
		bundle,
		[],
		extraHeaders,
	);
	// Adopted only after the server accepted it, so a refused commit leaves no
	// forked local state for the next leaf in the pass to build on.
	group.save();
	return epoch;
}

/** The first three of a named set, plus a count for the rest. */
function namedFew(agentIds: string[]): string {
	const named = agentIds.slice(0, 3).join(", ");
	return agentIds.length > 3
		? `${named}, and ${agentIds.length - 3} more`
		: named;
}

/**
 * The sentence an unreadable entitled agent earns, naming who it was.
 *
 * Deliberately does NOT claim to cover a revoked member: `GET
 * /groups/{id}/members` filters revoked agents out, so one never reaches this
 * set at all (see this module's header). What does reach it is an agent holding
 * a live voucher whose key the server no longer publishes — an invitation
 * outlives the revocation of the agent it names.
 */
function unreadableDetail(unreadable: string[]): string {
	return (
		`Reclaimed nothing: ${unreadable.length} agent(s) this group entitles to a ` +
		`seat publish no readable signing key (${namedFew(unreadable)}), so their ` +
		"leaves cannot be told apart from an orphan's. An agent the group still " +
		"holds a seat for is entitled to it, and dropping its leaf would leave an " +
		"entitlement with no leaf behind it."
	);
}

/**
 * The sentence a member whose published key occupies no leaf earns.
 *
 * A member always holds a leaf — that is what admission committed. So a member
 * whose published signing key matches none of them means the two have come
 * apart, and the ordinary cause is a key rotation: `POST /agents/{id}/keys` has
 * no MLS guard, so `rine keys rotate` changes what this pass subtracts while
 * the leaf keeps carrying the credential the group was founded on. Reclaiming
 * then evicts a seated member — the epoch advances, the group stops opening for
 * them, their member row is untouched, and the pass reports only a count.
 *
 * So the pass declines and names them, exactly as {@link unreadableDetail}
 * does, and for the same reason: an ambiguity between a member's leaf and an
 * orphan's is not a licence to remove either.
 */
function unseatedDetail(unseated: string[]): string {
	return (
		`Reclaimed nothing: ${unseated.length} member(s) of this group publish a ` +
		`signing key that occupies no leaf in its ratchet tree ` +
		`(${namedFew(unseated)}), so this group's membership and its tree have ` +
		"come apart and no leaf can be attributed. A member that rotated its " +
		"signing key looks exactly like this; its leaf still carries the key it " +
		"published before, and removing that leaf would evict a seated member. " +
		"Have them rejoin the group, or remove them and invite them again, and " +
		"run this pass afterwards."
	);
}

/**
 * Retire every leaf this group's members and live vouchers do not account for.
 *
 * One Remove commit per leaf, each O(N) and billed to every member — the native
 * core removes one leaf at a time, so a group carrying 100 orphans pays 100
 * commits to reclaim them. That is a one-off against a weight every future
 * commit would otherwise carry.
 *
 * A lost epoch CAS is ordinary rather than exceptional here: the pass is a
 * sequence of commits against a group that is free to move underneath it. The
 * first conflict syncs and retries that leaf once; a second ends the pass and
 * reports what landed, because an unbounded retry against an advancing epoch is
 * a self-DoS.
 *
 * 🔴 It refuses to act at all on either ambiguity between a member's leaf and
 * an orphan's: an entitled agent whose signing key is unreadable
 * ({@link unreadableDetail}), and a member whose published key occupies no leaf
 * ({@link unseatedDetail}). Both mean a leaf cannot be attributed, and a
 * destructive pass that cannot attribute a leaf must decline rather than guess.
 * The one ambiguity it CANNOT see is a revoked member — see this module's
 * header.
 *
 * One race it cannot close, and does not pretend to: an agent whose invitation
 * lapsed and who is re-invited between the tree read and the Remove commit loses
 * the fresh leaf too. Their membership is untouched, and the next resume seats
 * them again.
 */
export async function reclaimOrphanLeaves(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<MlsReclamationResult> {
	const tree = await fetchGroupTree(client, groupId, extraHeaders);
	// The WIDER of the two voucher populations. A `pending` self-applicant holds
	// no leaf today, so counting them can only ever decline to reclaim a leaf,
	// never wrongly evict one — the safe direction for a destructive pass.
	const entitledIds = [...tree.members, ...tree.outstanding];
	const identities = await fetchMlsIdentities(
		client,
		entitledIds,
		extraHeaders,
	);
	const unreadable = entitledIds.filter(
		(id) => !identities.has(admissionKey(id)),
	);
	const group = openMlsGroup(configDir, agentId, groupId);
	if (unreadable.length > 0) {
		return {
			found: 0,
			reclaimed: 0,
			commits: 0,
			epoch: group.epoch(),
			declined: {
				reason: "identity_unknown",
				detail: unreadableDetail(unreadable),
			},
		};
	}

	// Members only. An outstanding invitee legitimately holds no leaf yet — its
	// Welcome may not have been minted — so requiring one of them would decline
	// every pass on a group with an unaccepted invitation.
	const unseated = tree.members.filter((id) => {
		const identity = identities.get(admissionKey(id));
		return identity !== undefined && !isSeated(group, identity);
	});
	if (unseated.length > 0) {
		return {
			found: 0,
			reclaimed: 0,
			commits: 0,
			epoch: group.epoch(),
			declined: {
				reason: "identity_unseated",
				detail: unseatedDetail(unseated),
			},
		};
	}

	const orphans = orphanLeaves(group, identities.values());
	let epoch = group.epoch();
	let commits = 0;
	let reclaimed = 0;
	for (const orphan of orphans) {
		let landed: number | null;
		try {
			landed = await commitOrphanRemoval(
				configDir,
				agentId,
				groupId,
				orphan.identity,
				client,
				extraHeaders,
			);
		} catch (err) {
			if (!isEpochConflict(err)) throw err;
			await syncMlsGroup(configDir, agentId, groupId, client, extraHeaders);
			try {
				landed = await commitOrphanRemoval(
					configDir,
					agentId,
					groupId,
					orphan.identity,
					client,
					extraHeaders,
				);
			} catch (retryErr) {
				if (!isEpochConflict(retryErr)) throw retryErr;
				break;
			}
		}
		// null means somebody else's commit already took this leaf — an answer,
		// not a failure, and the pass simply owes one fewer commit.
		if (landed === null) continue;
		epoch = landed;
		commits += 1;
		reclaimed += 1;
	}
	return { found: orphans.length, reclaimed, commits, epoch };
}
