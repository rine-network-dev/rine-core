import type { MlsGroup } from "@rine-network/mls";
import { ascii } from "./crypto/bytes.js";
import { BATCH_KEYS_MAX_IDS, verifyBatchKeys } from "./crypto/batch-keys.js";
import type { VerifiedAgentKeys } from "./crypto/key-chain.js";
import type { BatchKeysResponse } from "./api-types.js";
import { fetchGroupMembers } from "./group-members.js";
import type { HttpClient } from "./http.js";
import {
	type AdmissionLedger,
	type AdmitContext,
	admissionKey,
	recordOutcome,
} from "./mls-admission.js";

/**
 * The leaf `identity` occupies in this tree, or `null` when it occupies none.
 *
 * `memberIndex` reads the in-memory ratchet tree and touches neither disk nor
 * network, so the only way it can fail is by not finding the identity — which
 * is the answer, not an error.
 *
 * 🔴 **A leaf index is only true of the epoch it was read at.** A commit that
 * lands in between can blank a leaf and a later add can refill it with somebody
 * else, so an index held across a sync names a different member than it did
 * when it was read. Resolve it from the identity at the point of use; never
 * carry one over a retry.
 */
export function leafIndexOf(
	group: MlsGroup,
	identity: Uint8Array,
): number | null {
	try {
		return group.memberIndex(identity);
	} catch {
		return null;
	}
}

/** True when `identity`'s leaf is already in the tree. */
export function isSeated(group: MlsGroup, identity: Uint8Array): boolean {
	return leafIndexOf(group, identity) !== null;
}

export async function fetchVerifiedBatchKeys(
	client: HttpClient,
	agentIds: string[],
	extraHeaders?: Record<string, string>,
): Promise<Map<string, VerifiedAgentKeys>> {
	const verified = new Map<string, VerifiedAgentKeys>();
	for (let i = 0; i < agentIds.length; i += BATCH_KEYS_MAX_IDS) {
		const chunk = agentIds.slice(i, i + BATCH_KEYS_MAX_IDS);
		const batch = (await client.get(
			"/agents/keys",
			{ ids: chunk.join(",") },
			extraHeaders,
		)) as BatchKeysResponse;
		for (const [agentId, keys] of verifyBatchKeys(client, batch.keys)) {
			verified.set(agentId, keys);
		}
	}
	return verified;
}

/**
 * Each agent's MLS basic-credential identity — its canonical agent id, as ASCII
 * bytes — for every agent the server returns keys for, fetched in server-sized
 * chunks.
 *
 * This is what tells a seated invitee from an unseated one. An agent whose key
 * the server does not return is simply absent from the map: it is either
 * revoked or gone, and both answers arrive properly named a step later, from
 * the claim (`no_key_package`) or from the commit (`rejected_by_server`).
 *
 * Chunked at {@link BATCH_KEYS_MAX_IDS}, the id cap `GET /agents/keys`
 * enforces. An unchunked read is the live defect this chunking closes on the
 * sender-key side, where one 201-recipient call throws out of a send with
 * nothing distributed at all.
 */
export async function fetchMlsIdentities(
	client: HttpClient,
	agentIds: string[],
	extraHeaders?: Record<string, string>,
): Promise<Map<string, Uint8Array>> {
	const identities = new Map<string, Uint8Array>();
	for (const agentId of (
		await fetchVerifiedBatchKeys(client, agentIds, extraHeaders)
	).keys()) {
		identities.set(admissionKey(agentId), ascii(agentId));
	}
	return identities;
}

/** A group's members, its outstanding invitations, and what they occupy. */
export interface GroupTree {
	/** Agent ids holding a member row, in the server's order. */
	members: string[];
	/**
	 * Agent ids holding a live invitation **somebody issued**, in the server's
	 * order. Deliberately NOT every live voucher — see {@link fetchGroupTree}.
	 */
	invited: string[];
	/**
	 * Every agent id holding a live voucher of any kind, self-applications
	 * included, in the server's order. A superset of {@link GroupTree.invited}.
	 *
	 * This is the population that is **entitled** to a seat, which is a
	 * different question from who may be admitted to one: leaf reclamation
	 * subtracts it (`mls-orphans.ts`) precisely because taking the wider set can
	 * only ever decline to reclaim a leaf, never wrongly evict one.
	 */
	outstanding: string[];
	/**
	 * Distinct agents occupying a ratchet-tree seat: members plus every live
	 * voucher, self-applications included. This is the population the server's
	 * seat ceiling counts, so it is what a batch is priced against — and it
	 * is larger than `members.length + invited.length`.
	 */
	occupancy: number;
}

/** How many ratchet-tree seats this group's populations occupy. */
export function treeSize(tree: GroupTree): number {
	return tree.occupancy;
}

/**
 * The populations that occupy ratchet-tree seats, read from the server.
 *
 * This is the client's view of `count_group_tree_occupancy`: a group's tree
 * holds its members plus everyone it has Welcomed but who has not joined yet.
 * {@link treeSize} is an UPPER bound on the real tree — an
 * invitee whose Welcome has not been minted yet holds no leaf — and upper
 * rather than lower on purpose: over-stating the tree only shrinks the next
 * batch, while under-stating it mints a POST the server refuses.
 *
 * `?outstanding=live` is the only way to learn the unaccepted half. A resume
 * verb that computes the tree from members plus vote requests concludes that
 * every legitimately invited agent holds nothing at all, and the
 * leaf-reclamation rule then tells it to evict all of them.
 *
 * 🔴 **`live` is a wider set than "invited", and the difference is a security
 * boundary.** The server's `live` is `("pending", "invited")`, and a `pending`
 * row is a request **awaiting a vote**, not an invitation anybody may spend:
 * a stranger's self-application, or — on `majority` and `unanimity` — a
 * member's nomination of one. Admitting either hands the group's
 * epoch secret to an agent the electorate may then deny, and no route ever
 * seats a denied applicant, so nothing would ever reclaim the leaf it consumed.
 * `/mls/init`'s founding offer set refuses to carry them for exactly this
 * reason (`invitation_criteria`), but that predicate guards a
 * different route: this one reads `?outstanding=live`, which is deliberately
 * the wider set. Splitting the two populations here is what keeps a client
 * from re-opening it by admitting everything it was handed.
 *
 * 🔴 It is the **status** that keeps a nomination out, not `invited_by`: a
 * nomination carries an inviter, so the second half of the filter no longer
 * discriminates between the two kinds of `pending` row. Both halves stay —
 * together they are the server's own `invitation_criteria` predicate — but a
 * reader must not conclude from `invited_by` alone that a row was invited.
 *
 * So: {@link GroupTree.invited} is the admit set, {@link GroupTree.occupancy}
 * is the count. They are not the same population and must not be conflated.
 */
export async function fetchGroupTree(
	client: HttpClient,
	groupId: string,
	extraHeaders?: Record<string, string>,
): Promise<GroupTree> {
	const members = (await fetchGroupMembers(client, groupId, extraHeaders)).map(
		(item) => item.agent_id,
	);
	const requests = (await client.get(
		`/groups/${groupId}/requests`,
		{ outstanding: "live" },
		extraHeaders,
	)) as {
		items?: { agent_id: string; status?: string; invited_by?: string | null }[];
	};
	const live = requests.items ?? [];
	const occupied = new Set(members.map(admissionKey));
	for (const row of live) occupied.add(admissionKey(row.agent_id));
	return {
		members,
		invited: live
			.filter((row) => row.status === "invited" && row.invited_by)
			.map((row) => row.agent_id),
		outstanding: live.map((row) => row.agent_id),
		occupancy: occupied.size,
	};
}

/**
 * The requested ids that still need a leaf, seeded into `ledger` in request
 * order.
 *
 * Dropping the ids already in the tree is what makes every caller of this a
 * resume: an agent whose leaf resolves is reported `already_in_group` rather
 * than costing a second leaf and a wasted one-time KeyPackage. The acting agent
 * is always in its own group, so it drops here too and never needs a lookup.
 *
 * `group` is null only while founding, where there is no tree to consult yet.
 */
export async function resolveUnseated(
	ctx: AdmitContext,
	group: MlsGroup | null,
	requested: string[],
	ledger: AdmissionLedger,
): Promise<string[]> {
	const self = admissionKey(ctx.agentId);
	const wanted: string[] = [];
	for (const agentId of requested) {
		if (ledger.has(admissionKey(agentId))) continue;
		if (admissionKey(agentId) === self) {
			recordOutcome(ledger, agentId, "skipped", "already_in_group");
			continue;
		}
		// Seeded as the outcome of an admission that got no further than asking
		// for this agent's KeyPackage; the claim or the commit replaces it.
		recordOutcome(ledger, agentId, "skipped", "no_key_package");
		wanted.push(agentId);
	}
	if (group === null || wanted.length === 0) return wanted;

	const identities = await fetchMlsIdentities(
		ctx.client,
		wanted,
		ctx.extraHeaders,
	);
	return wanted.filter((agentId) => {
		const identity = identities.get(admissionKey(agentId));
		if (!identity || !isSeated(group, identity)) return true;
		recordOutcome(ledger, agentId, "skipped", "already_in_group");
		return false;
	});
}
