import { mlsInit } from "./crypto/mls-api.js";
import { loadMlsState } from "./crypto/mls-state.js";
import { openMlsClient } from "./crypto/mls.js";
import type { HttpClient } from "./http.js";
import { processMlsWelcomes } from "./mls-ops-join.js";
import { runAdmission } from "./mls-admission-batch.js";
import {
	fetchGroupTree,
	resolveUnseated,
	treeSize,
} from "./mls-admission-tree.js";
import {
	type AdmissionLedger,
	type MlsAdmissionResult,
	admissionKey,
	requireGroup,
} from "./mls-admission.js";
import { mlsHeartbeat } from "./mls-heartbeat.js";
import { reclaimOrphanLeaves } from "./mls-orphans.js";

/**
 * Initialize an MLS group: found it, and admit every member and invitee the
 * server reports a KeyPackage for, in batches sized to the growing tree.
 *
 * `/mls/init` reports the group's invitees as well as its members, so a group
 * created with a roster founds with its roster already in the tree. Nobody is
 * seated by this: an invitee holds a leaf and a Welcome, and becomes a member
 * when they join.
 *
 * A founding roster mints real invitations under **every** enrollment policy,
 * including the two where a later invite only nominates: at founding
 * the creator is the only member, so a vote would be a formality that approves
 * every row — and putting the founding batches behind one is what makes 500
 * members unreachable. So this path never asks `inviteNominates`.
 *
 * Local state is saved only after the server accepts a commit, so a rejected
 * commit leaves no forked state behind.
 */
export async function initMlsGroup(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<MlsAdmissionResult> {
	const ctx = { configDir, agentId, groupId, client, extraHeaders };
	// Forced rather than gated: founding is about to spend key packages, and the
	// founder's own inventory is the one no other member can top up.
	await mlsHeartbeat({ configDir, agentId, client }, "forced");
	const initResp = await mlsInit(client, groupId, extraHeaders);

	// Everyone the server reported, in the order it reported them, so the
	// outcomes come back in that order too. An agent it says has published no key
	// package is left where it is: `no_key_package` is what the ledger seeds, and
	// claiming for them would only have the server say the same thing again.
	const unready = new Set(
		initResp.members
			.filter((member) => !member.has_key_package)
			.map((member) => admissionKey(member.agent_id)),
	);
	const ledger: AdmissionLedger = new Map();
	const requested = initResp.members.map((member) => member.agent_id);
	const pending = (await resolveUnseated(ctx, null, requested, ledger)).filter(
		(agent) => !unready.has(admissionKey(agent)),
	);

	const mls = openMlsClient(configDir, agentId);
	return runAdmission(ctx, mls, pending, ledger, 1, null);
}

/**
 * Install a Welcome this agent holds but has never opened, so an admission verb
 * can mint its commit.
 *
 * An admin who was themselves admitted by Welcome and has not read the group yet
 * holds NO local state. Both admission verbs below then fail on
 * {@link requireGroup} — and both of their callers treat that as best-effort, so
 * the applicant is seated in the rine group and left OUTSIDE the MLS one, losing
 * every message sent until they self-heal. That is the ordinary shape of a
 * `majority` group, where the deciding vote is routinely cast by a member who
 * joined and has not read anything yet.
 *
 * The decrypt path (`crypto/message.ts`) and the join path both install pending
 * Welcomes before they need state. These two did not; this is that same step.
 *
 * Scoped with `forGroup` because it establishes exactly ONE group's state:
 * unscoped, a substituted Welcome for any other group would abort an admission
 * that has nothing to do with it.
 *
 * Called BEFORE `openMlsClient` deliberately — the install writes through its own
 * client handle, so a handle opened first is not guaranteed to see the result.
 */
async function ensureAdmitterState(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
): Promise<void> {
	if (loadMlsState(configDir, agentId, groupId)) return;
	await processMlsWelcomes(configDir, agentId, client, { forGroup: groupId });
}

/**
 * Admit members to a group this agent already holds MLS state for.
 *
 * The same loop founding runs, started at the tree's current size instead of
 * at 1. Ids already in the tree are dropped as `already_in_group`, which is
 * what makes this safe to re-run over the same list: a partly-completed
 * admission is finished by calling it again.
 */
export async function addMlsGroupMembers(
	configDir: string,
	agentId: string,
	groupId: string,
	memberAgentIds: string[],
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<MlsAdmissionResult> {
	const ctx = { configDir, agentId, groupId, client, extraHeaders };
	await ensureAdmitterState(configDir, agentId, groupId, client);
	const mls = openMlsClient(configDir, agentId);
	const group = requireGroup(mls, groupId);
	// Forced replenishment of OUR inventory. Each member's own inventory is
	// theirs to replenish — a client can only publish key packages for an agent
	// whose signing key it holds.
	await mlsHeartbeat({ configDir, agentId, client }, "forced");

	const ledger: AdmissionLedger = new Map();
	const pending = await resolveUnseated(ctx, group, memberAgentIds, ledger);
	// Pricing the tree only changes the answer when there is more than one
	// member to seat: one member is always exactly one batch, whatever the tree
	// weighs. So the two reads it costs are skipped on the single-member invite
	// rather than billed to it.
	const seated =
		pending.length > 1
			? treeSize(await fetchGroupTree(client, groupId, extraHeaders))
			: 1;
	return runAdmission(ctx, mls, pending, ledger, seated, group.epoch());
}

/**
 * Seat everyone this group has invited and not yet given a leaf to.
 *
 * `mls_group_id` is a one-way latch, so a founding interrupted at commit 5 of
 * 39 can never be re-initialized — but it does not need to be. Batches 2..39
 * were add commits already, so what a partly-founded group needs is the add
 * path run over its still-unseated invitees, which is exactly this. Running it
 * a second time seats nobody and reports every invitee `already_in_group`.
 *
 * The invited set is read from the server (`?outstanding=live`) and nowhere
 * else. Inferring it from members plus vote requests concludes that every agent
 * who was legitimately invited and has not accepted yet holds no entitlement at
 * all.
 *
 * **Members are candidates too, and that is not redundant.** A member can hold
 * no leaf: an invitee whose add commit was refused still joins on their voucher,
 * which resolves it — so they leave the invited set and enter the member set
 * having never been seated. They are unreachable by every other verb (`invite`
 * refuses them as `already_a_member`), so a resume that read invitations alone
 * would report `added: 0` and call it success. Anyone already seated costs one
 * leaf lookup and is reported `already_in_group`.
 *
 * 🔴 A **`pending`** row is deliberately NOT a candidate, whether it is a
 * stranger's self-application or a member's nomination of one. See
 * {@link fetchGroupTree}: both are awaiting a vote that may deny them, and
 * Welcoming either hands the group's epoch secret to an agent the electorate
 * has not admitted.
 *
 * `reclaim` adds the second half of the pass: after everyone entitled to a leaf
 * has one, retire the leaves nobody is entitled to. It is **off by default and
 * asked for explicitly**, because it removes leaves and costs one O(N) commit
 * per leaf — a resume that quietly did both would change what the verb means
 * and what it bills. Reclamation runs **after** admission, never before, so an
 * agent that rotated its signing key is re-seated under the new key before its
 * stale leaf is dropped.
 */
export async function resumeMlsGroupAdmission(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
	opts: { reclaim?: boolean } = {},
): Promise<MlsAdmissionResult> {
	const ctx = { configDir, agentId, groupId, client, extraHeaders };
	await ensureAdmitterState(configDir, agentId, groupId, client);
	const mls = openMlsClient(configDir, agentId);
	const group = requireGroup(mls, groupId);
	await mlsHeartbeat({ configDir, agentId, client }, "forced");

	const tree = await fetchGroupTree(client, groupId, extraHeaders);
	const ledger: AdmissionLedger = new Map();
	const pending = await resolveUnseated(
		ctx,
		group,
		[...tree.members, ...tree.invited],
		ledger,
	);
	const result = await runAdmission(
		ctx,
		mls,
		pending,
		ledger,
		treeSize(tree),
		group.epoch(),
	);
	if (!opts.reclaim) return result;
	const reclamation = await reclaimOrphanLeaves(
		configDir,
		agentId,
		groupId,
		client,
		extraHeaders,
	);
	return { ...result, epoch: reclamation.epoch, reclamation };
}
