import { bytesToHex } from "@noble/curves/utils.js";
/**
 * What a client checks before it adopts a Welcome as local group state.
 *
 * `createGroupWithMembers` takes a caller-chosen group id and the server holds
 * every KeyPackage every agent has published, so a compromised or compelled
 * server can found its OWN MLS group whose id bytes are a rine group UUID the
 * victim belongs to, seal a real Welcome to the victim's own published
 * KeyPackage, and serve it from `GET /agents/{id}/mls/welcomes`. The only check
 * the join path had was `bytesToUuid(group.groupId()) === welcome.group_id` —
 * and the server chose both sides of that comparison, so it catches a mis-filed
 * row and not an adversary. `save()` then truncates whatever real state sat
 * under that id, and epoch secrets are the only copy of themselves.
 *
 * Two checks answer that here, and neither is the same kind of thing:
 *
 * * The group id comparison is **local and exact**, and catches a mis-filed row.
 * * {@link corroborateWelcomeRoster} asks whether anybody else in the tree this
 *   Welcome seats us in is an agent the group's roster names. That is a check
 *   on server-supplied data with server-supplied data, so it raises the bar
 *   from no check at all to two coordinated lies — a fabricated tree AND a
 *   matching fabricated roster, both of which `GET /agents/keys` and
 *   `GET /groups/{id}/members` are free to tell. It does not close the attack,
 *   and no surface may say it does; the residual is the key-transparency gap.
 *   The server chooses BOTH halves of the only check a joining client can make,
 *   so nothing here distinguishes a fabricated tree-plus-roster pair from a real
 *   one. That gap is accepted, not closed, and closing it needs a key source the
 *   client does not have to take from the server.
 *
 * 🔴 **A corroborated Welcome is adopted even over local state this agent
 * already holds, and that is deliberate.** Holding state raises the bar; it is
 * not a veto. There is no local fact that tells "my leaf is gone and this is
 * the way back in" from "this is a substitution": `isActive()` is in-session
 * only — the native core does not persist eviction (`mls-ops-sync.ts`) — so a
 * reloaded handle reports `true` again for every one-shot CLI call and every
 * restarted daemon. A guard that refused on held state therefore refused every
 * removed-then-re-invited member, permanently, and re-invitation is a
 * first-class rine flow. So this file does **not** close the state-destruction
 * half of the attack: a server that can fabricate a matching roster can still
 * get a Welcome adopted over live state, and no surface may say otherwise.
 *
 * 🔴 **A check that refuses an honest Welcome is worse than the attack.** The
 * asymmetry is what sets the bar in each direction. With local state held, a
 * wrong refusal costs a retry and the agent keeps reading the group, while a
 * wrong adoption costs the only copy of the epoch secrets — so corroboration
 * must be **positive**, and `unreadable` refuses along with `uncorroborated`.
 * With no local state held there is nothing to destroy and a wrong refusal is
 * the unrecoverable error, so the weakest predicate stands: `unreadable`
 * accepts.
 *
 * Corroboration itself is deliberately the weakest predicate that still catches
 * a group the roster knows nothing about: ONE identity in common with members
 * or live invitees is enough. The tree of an honest group routinely holds
 * leaves no roster read accounts for — an orphan from a self-leave or a lapsed
 * invitation, a member who rotated its signing key since it joined, a revoked
 * agent `GET /agents/keys` no longer publishes — so requiring every leaf to be
 * on the roster would refuse ordinary joins into ordinary groups. Those three
 * populations are the same ones leaf reclamation declines on
 * (`mls-orphans.ts`), for the same reason.
 *
 * A refusal is not a verdict for all time. Every reason a later attempt could
 * clear keeps the Welcome bytes on the spool — see {@link refusalIsRetryable}
 * and `mls-welcome-spool.ts` — because `GET /agents/{id}/mls/welcomes` consumes
 * what it serves and a dropped Welcome can never be re-minted.
 */
import type { MlsClient, MlsGroup } from "@rine-network/mls";
import { loadMlsGroup } from "./crypto/mls.js";
import { bytesToUuid } from "./crypto/sender-keys-helpers.js";
import type { HttpClient } from "./http.js";
import { fetchGroupTree, fetchMlsIdentities } from "./mls-admission-tree.js";

/**
 * The stable code every surface branches on. Outside the `RINE_MLS_` namespace
 * on purpose: that prefix is the native core's vocabulary, and `mlsErrorCode`
 * classifies anything inside it as a recoverable MLS read — which is exactly
 * the retry-and-swallow path a refusal must survive.
 */
export const WELCOME_REFUSED_CODE = "RINE_WELCOME_REFUSED";

/** Why a Welcome was not adopted. A value to branch on, never a message to parse. */
export type WelcomeRefusalReason =
	/** The joined group's own id is not the one the delivery was filed under. */
	| "group_id_mismatch"
	/** The roster was read and named nobody holding a leaf in the joined tree. */
	| "roster_uncorroborated"
	/**
	 * This agent holds local state for that group id and the roster could not be
	 * read, so nothing corroborates spending it.
	 */
	| "state_would_be_overwritten";

/**
 * Whether the Welcome bytes are kept for a later attempt, or dropped.
 *
 * `group_id_mismatch` is deterministic — the Welcome joins one group and was
 * filed under another, and no later attempt changes either — so it is the one
 * refusal that discards. The other two turn on facts that move: a roster read
 * can fail transiently, an invitation can be accepted, a stale leaf can be
 * re-seated. `GET /agents/{id}/mls/welcomes` consumes what it serves and no
 * peer can mint a replacement without noticing the first went unused, so a
 * refusal that dropped those bytes would be permanent by accident.
 */
export function refusalIsRetryable(reason: WelcomeRefusalReason): boolean {
	return reason !== "group_id_mismatch";
}

/** A Welcome this client refuses to adopt as state for the group it names. */
export class MlsWelcomeRefusedError extends Error {
	readonly code = WELCOME_REFUSED_CODE;

	constructor(
		readonly groupId: string,
		readonly reason: WelcomeRefusalReason,
		detail: string,
	) {
		super(detail);
		this.name = "MlsWelcomeRefusedError";
	}
}

/**
 * True for a refusal minted by the Welcome guard, matched on its code.
 *
 * A type predicate, so a caller that has to ask *which group* a refusal names
 * — the scoping every recovery path needs — reads `err.groupId` without a cast.
 */
export function isMlsWelcomeRefusedError(
	err: unknown,
): err is MlsWelcomeRefusedError {
	return (
		(err as { code?: unknown } | null | undefined)?.code ===
		WELCOME_REFUSED_CODE
	);
}

/** What the roster had to say about the tree a Welcome seats this agent in. */
type RosterCorroboration =
	/** At least one other leaf belongs to an agent this group's roster names. */
	| "corroborated"
	/** No leaf but this agent's own belongs to anyone the roster names. */
	| "uncorroborated"
	/** The roster could not be read, so it says nothing either way. */
	| "unreadable";

/**
 * Whether anyone else in `joined`'s ratchet tree is an agent the rine roster
 * names for this group.
 *
 * The populations are the ones leaf reclamation calls entitled — members plus
 * every live voucher — because the wider set can only ever accept a Welcome it
 * should have questioned, never refuse an honest one.
 *
 * `unreadable` is a real and ordinary answer, not a failure: a Welcome can be
 * installed by an agent that has been invited and has not accepted yet, and
 * `GET /groups/{id}/members` answers 403 to an org holding no member row. Every
 * shipped join verb accepts the invitation first, so that is the exception
 * rather than the rule — but it is honest, and it is why an unreadable roster
 * accepts for an agent holding no state to lose.
 */
async function corroborateWelcomeRoster(
	client: HttpClient,
	groupId: string,
	joined: MlsGroup,
	extraHeaders?: Record<string, string>,
): Promise<RosterCorroboration> {
	let entitled: string[];
	let identities: Map<string, Uint8Array>;
	try {
		const tree = await fetchGroupTree(client, groupId, extraHeaders);
		entitled = [...tree.members, ...tree.outstanding];
		identities = await fetchMlsIdentities(client, entitled, extraHeaders);
	} catch {
		return "unreadable";
	}
	// This agent's own leaf is excluded structurally rather than by trusting the
	// roster read: it is in the tree by construction and on the roster whenever
	// the invitation was accepted, so counting it would corroborate every
	// Welcome including a fabricated one.
	const own = joined.currentMemberIndex();
	const others = new Set(
		joined
			.memberIdentities()
			.filter((leaf) => leaf.index !== own)
			.map((leaf) => bytesToHex(leaf.identity)),
	);
	for (const identity of identities.values()) {
		if (others.has(bytesToHex(identity))) return "corroborated";
	}
	return "uncorroborated";
}

/** The sentence a Welcome the roster contradicts earns. */
function uncorroboratedDetail(groupId: string): string {
	return (
		`Refusing the MLS welcome for group ${groupId}: the group's roster names ` +
		"no member and no outstanding invitation holding a leaf in the ratchet " +
		"tree this welcome seats the agent in, so the group it joins is not the " +
		"group it names. The welcome is kept and retried. If the group is honest, " +
		"this is what a member that rotated its signing key after joining looks " +
		"like — its leaf still carries the old identity, so it has to re-seat it " +
		"with `rine group sync` or be re-invited before a welcome into this group " +
		"can be corroborated."
	);
}

/** The sentence a Welcome nothing could corroborate against held state earns. */
function overwriteDetail(groupId: string): string {
	return (
		`Refusing the MLS welcome for group ${groupId}: this agent already holds ` +
		"local state for it and the group's roster could not be read, so nothing " +
		"corroborates the welcome — and adopting it would destroy the epoch " +
		"secrets that are the only copy of themselves. The welcome is kept and " +
		"retried. If this agent was invited to the group again, accept the " +
		"invitation first: `GET /groups/{id}/members` answers 403 to an org " +
		"holding no member row, and a roster that cannot be read corroborates " +
		"nothing."
	);
}

/** The sentence a Welcome filed under the wrong group earns. */
function mismatchDetail(groupId: string, joinedId: string): string {
	return (
		`Refusing the MLS welcome delivered for group ${groupId}: it joins group ` +
		`${joinedId} instead, so the state key and the group a user sees would ` +
		"disagree from here on. The welcome is discarded — no later attempt " +
		"changes which group it joins."
	);
}

/**
 * The refusal one Welcome earns, or `null` when it may be adopted.
 *
 * The local id comparison is first because it is exact and free. Everything
 * after it turns on the roster read, whose weight depends on what this agent
 * stands to lose:
 *
 * | local state | roster           | verdict                             |
 * | ----------- | ---------------- | ----------------------------------- |
 * | either      | `corroborated`   | adopt                               |
 * | either      | `uncorroborated` | refuse `roster_uncorroborated`      |
 * | none        | `unreadable`     | adopt                               |
 * | held        | `unreadable`     | refuse `state_would_be_overwritten` |
 *
 * The last two rows are the whole design: with nothing to destroy, a wrong
 * refusal is the unrecoverable error; with state held, a wrong adoption is.
 * Note what is NOT in the table — `isActive()`. It is in-session only, so it
 * cannot mean "am I still in this group" across a process boundary and may not
 * be a discriminator here.
 *
 * `joined` is a handle the caller has NOT saved. Nothing here writes, so a
 * refused Welcome leaves the store exactly as it was.
 */
export async function welcomeRefusal(
	client: HttpClient,
	mls: MlsClient,
	joined: MlsGroup,
	rineGroupId: string,
	extraHeaders?: Record<string, string>,
): Promise<MlsWelcomeRefusedError | null> {
	const joinedId = bytesToUuid(joined.groupId());
	if (joinedId !== rineGroupId.toLowerCase()) {
		return new MlsWelcomeRefusedError(
			rineGroupId,
			"group_id_mismatch",
			mismatchDetail(rineGroupId, joinedId),
		);
	}
	const corroboration = await corroborateWelcomeRoster(
		client,
		rineGroupId,
		joined,
		extraHeaders,
	);
	if (corroboration === "corroborated") return null;
	if (corroboration === "uncorroborated") {
		return new MlsWelcomeRefusedError(
			rineGroupId,
			"roster_uncorroborated",
			uncorroboratedDetail(rineGroupId),
		);
	}
	if (loadMlsGroup(mls, rineGroupId) === null) return null;
	return new MlsWelcomeRefusedError(
		rineGroupId,
		"state_would_be_overwritten",
		overwriteDetail(rineGroupId),
	);
}
