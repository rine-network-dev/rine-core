/**
 * Recovering a group, whichever encryption it runs — the one place the
 * TypeScript stack decides which recovery a group even has.
 *
 * A rine group runs one of two encryptions and both are supported products, so
 * "catch this group up" has two meanings and they share nothing:
 *
 *   - **MLS.** Walk the epoch ladder — {@link recoverMlsGroup}, which replays
 *     the commits the server still holds and, only when replay cannot bridge
 *     the gap, posts one O(N) external commit that re-seats this agent's leaf.
 *   - **Sender keys.** There is no epoch chain to walk. What a member can be
 *     missing is other members' keys, and those are sitting in its own inbox as
 *     distribution DMs — so recovery is
 *     {@link scanPendingSKDistributions} and nothing else. It posts nothing,
 *     commits nothing, and installs the sender keys this agent is missing.
 *
 * 🔴 **The regime is decided from the group row's `mls_group_id` latch and
 * never from state absence.** `loadMlsGroup(...) === null` is a symptom shared
 * by an MLS member whose local state was deleted and by every member of an open
 * group; branching on it tells an operator of a sender-key group to ask an
 * admin to remove and re-invite them, which is advice about a ratchet tree the
 * group does not have. The latch is the server's own answer and is the only one
 * that distinguishes the two.
 *
 * One case has no recovery at all and is refused rather than answered: a group
 * between its MLS init and the latch. It looks exactly like a sender-key group
 * in the MLS columns, and running the ingest on it is a wrong action rather
 * than a wrong sentence — the server refuses a sender-key send there, so the
 * group is not carrying sender-key traffic to have keys for.
 *
 * A group created to run MLS whose tree was never founded looks the same in
 * those columns and is NOT that case: the server accepts sender-key sends into
 * it, so it really is carrying sender-key traffic and the scan really does
 * install keys for it. It gets the sender-key recovery and, with it, a warning
 * naming what that recovery could not reach — the ratchet tree.
 *
 * What this does NOT do, deliberately: distribute **this** agent's key to
 * members who joined after its last post. That material does not exist at the
 * reader's end — it is minted and fanned out on the send path
 * (`getOrCreateSenderKey`) — and a read verb that wrote DMs into other orgs'
 * inboxes, and could rotate on a timer, would be a different verb wearing this
 * one's name.
 */
import {
	groupIsMls,
	groupMlsInitInFlight,
	groupMlsNeverFounded,
} from "./crypto/group-predicates.js";
import type { GroupRegimeFields } from "./crypto/group-predicates.js";
import type { HttpClient } from "./http.js";
import {
	NO_KEY_PACKAGE_TOP_UP,
	topUpKeyPackages,
} from "./mls-keypackage-topup.js";
import type { KeyPackageTopUp } from "./mls-keypackage-topup.js";
import {
	MlsResyncUnavailableError,
	isMlsResyncUnavailable,
	recoverMlsGroup,
} from "./mls-ops-resync.js";
import type { MlsRecoveryResult } from "./mls-ops-resync.js";
import {
	mlsInitInFlightSync,
	mlsNeverFoundedSync,
} from "./mls-recovery-format.js";
import type { UnfoundedGroupRepair } from "./mls-recovery-format.js";
import {
	retirementBlocksRead,
	scanPendingSKDistributions,
} from "./sender-key-recovery.js";

/** What recovering a sender-key group did, and what it could not do. */
export interface SenderKeyRecoveryResult {
	regime: "sender-key";
	/**
	 * Sender keys newly installed. The scan is this agent's WHOLE distribution
	 * inbox rather than one group's share of it — the group a distribution
	 * belongs to is only known after its DM is decrypted — so a recovery run for
	 * one group also installs any key waiting for another. The count says what
	 * was installed, not what was installed *here*.
	 */
	ingested: number;
	/**
	 * True when this agent retired its keys for this group and nothing lifted
	 * that retirement, so nothing was installed and nothing could be.
	 *
	 * 🔴 It is NOT "the server said this agent is not a member". The gate fails
	 * closed — a membership read that errors keeps the refusal, because a
	 * transport failure proves nothing — so this flag covers both "the server
	 * does not name this agent a member" and "the server could not be asked".
	 * Anything rendering it must leave a retry open.
	 */
	retired: boolean;
	/**
	 * How many distribution DMs the server counts for this agent beyond the
	 * single page the scan read — the exact shortfall, straight out of the
	 * `total` the list response already carries, at no extra request.
	 *
	 * **Absent, never zero and never null**, when the page covered everything
	 * (and when the scan never ran, which is the retired arm): the renderer's
	 * shortfall sentence is the only reader, so an absent field and a `0` would
	 * mean the same thing to it while a spread into JSON would print a number
	 * that says nothing happened.
	 *
	 * 🔴 It counts what the pass did not LOOK at, and it is not a count of keys
	 * this agent is missing. The inbox listing is every distribution this agent
	 * has ever been sent, so most of what sits behind that page is material it
	 * installed long ago — `SenderKeyScan`'s own doc carries the same warning,
	 * and the sentence built from it may state the number and may not conclude a
	 * missing key from it.
	 */
	unscanned?: number;
	/**
	 * Set when the group was created to run MLS and its ratchet tree was never
	 * founded: what this recovery could not reach, in the words every surface
	 * prints — {@link mlsNeverFoundedSync}, already carrying this surface's own
	 * spelling of the founding verb.
	 *
	 * A fact about the GROUP, not about the scan, so it rides on all three
	 * sender-key answers alike. **Absent, never null or empty**, when there is
	 * nothing to say: a consumer spreading the result into JSON then emits no
	 * key at all, which is the `actorNote` rule this stack already follows.
	 *
	 * 🔴 It is deliberately not called `warning`. `rine-mcp` spreads an actor
	 * note over this result under exactly that key, and the hermes tool passes
	 * one as `**note`, so a second `warning` here would silently overwrite the
	 * first on MCP and raise `TypeError` on hermes.
	 */
	mlsNeverFoundedNote?: string;
	/**
	 * What the key-package top-up that rode along with this recovery did.
	 *
	 * Absent when the recovery was not driven through `recoverGroup` — the
	 * `mlsNeverFoundedNote` rule: a consumer spreading the result into JSON then
	 * emits no key at all rather than a null.
	 */
	keyPackages?: KeyPackageTopUp;
}

/** What recovering a group did, whichever encryption it runs. */
export type GroupRecoveryResult = MlsRecoveryResult | SenderKeyRecoveryResult;

/**
 * Catch one group up, on whichever recovery that group actually has.
 *
 * Takes the **already-fetched group row**, never a bare id. That is the type
 * doing the work of a rule: `GET /groups/{id}` is what answers "does this group
 * exist, and does this agent hold a seat in it", in the server's own words, and
 * a surface that could pass an id would be able to skip it — which is how a
 * mistyped group id came back as "ask an admin to remove this agent from the
 * group and invite it again".
 *
 * `repair` is the spelling of the founding verb THIS surface can offer, and is
 * read only by the never-founded warning. It defaults to naming no verb,
 * because most surfaces have none that works and a warning naming a verb the
 * caller cannot call is worse than one naming nothing.
 *
 * @throws Error while the group's MLS init is in flight — there is no epoch
 *   chain to catch up with yet and no sender keys to install.
 * @throws MlsResyncUnavailableError when the group is MLS and this agent's
 *   local state will not load at all.
 */
export async function recoverGroup(
	configDir: string,
	agentId: string,
	group: GroupRegimeFields & { id: string; handle?: string | null },
	client: HttpClient,
	extraHeaders?: Record<string, string>,
	repair: UnfoundedGroupRepair = "none",
): Promise<GroupRecoveryResult> {
	// Ahead of both arms: a closed group between its MLS init and the latch has
	// no MLS state to catch up and is emphatically not a sender-key group, so
	// running the ingest here would be a wrong action rather than a wrong
	// sentence. The server clears this state on its own.
	if (groupMlsInitInFlight(group)) {
		// `handle ?? id`, the `notAnMlsGroupResume` precedent
		// (`rine-ts-sdk/src/resources/groups-mls.ts`): the Python twin formats the
		// row's handle, so echoing the UUID here made one event print two
		// sentences depending on which SDK the surface wraps — and on a surface
		// that resolved a handle for the caller, an identifier they never typed.
		throw new Error(mlsInitInFlightSync(group.handle ?? group.id));
	}
	// A group created to run MLS whose tree was never founded is field for field
	// an open group in those same MLS columns, so the latch alone sent it to the
	// ingest and reported "Recovered group …" — a success sentence for a group
	// that never got the encryption it was created for. 🔴 The scan is real
	// work: this group IS carrying sender-key traffic, so keys for it really are
	// waiting, and refusing ahead of the scan cost an operator those keys to buy
	// a sentence. So the work runs and the sentence rides with it. What no scan
	// can install is the ratchet tree, and that is what this says. The intent
	// the server kept from create time is the only thing that tells this group
	// from an open one.
	//
	// Computed here, where `repair` is in scope, rather than at each render:
	// the surface that knows which founding verb its caller can run is the one
	// that called this.
	const mlsNeverFoundedNote = groupMlsNeverFounded(group)
		? mlsNeverFoundedSync(repair)
		: undefined;
	// 🔴 AHEAD of the regime branch, and ahead of the throw inside it. An agent
	// whose published key packages have run out is un-addable: no member can mint
	// it a Welcome, so a carried vote seats it on the roster with no leaf, and
	// `recoverMlsGroup` answers that agent by THROWING — its local state will not
	// load, because it never had any. A top-up attached to the returned result
	// would run for every group except the one this exists to fix, so it runs
	// here and rides on both the result and the refusal.
	const keyPackages = groupIsMls(group)
		? await topUpKeyPackages({ configDir, agentId, client })
		: NO_KEY_PACKAGE_TOP_UP;
	// `recoverMlsGroup` sets `regime: "mls"` on both of its own returns, so this
	// arm re-tags nothing: a discriminant restated at the call site is a second
	// place it can be forgotten.
	if (groupIsMls(group)) {
		try {
			const recovered = await recoverMlsGroup(
				configDir,
				agentId,
				group.id,
				client,
				extraHeaders,
			);
			return { ...recovered, ...topUpField(keyPackages) };
		} catch (err) {
			// Re-minted rather than mutated, the `resyncFailure` precedent: the
			// message is composed in the constructor, so a refusal that learned
			// about the top-up afterwards would carry a field its own sentence
			// never mentions. Every other failure is somebody else's to explain.
			//
			// 🔴 And re-minted WITHOUT a `cause`. This is a replacement for the
			// refusal, not a wrapper around a different failure: the inner error's
			// message is this one's message minus the top-up line. Every renderer
			// in this repo concatenates an error with its cause — `formatError`
			// returns `${message}: ${cause.message}` — so carrying it would print
			// the whole admin-remedy paragraph, then the top-up sentence, then the
			// paragraph again, with the top-up report reading as a prefix to a
			// duplicate. An error that composes the operator's whole sentence does
			// not also carry the sentence it replaced.
			if (!isMlsResyncUnavailable(err)) throw err;
			throw new MlsResyncUnavailableError(group.id, { keyPackages });
		}
	}
	// Asked before the scan so the two zeroes can be told apart: "nothing was
	// waiting" and "this agent's material was retired here" are different facts
	// with different remedies. The scan re-checks and the second check is a
	// local file read, so this costs no extra round trip.
	if (await retirementBlocksRead(client, configDir, agentId, group.id)) {
		// Spread rather than assigned: the field is optional and absent when
		// there is nothing to say, so a consumer spreading this into JSON emits
		// no key rather than a null.
		return {
			regime: "sender-key",
			ingested: 0,
			retired: true,
			...(mlsNeverFoundedNote ? { mlsNeverFoundedNote } : {}),
			...topUpField(keyPackages),
		};
	}
	// The scan, not the count-only wrapper every read path calls: this is the one
	// caller that reports what the pass could not reach as well as what it
	// installed, and the wrapper is this function with that second number
	// dropped.
	const scan = await scanPendingSKDistributions(
		client,
		configDir,
		agentId,
		undefined,
		// The group whose read missed. It is the only thing that spends a
		// retirement on the read path, so it is never omitted.
		group.id,
	);
	return {
		regime: "sender-key",
		ingested: scan.ingested,
		retired: false,
		// Spread rather than assigned, the `mlsNeverFoundedNote` rule: a page that
		// covered everything says nothing, and a `0` spread into JSON is a number
		// reporting that nothing happened.
		...(scan.unscanned > 0 ? { unscanned: scan.unscanned } : {}),
		...(mlsNeverFoundedNote ? { mlsNeverFoundedNote } : {}),
		...topUpField(keyPackages),
	};
}

/**
 * The top-up, spread rather than assigned — the `mlsNeverFoundedNote` rule. A
 * group that runs sender keys has no key packages to report on, so it reports
 * no key, not a `healthy` nobody asked about.
 */
function topUpField(
	keyPackages: KeyPackageTopUp,
): { keyPackages?: KeyPackageTopUp } {
	return keyPackages.outcome === "healthy" ? {} : { keyPackages };
}
