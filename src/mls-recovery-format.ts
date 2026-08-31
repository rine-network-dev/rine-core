import type {
	GroupRecoveryResult,
	SenderKeyRecoveryResult,
} from "./group-recovery.js";
import type { MlsReclamationResult } from "./mls-admission.js";

/**
 * A group between its MLS init and the latch has neither recovery yet.
 *
 * Its own answer, because it is the one case both arms of `recoverGroup` would
 * get wrong: `mls_group_id` has not latched, so a two-way branch reads the
 * group as sender-key and runs an ingest against a group that is really MLS —
 * a wrong action rather than a wrong sentence. There is no epoch chain to catch
 * up with yet and no sender keys to install, and the server clears the state
 * on its own.
 *
 * Thrown, never returned, and deliberately as a bare `Error`: a new error class
 * plus its code, on two SDKs and in the matrix contract, is not worth what it
 * buys for a state that self-clears in minutes. Its Python twin is
 * `rine.format.MLS_INIT_IN_FLIGHT_SYNC` and the two are sentence for sentence
 * identical — two stacks printing different sentences about one event is the
 * defect a single shared sentence exists to stop.
 *
 * `groupRef` is whatever the caller named the group — a handle as often as a
 * UUID — because echoing an identifier the operator never typed is its own
 * small lie about what was acted on.
 */
export function mlsInitInFlightSync(groupRef: string): string {
	return (
		`Group ${groupRef} is still founding its MLS state, so there is no epoch` +
		" chain to catch up with yet and no sender keys to install. This clears on" +
		" its own within minutes — run the sync again then."
	);
}

/**
 * The repair a surface can actually offer for a group with no ratchet tree.
 *
 * The remedy is one operation — found the group's MLS state — and it is spelled
 * differently on every kind of caller, so it is the caller that names it. The
 * set is closed and every spelling in it is one this lane verified reaches the
 * founding path:
 *
 *   - `cli-resume-admission` — `rine group resume-admission`, which branches to
 *     `initMlsGroup` on an unlatched group (`rine-cli`'s group verbs).
 *   - `sdk-resume-admission` — the Python SDK's `resume_admission()`, whose
 *     `_resume` does the same branch.
 *   - `tool-group-reclaim` — `rine_group_reclaim` where it wraps that Python
 *     method (`rine-crewai`, `rine-langchain`, `rine-hermes`).
 *   - `none` — every surface whose nearest verb throws instead of founding.
 *     🔴 The TypeScript SDK's `resumeMlsAdmission` is one of them: it requires
 *     local MLS state and there is none here, so `rine-ts-sdk`, `rine-mastra`,
 *     `rine-eve`, `rine-mcp` and `rine-openclaw` name no verb. Naming a verb
 *     that refuses is the failure mode {@link notAnMlsGroupResume} exists to
 *     prevent, one level up.
 *
 * It is a value rather than a caller-supplied string so the clauses live here,
 * with the sentence they are part of, instead of drifting across the surfaces
 * that print them — and it defaults to `none`, so a surface that forgets to
 * choose gets the sentence that is true everywhere rather than the one that
 * names somebody else's verb.
 */
export type UnfoundedGroupRepair =
	| "cli-resume-admission"
	| "sdk-resume-admission"
	| "tool-group-reclaim"
	| "none";

/**
 * How each surface spells the founding verb, and nothing else.
 *
 * 🔴 One map, two clause tables DERIVED from it. The remedy is read in two
 * contexts and the sentence cannot be the same in both — a sync ends "then run
 * the sync again", and a renderer describing the group cannot say that because
 * nobody ran a sync — but the load-bearing token is identical in both: how this
 * surface spells the verb. A second table written by hand would drift on exactly
 * that token, which is what the two stacks had already done to each other on a
 * sentence nothing bound.
 *
 * `null` is a surface whose nearest verb refuses instead of founding. The
 * TypeScript SDK's `resumeMlsAdmission` requires local MLS state and there is
 * none here, and `rine-mcp`'s `rine_group_reclaim` refuses an unlatched group
 * outright — so `rine-ts-sdk`, `rine-mastra`, `rine-eve`, `rine-mcp` and
 * `rine-openclaw` name no verb. Naming one that refuses is the failure mode
 * {@link notAnMlsGroupResume} exists to prevent, one level up.
 */
const REPAIR_VERBS: Record<UnfoundedGroupRepair, string | null> = {
	"cli-resume-admission": "rine group resume-admission",
	"sdk-resume-admission": "resume_admission()",
	"tool-group-reclaim": "rine_group_reclaim",
	none: null,
};

/** The half both no-verb clauses share; only what follows it is context. */
const NO_VERB_HERE =
	" No verb on this surface founds it: a member has to found the group's MLS" +
	" state";

/** Both tables, from one spelling each: the verb arm, and the arm with no verb. */
function repairClauses(
	withVerb: (verb: string) => string,
	withoutVerb: string,
): Record<UnfoundedGroupRepair, string> {
	const clauses = {} as Record<UnfoundedGroupRepair, string>;
	for (const [repair, verb] of Object.entries(REPAIR_VERBS) as [
		UnfoundedGroupRepair,
		string | null,
	][]) {
		clauses[repair] = verb === null ? withoutVerb : withVerb(verb);
	}
	return clauses;
}

/** What a sync says: the remedy, and the sync that has to follow it. */
const UNFOUNDED_REPAIR_CLAUSES = repairClauses(
	(verb) =>
		` Run ${verb} on it to found its MLS state, then run the sync again.`,
	`${NO_VERB_HERE} before this sync has anything to catch up.`,
);

/**
 * What a surface describing the GROUP says: the remedy, and no sync.
 *
 * Every clause in the table above ends on a sync — "then run the sync again",
 * "before this sync has anything to catch up" — which is false in a renderer
 * where nobody ran one. That is the whole reason this second table exists, and
 * the verb spelling it names is the same map's.
 */
const UNFOUNDED_REPAIR_STATE_CLAUSES = repairClauses(
	(verb) => ` Run ${verb} on it to found its MLS state.`,
	`${NO_VERB_HERE}.`,
);

/**
 * A group created to run MLS, whose ratchet tree was never founded.
 *
 * 🔴 **The one place this fact is worded, on this stack.** Two surfaces state
 * it and they must state it identically: {@link groupEncryption} renders it when
 * an operator asks what a group is encrypted with, and `recoverGroup` appends it
 * to whatever the recovery it just ran produced. Its Python twin is
 * `rine.format.MLS_NEVER_FOUNDED_NOTE`, byte for byte — two stacks describing
 * one group differently is the defect this one constant exists to stop, and the
 * two stacks had already drifted here once.
 *
 * What it says, and why every clause of it is load-bearing:
 *
 *   - **"was created to run MLS"** — the group's four MLS columns are field for
 *     field an open group's, so nothing but the intent the server kept from
 *     create time (`groupMlsNeverFounded`) can tell the two apart.
 *   - **"never founded"**, never "founding failed". A founding that died and one
 *     that was never attempted leave identical rows, and the column that
 *     recorded the attempt is nulled by the server's own self-heal.
 *   - **"its messages are sealed with sender keys"** — the group is not broken,
 *     not frozen, and holds keys: the server accepts a sender-key send into it,
 *     the send path mints and fans out sender keys for it, and it carries
 *     messages. What it has not got is the MLS it was created for.
 *
 * It names no verb and no group. It names no verb because six agent surfaces
 * have none that founds a group — {@link UnfoundedGroupRepair} is where a
 * surface that HAS one says so. It names no group because it is appended to a
 * sentence that already did, the {@link MLS_EVICTED_BY_COMMIT} shape: a second
 * identifier in the same answer is what makes two stacks' output differ.
 */
export const MLS_NEVER_FOUNDED_NOTE =
	"This group was created to run MLS, but its ratchet tree was never founded," +
	" so its messages are sealed with sender keys rather than the MLS it was" +
	" created for.";

/**
 * What a sync says about a group whose ratchet tree was never founded.
 *
 * 🔴 **A warning appended to the recovery, not a refusal instead of one.** The
 * sync's sender-key arm really is this group's recovery in part: the group
 * carries sender-key traffic, so the distribution scan can and does install keys
 * for it. What the scan cannot do is found a ratchet tree, so the work happens
 * and then this says what the work did not reach. Refusing ahead of the scan
 * bought an operator nothing and cost them the keys.
 *
 * The repair clause is the whole of what differs between surfaces, and it
 * defaults to naming no verb: a warning that names a verb the caller cannot run
 * is the failure {@link UnfoundedGroupRepair} exists to prevent. Its Python twin
 * is `rine.format.mls_never_founded_sync` and the two are sentence for sentence
 * identical. An unmapped word is refused rather than rendered — see
 * {@link noteWithRepair}.
 */
export function mlsNeverFoundedSync(
	repair: UnfoundedGroupRepair = "none",
): string {
	return noteWithRepair(UNFOUNDED_REPAIR_CLAUSES, repair);
}

/**
 * The same fact, said by a surface that is describing the group rather than a
 * sync it just ran.
 *
 * 🔴 Its own function rather than an argument on {@link mlsNeverFoundedSync},
 * because the two differ in what they may claim happened, not in tone: every
 * clause the sync renders ends on a sync — "then run the sync again", "before
 * this sync has anything to catch up" — and a group renderer telling an operator
 * to repeat an operation they never performed is a straight falsehood about
 * their own session. Both tables name the verb from one map, so the half that
 * drifts unwatched cannot.
 *
 * Not `mlsNeverFoundedNote`: that name is already a field on
 * `GroupRecoveryResult`, carrying the SYNC sentence, and two things one name
 * apart is how a caller ends up appending the sync clause to a render. Its
 * Python twin is `rine.format.unfounded_group_note`, bound to this one by
 * `rine-core/test/mls-recovery-twin.test.ts`.
 */
export function unfoundedGroupNote(
	repair: UnfoundedGroupRepair = "none",
): string {
	return noteWithRepair(UNFOUNDED_REPAIR_STATE_CLAUSES, repair);
}

/**
 * 🔴 An unmapped word is refused rather than rendered, on both tables. These are
 * published exports on `@rine-network/core`, so a caller outside TypeScript's
 * reach can hand them anything, and `Record` lookup plus string concatenation
 * put the literal text `undefined` into an operator's warning — a silent
 * falsehood where the Python twin raises. One event, one behaviour: both name
 * the closed set, and both name it from {@link REPAIR_VERBS} so the refusal
 * cannot list a set neither table has.
 */
function noteWithRepair(
	table: Record<UnfoundedGroupRepair, string>,
	repair: UnfoundedGroupRepair,
): string {
	const clause = table[repair];
	if (clause === undefined) {
		throw new Error(
			`Unknown repair verb ${JSON.stringify(repair)} — expected one of: ` +
				`${Object.keys(REPAIR_VERBS).join(", ")}.`,
		);
	}
	return MLS_NEVER_FOUNDED_NOTE + clause;
}

/**
 * A sender-key group has no ratchet tree, so there is nobody here to seat.
 *
 * The resume verb's refusal, and the TypeScript stack's one implementation.
 * Unlike the sync verb — which now recovers an open group instead of refusing
 * it — resume has nothing to offer here at all: seating somebody needs a
 * ratchet tree, and an open group has none. Its Python twin is
 * `rine._resources.group_resume.NOT_AN_MLS_GROUP` and the two are sentence for
 * sentence identical: the connectors that wrap this SDK promise their model
 * that "an open group runs sender keys and has no ratchet tree, so it is
 * refused", and without this they got the generic "no MLS state for <uuid>"
 * instead — a string that is byte-identical to what an agent gets when it
 * genuinely belongs to an MLS group and holds no local state, whose remedy is a
 * resync rather than "there is nothing here, ever".
 *
 * `groupRef` is whatever the caller named the group — a handle as often as a
 * UUID — because echoing an identifier the operator never typed is its own
 * small lie about what was acted on.
 */
export function notAnMlsGroupResume(groupRef: string): string {
	return (
		`Group ${groupRef} runs on sender keys, not MLS, so it has no ratchet tree to ` +
		"seat anyone in. Open-enrollment groups are sender-key groups by design: MLS " +
		"would hand an unattested joiner a cryptographic seat, so the server keeps " +
		"open enrollment off the MLS path. There is nothing to resume here."
	);
}

/**
 * What an agent is told when a commit it just applied removed it from the group.
 *
 * One sentence, one home: the explicit recovery verbs report it through
 * {@link describeMlsRecovery}, and a plain read reports it too — the catch-up
 * behind a read applies the same commits, so an agent could be evicted by a
 * message it opened successfully. Both must say the same thing, and a second
 * copy of this sentence is how they would stop.
 *
 * Both matrix harnesses regex the rungs this is appended to, so its bytes are
 * pinned: change the wording and re-run them.
 */
export const MLS_EVICTED_BY_COMMIT =
	"This agent was removed from the group by a commit it just replayed: " +
	"messages that already arrived still open, and nothing committed after the " +
	"Remove ever will.";

/**
 * What to do once the sync is over, on every arm where the scan actually ran.
 *
 * 🔴 The answer used to end on a description of state, and a model reading it
 * handed the product's own status sentence to its user AS IF IT WERE WHAT THE
 * GROUP SAID, then never read the group (`e2e-group-qol.sh`'s g4, measured at
 * 0.00 twice). So this says both halves out loud: that our own text is not a
 * message from the group, and that the group's messages are the thing to read
 * next. It names no verb, because "read a group" is spelled differently on
 * every surface and a sentence naming somebody else's spelling is the failure
 * {@link UnfoundedGroupRepair} exists to prevent one level down.
 *
 * Not on the retired arm: nothing was installed there and nothing could be, so
 * sending its reader to the group's messages would send them to the same
 * refusal. That arm already ends on its own next action.
 *
 * Its Python twin is `rine.format._SCAN_DONE`, bound by
 * `rine-core/test/mls-recovery-twin.test.ts`.
 */
const SCAN_DONE =
	"This sync is finished; nothing here is a message from the group, so read" +
	" the group's own messages next.";

/**
 * The part of the distribution inbox this pass never opened, when there is one.
 *
 * The scan reads one page of a hundred and follows no cursor, so an agent with
 * a longer distribution inbox gets a partial pass — and until this, the answer
 * reported that partial pass as a whole one. The number is the server's own
 * `total` minus the page that was read, so it costs no extra request.
 *
 * 🔴 What it may say is bounded by what the number is, and the first version of
 * this sentence said more. It counted rows this pass did not LOOK at and called
 * them DMs that "stayed unopened, so a key this agent needs may be among them"
 * — but the listing it counts is every distribution this agent has EVER been
 * sent, read-state and installed-state alike, so the rows behind the page are
 * mostly keys installed long ago. "stayed unopened" was false of them, and an
 * agent past a hundred lifetime distributions read that hint on every healthy
 * sync it ever ran, with no verb offered for it (the wider page and the cursor
 * were both declined). So the sentence now states what the number is, states
 * what it is NOT, and names nothing to do about it.
 *
 * Empty, with no leading space, when the page covered everything — the
 * {@link NO_VERB_HERE} shape, so the two arms compose one way and not two.
 *
 * Its Python twin is `rine.format._unscanned_clause`.
 */
function unscannedClause(unscanned: number | undefined): string {
	if (!unscanned) return "";
	return (
		` ${unscanned} older sender-key distribution(s) in this agent's inbox sat` +
		" past the end of this scan's one page. That is a count of rows this pass" +
		" did not read, on a listing that holds every distribution this agent has" +
		" ever been sent — not a count of keys it is missing."
	);
}

/**
 * What recovering a sender-key group did, in the words the operator gets.
 *
 * Three facts and no more: what was installed, that nothing was committed, and
 * what is still out of reach. The last clause is the one that has to be exact —
 * an ingested distribution carries the sender's chain key at the index it was
 * distributed at, and a chain key only ratchets forward, so this repairs reads
 * from each key's own index onward and never behind it. It is not "read the
 * backlog", and it is emphatically not a re-key, a rotation or anything that
 * changes what an old key could open: recovery here installs the sender keys
 * this agent is missing, and touches nobody else's material.
 *
 * Each arm ends on a forward half, and that is a rule rather than a habit: the
 * retired arm names the next step, the installed arm says what is readable now,
 * and the empty arm says that this agent's state did not move — so an operator
 * who ran the sync because something would not open learns from the answer
 * itself whether the sync was the lever.
 *
 * Both arms where the scan actually ran then close on the same two clauses:
 * {@link unscannedClause}, when the one page the scan reads did not cover the
 * distribution inbox, and {@link SCAN_DONE}, which names the next action. The
 * retired arm takes neither — no scan ran there to fall short, and its reader
 * has its own next step.
 *
 * 🔴 Two matrix drivers decide whether this surface answered at all by
 * `^`-anchored regexes on these heads
 * (`scripts/mls-matrix/driver_framework_ts_admin.mjs`,
 * `scripts/mls-matrix/container_admin.py`), and a miss there is reported as the
 * refusal — a successful recovery graded as a broken surface. So a head may be
 * reworded, but only together with both of those regexes and its Python twin, in
 * one commit. The empty-scan head has been reworded twice for the same reason —
 * it kept claiming more than the number it reads can say. The first rewording
 * removed the success verb (`Recovered group X:` on a scan that recovered
 * nothing); a later audit removed the inbox inventory that survived it. The
 * warning rides on its own line, the {@link MLS_EVICTED_BY_COMMIT} shape.
 */
function describeSenderKeyRecovery(
	groupRef: string,
	result: SenderKeyRecoveryResult,
): string {
	const note = result.mlsNeverFoundedNote;
	const withNote = (head: string): string =>
		note ? `${head}\n${note}` : head;
	// Both arms where the scan ran end the same way: what it could not reach, if
	// anything, and then the next action. Composed once so the two cannot drift.
	const scanTail = `${unscannedClause(result.unscanned)} ${SCAN_DONE}`;
	if (result.retired) {
		// 🔴 It does not say "the server does not name this agent a member". The
		// retirement gate fails closed, so `retired` is also what a membership
		// read that never got an answer produces — and a sentence that stated the
		// server's verdict as fact sent an operator to an admin for a
		// re-invitation they already had, while ruling out the one thing that
		// would have worked. Cheapest remedy first, escalation second.
		return withNote(
			`Group ${groupRef} refused its own key material to this agent: its sender` +
				" keys were retired here, and nothing lifted that retirement, so nothing" +
				" was installed. A retirement lifts when the server names this agent a" +
				" member again: run the sync again, and if it still refuses, this agent" +
				" needs an invitation before it can take the group's keys.",
		);
	}
	if (result.ingested === 0) {
		// 🔴 "nothing new was installed", never "none were waiting". The number
		// this arm reads counts distributions this scan INSTALLED, and
		// `fetchAndIngestPendingSKDistributions` reaches zero with distribution
		// DMs sitting in the inbox — one already installed, one whose envelope
		// refused, one past the un-paginated `limit: 100`. So the sentence
		// states what the zero observes and stops: an inventory of the inbox is
		// a claim this vantage point cannot make, and the version that made it
		// went on to rule out the one thing that would have explained the miss.
		return withNote(
			`Scanned group ${groupRef} for sender keys: nothing new was installed,` +
				" so this agent's local state is unchanged. A sender-key group has no" +
				" epoch chain, so nothing was committed and this cost reads only." +
				" Whatever opened here before opens now, and a member's key this agent" +
				" has not got yet reaches it on that member's next post to the group." +
				scanTail,
		);
	}
	return withNote(
		`Recovered group ${groupRef}: installed ${result.ingested} sender key(s)` +
			" that were waiting in this agent's inbox. A sender-key group has no epoch" +
			" chain, so nothing was committed and this cost reads only. The messages" +
			" those keys cover open now; anything a member sent before its key was" +
			" minted stays unreadable." +
			scanTail,
	);
}

/**
 * What the operator paid, and what they got for it.
 *
 * Selects on `result.regime` first and on nothing else — never on which fields
 * a result happens to carry. A sender-key recovery has no epoch, no commit, no
 * ratchet tree and no leaf, so falling into either MLS rung would describe
 * events that did not happen, and appending {@link MLS_EVICTED_BY_COMMIT} to
 * one would report an MLS Remove for a group whose removals are the server's
 * delivery filter.
 *
 * Both MLS rungs report how far behind the agent was, because that is the
 * number that says whether the recovery was routine; and the resync rung says
 * out loud that a commit was posted and who is billed for it, because an O(N)
 * commit charged to every member of the group is not something to discover
 * later.
 *
 * `groupRef` is whatever the caller named the group — a handle as often as a
 * UUID — because echoing an identifier the operator never typed is its own
 * small lie about what was acted on.
 *
 * The name keeps its `Mls` prefix although it now answers for both regimes:
 * renaming a published export across seven consuming packages buys one word.
 */
export function describeMlsRecovery(
	groupRef: string,
	result: GroupRecoveryResult,
): string {
	if (result.regime === "sender-key") {
		return describeSenderKeyRecovery(groupRef, result);
	}
	const distance =
		result.behind === null
			? "by an unknown distance (the group has published no confirmed epoch)"
			: `by ${result.behind} epoch(s)`;
	const head =
		result.rung === "replay"
			? `Replayed ${result.processed} commit(s) for group ${groupRef}: it was behind ${distance}, and is now at epoch ${result.epoch}. Nothing was committed.`
			: `Resynced group ${groupRef}: it was behind ${distance} and no stored commit could bridge that gap, so one external commit re-seated this agent's existing leaf at epoch ${result.epoch}. That commit is O(N) — every member of the group downloads and processes it.`;
	if (!result.evicted) return head;
	return `${head}\n${MLS_EVICTED_BY_COMMIT}`;
}

/**
 * What a leaf-reclamation pass did to a group's ratchet tree.
 *
 * The TypeScript stack's one implementation, sentence for sentence identical to
 * its Python twin `rine.admission_words.describe_mls_reclamation`. Four
 * TypeScript surfaces report a reclamation — the CLI, the MCP server, and the
 * two connectors that wrap them — and before this each would have composed its
 * own; that is the drift a single shared sentence stops, and the same reason
 * {@link notAnMlsGroupResume} lives here rather than in three packages.
 *
 * Empty when no pass ran, so a caller can append it unconditionally. A pass that
 * ran and found nothing still says so: "nobody asked" and "there was nothing
 * there" are different facts, and only one of them means the tree is clean.
 *
 * The cost clause is not decoration. One Remove commit per orphaned leaf, each
 * O(N) and downloaded by every member, is what makes reclamation something a
 * member chooses rather than something that happens — nothing retires a leaf
 * until somebody runs the pass, and any member may.
 *
 * Unlike its neighbours this takes no `groupRef`: the Python twin takes none
 * either, and a second identifier in the sentence is what would make the two
 * stacks' output differ.
 */
export function describeMlsReclamation(
	reclamation?: MlsReclamationResult,
): string {
	if (!reclamation) return "";
	if (reclamation.declined) return reclamation.declined.detail;
	if (reclamation.found === 0) {
		return "Every leaf belongs to a member or to an unanswered invitation.";
	}
	return (
		`Reclaimed ${reclamation.reclaimed} of ${reclamation.found} orphaned leaves` +
		` in ${reclamation.commits} commit(s), now at epoch ${reclamation.epoch};` +
		" each Remove commit is O(N) and is billed to every member."
	);
}
