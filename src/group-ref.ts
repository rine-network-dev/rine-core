/**
 * How a group reference is matched against a group list, and what a miss says.
 *
 * `resolve-group.ts` owns the network — which route is asked, with which
 * parameters — and this module owns the decision it makes with the answer. The
 * split is not stylistic: that file carries the path literals
 * `tests/test_client-server-contract_group0.py` extracts out of `rine-core/src`
 * and resolves against the real FastAPI routes, so it must stay a file whose
 * `client.get(...)` calls are readable at a glance, and the ladder below plus
 * its two refusals would have pushed it past the ~200-line rule. **Nothing here
 * may grow a path literal** — a lookup that needs one belongs next to the
 * others, in `resolve-group.ts`.
 *
 * 🔴 **Twin of the Python SDK's `rine-sdk/src/rine/_group_ref.py`.** The two
 * stacks share no module, so they are two implementations of one contract:
 * every group verb on every surface promises *"Group handle (e.g. #logistics@acme.rine.network), name
 * or UUID"*, and a reference that resolves on one stack and 404s on the other
 * makes that sentence a lie on whichever surface the caller happened to pick.
 * Same tiers, same order, same normalisation, same refusal shape — the
 * one-refusal-per-mistake rule (`actor.ts`), applied to behaviour rather than
 * to a sentence.
 *
 * **Why a ladder at all.** A caller — a person or a model — names a group the
 * way they say it out loud, and the handle it was minted under carries a slug
 * and a suffix nobody says. Exact string equality answers that with a 404 while
 * holding the very list the answer is in. Every reference-taking tool ships the
 * same affordance under the same bound — git abbreviates a rev, docker a
 * container, kubectl a resource — and the bound is what makes it honest: a
 * partial reference resolves only when it is unambiguous, and otherwise names
 * the candidates it could not choose between.
 *
 * **The rungs.** Exact local part, then normalised equality against the local
 * part or `name`, then a unique whole-segment prefix of either — and, only when
 * all three matched nothing at all, the same three again against the reference
 * with one generic classifier noun peeled off its tail (or one leading article
 * off its head), one word at a time. {@link GENERIC_GROUP_NOUNS} carries that
 * last rung's whole justification.
 */

import type { AgentRead, GroupRead } from "./api-types.js";
import {
	type RefusalCandidates,
	type RefusalLead,
	composeGroupRefusal,
	joinSentences,
} from "./recipient-refusal.js";
import { REF_CLASS, classifyReference } from "./recipient-target.js";

/**
 * The lead every "no such group" refusal opens with, byte-for-byte.
 *
 * Five published surfaces branch on it to decide which HALF of the directory a
 * model is sent to, the server raises the same phrase as a bare literal, and
 * `tests/test_client-server-contract_group0.py` pins the copies against each
 * other. This is the one this package composes with — never retyped, on either
 * stack.
 */
export const GROUP_NOT_FOUND_LEAD = "Group not found";

/**
 * The SECOND lead: what a BARE recipient name is refused with.
 *
 * A bare name is the one spelling that named no namespace, so a verdict about
 * groups alone was never the whole answer — by the time
 * {@link recipientGroupForBareName} refuses, the agent namespace has declined
 * the spelling on syntax AND no agent of this org carries the name, so both
 * halves have already answered no. Leading with *"Group not found"* told a
 * caller only the half they had not asked about.
 *
 * 🔴 **It is the invariant TAIL of that lead sentence, not its first bytes** —
 * the caller's own spelling opens it, which is the whole point of the reword —
 * so the six surfaces that discriminate on it must use a CONTAINMENT test,
 * never `startsWith`. {@link GROUP_NOT_FOUND_LEAD} keeps its `startsWith`
 * semantics and its value: every `rine_group_*` verb, the server's four
 * modules and {@link unknownGroupRefusal} still open with it, because there the
 * caller DID name a group.
 *
 * Registered in `tests/helpers_client_paths.py` as
 * `NEITHER_NAMESPACE_LEAD_COPIES` and gated the way the first lead is — with
 * one difference that is a property of the phrase rather than an omission: this
 * one has no server copy to compare against. The server never composes it; it
 * is minted on both client stacks and nowhere else.
 */
export const NEITHER_NAMESPACE_LEAD = "names neither an agent nor a group you can reach";

/**
 * The sentence that introduces the group list in a group refusal.
 *
 * It says "name one of these" rather than "your groups are", because the
 * ambiguous arm passes the candidates rather than the whole roster and the
 * sentence has to stay true of a subset.
 */
export const GROUP_ROSTER_LEAD = "Name one of these groups:";

/** What the tail says instead, for an org that is in no groups at all. */
export const NO_GROUPS_IN_ORG = "This org is in no groups yet.";

/**
 * How many groups a refusal names before it stops counting.
 *
 * A caller in two hundred groups gets a two-hundred-line sentence otherwise,
 * which is a refusal nobody reads and — on an agent surface — a refusal that
 * eats the context window the retry needs. Both arms share the bound, because
 * the ambiguous arm is the one that can grow without warning: a normalised tier
 * matches on two spellings at once.
 *
 * 🔴 The same number as the Python twin. It is a contract value, not a taste:
 * a caller who compares the two stacks' answers to one reference must see the
 * same list.
 */
export const MAX_LISTED_GROUPS = 20;

/**
 * Trailing segments that name the KIND of thing a group is, never the thing.
 *
 * A reference holds two kinds of segment. One names the group — `payroll`,
 * `roadmap`, `incidents`. The other names the kind of thing the group is, and
 * carries nothing that could tell two of an org's groups apart: "the ops group"
 * and "the ops chat" are the same sentence to a person, and neither word is
 * what makes the group theirs. So a reference that matched NOTHING drops a
 * trailing one of these and asks again — reading the sentence the way the
 * person who wrote it meant it, not guessing at it.
 *
 * 🔴 `thread` is deliberately absent, and it is the only near-miss worth
 * naming: a conversation thread is a first-class rine entity a caller can
 * reference, and this ladder is reached FROM the thread verb
 * (`readThreadPage` → `resolveGroupUuid`), so `thread` here would peel a word
 * inside the verb that word names. `team` and `list` are absent because both
 * are content in the domains this product serves (`#platform-team`,
 * `pick-list`), and `dm`/`inbox` because they name the 1:1 namespace —
 * answering one with a group is the misdelivery this ladder exists to avoid.
 *
 * 🔴 The same set as the Python twin's `GENERIC_GROUP_NOUNS`, and
 * `test/group-ref.test.ts` lifts both out of the source and compares them: two
 * word sets that drift are one reference resolving on the SDK a caller did not
 * pick, which nothing else in either suite would notice.
 */
const GENERIC_GROUP_NOUNS: ReadonlySet<string> = new Set([
	"group",
	"groups",
	"channel",
	"channels",
	"chat",
	"chats",
	"room",
	"rooms",
]);

/**
 * The one article a caller writes in front of a group's name.
 *
 * Leading position only — a trailing `the` is not a thing a person writes.
 * `a`/`an` are excluded: neither is natural in a recipient slot, and both are
 * two-letter tokens with a real chance of colliding with a slug segment.
 */
const LEADING_ARTICLES: ReadonlySet<string> = new Set(["the"]);

/**
 * The local part of a group handle: `#ops@acme.rine.network` → `ops`.
 *
 * Exported because it is also the only query that can find a group in the
 * public directory by handle: `POST /groups` mints the handle as
 * `#${name}@${org}` and `name` is a validated DNS slug, so the local part **is**
 * `Group.name` byte for byte, and `GET /directory/groups?q=` — which searches
 * `name` and `description`, never `handle` — will return the row when asked for
 * it. `resolve-group-join.ts` is the caller that needs that; its Python twin is
 * `rine._group_ref.group_local_part`.
 *
 * 🔴 `/^#+/` and not `/^#/`, which is the ONE spelling where the two stacks had
 * measurably drifted: Python strips with `lstrip("#")`, which eats a whole run,
 * and a single-sigil strip left `##ops` as `#ops` here. That is not cosmetic —
 * {@link isInvitationOfThatName} (`group-join-words.ts`) compares this against a
 * pending invitation's handle, so `join("##ops")` was seated on the three Python
 * connectors and refused on eve and mastra: one reference, two answers,
 * decided by which SDK the caller happened to be running.
 *
 * The stacks converge on the FORGIVING spelling, deliberately. Tightening
 * Python instead would REMOVE a spelling that ships today on three surfaces,
 * and the permissive side is bounded to groups that have ALREADY invited this
 * agent — a doubled sigil can reach no group that a single one could not, so
 * nothing irreversible widens. {@link matchGroupByName} below already strips the
 * run for the same reason; this makes the third copy agree with the other two.
 */
export function groupLocalPart(handle: string): string {
	const [local = ""] = handle.split("@");
	return local.replace(/^#+/, "");
}

/**
 * A group reference with its `#` on, which is how group handles compare.
 *
 * 🔴 **The sigil is not decoration on the wire.** A stored group handle always
 * carries it (`POST /groups` mints `#${name}@${org}`), and the server's
 * `?handle=` filter is an equality test against that stored string — so a
 * caller who writes `ops@acme.rine.network`, which every handle comparison on
 * this stack treats as the same reference, misses the lookup entirely unless
 * the sigil is put back first.
 *
 * One exported helper rather than the eleventh inline restatement of
 * `x.startsWith("#") ? x : "#" + x`: the two callers that matter are the seated
 * lookup (`resolve-group.ts`) and the join ladder's exactness filter
 * (`group-join-words.ts`), and those two disagreeing is a group that resolves
 * for one verb and 404s for another. Its Python twin is
 * `rine._group_ref.sigiled_group_ref`.
 */
export function sigiledGroupRef(reference: string): string {
	return reference.startsWith("#") ? reference : `#${reference}`;
}

/**
 * The two spellings a group answers to: the handle's local part, which is what
 * the wire takes, and `name`, which is what the creator typed and what every
 * listing prints back.
 *
 * ⚠️ **On every group this server has minted they are the same string**, so the
 * `name` half matches nothing the local part did not already match. `POST
 * /groups` builds the handle as `#${name}@${org}` unconditionally
 * (`src/rine/api/group_routes_crud.py`), `name` must pass `validate_slug`, and
 * `GroupUpdate` carries no `name` field at all — a group name is its handle's
 * local part, and immutable. Say that plainly rather than implying the two
 * columns carry different information: they do not, and a reader who believes
 * they do will read the roster rows below as saying twice as much as they do.
 *
 * The second spelling is kept rather than deleted because it is a wire field,
 * not a derived one: `GroupRead.name` arrives from the server on every listing,
 * and the day it diverges from the slug — a rename, an import, a row that came
 * from somewhere else — the ladder must not refuse the string the product
 * itself printed. It costs one comparison, and because a match is identified by
 * the GROUP and never by the spelling that found it, it can never widen a tier
 * past the groups the local part already reached.
 */
function spellings(group: GroupRead): string[] {
	return [groupLocalPart(group.handle ?? ""), group.name ?? ""];
}

/**
 * One reference, reduced to the form two spellings of the same group share.
 *
 * Case-folded, every run of non-alphanumerics collapsed to a single `-`, and
 * the leading/trailing separators dropped — so `"Quarterly Planning"`,
 * `"quarterly_planning"` and `"#quarterly-planning"` are one string. The leading
 * `#` a caller may or may not type falls out of the same rule rather than
 * needing its own.
 *
 * ⚠️ Narrower than Python's `str.casefold()` in one direction, recorded rather
 * than chased. `toLowerCase()` is simple case mapping; `casefold()` is FULL
 * case folding, so wherever Unicode expands one character into several the
 * Python twin resolves a reference this stack refuses. Measured, not guessed —
 * the whole reachable class, so the next reader checks against a class and not
 * against one example:
 *
 * | reference | Python | here |
 * |---|---|---|
 * | `Straße` | `strasse` | `straße` |
 * | `ﬁle` (ligature) | `file` | `ﬁle` |
 * | `ﬃ` | `ffi` | `ﬃ` |
 * | `ΣΣ` | `σσ` | `σς` (final sigma) |
 * | `ᾼ` (iota subscript) | `αι` | `ᾳ` |
 *
 * Only the caller-supplied REFERENCE can carry any of these: both a group
 * handle's local part and a group `name` are DNS slugs on the server, so the
 * candidate side normalises identically on both stacks. The concrete case is a
 * group called `file` and a caller who pasted `ﬁle` out of a PDF. The
 * alternative is restating Unicode's full-case-folding table in a regex, which
 * is a bigger promise than the divergence is worth — but the divergence is
 * real, and this is the table that explains it.
 *
 * {@link refuseIfABareAgentName} carries the same split and is NOT reachable
 * through it: an agent `name` is `[a-z0-9-]` on the server, so the guard's two
 * sides are ASCII on every row it can ever compare.
 */
export function normalizeGroupRef(value: string): string {
	return value
		.toLowerCase()
		.replace(/[^\p{L}\p{N}]+/gu, "-")
		.replace(/^-+|-+$/g, "");
}

/**
 * Whether a recipient spelling names neither namespace, as written.
 *
 * Not a UUID, no `@`, no leading `#` — the exact set `resolveToUuid`
 * (`resolve-agent.ts`) refuses before any HTTP, which is why routing it to the
 * group ladder can take nothing away. It is the complement of that refusal and
 * must stay one: widening it past what the agent namespace has already declined
 * is how a routing convenience turns into a misdelivery on an E2EE product.
 *
 * The strict `UUID_RE` and not `parsesAsUuid`, deliberately. The looser
 * predicate is the one a *pre-flight* must ask, because a pre-flight may only
 * refuse what the wire would have refused; this is the opposite question. A
 * dashless UUID is a spelling `resolveToUuid` already refuses on syntax, so it
 * is bare here for the same reason every other bare word is, and the twin's
 * `is_uuid` reads it the same way.
 *
 * A blank recipient is deliberately NOT one of them. It names nothing in either
 * namespace, and the agent resolver's *"expected a UUID or handle"* says that
 * far better than a hunt through the groups the key can see ending in *"no group is
 * called ''"* would.
 *
 * Re-expressed over {@link classifyReference} rather than restating its four
 * tests: `bare` is defined as the class those four tests leave, so the two
 * cannot answer differently about one string.
 *
 * 🔴 **No production caller, and kept on purpose — do not sweep it.** The
 * send path is `resolveRecipient`, which asks `classifyReference` directly, so
 * every reference to this function is a test or this file. Two things depend
 * on it anyway. It is a published export of
 * `@rine-network/core` (`index.ts` re-exports this module whole), so deleting
 * it breaks an out-of-repo consumer's build in a non-major release. And it is
 * the reference definition the classifier is checked AGAINST:
 * `test/recipient-resolution.test.ts`'s *"is the whole of what isBareReference
 * and isSigilGroupReference ask"* proves the five-class table equivalent to
 * these two predicates, so deleting the predicate deletes the only thing that
 * proof stands on — after which `bare` could be widened to admit `#ops` with
 * nothing going red.
 */
export function isBareReference(value: string): boolean {
	return classifyReference(value) === REF_CLASS.bare;
}

/**
 * Whether a recipient spelling names the group namespace and only that: the
 * sigil, with no `@` to make it a whole handle.
 *
 * The other half of {@link isBareReference}'s set, and a SECOND predicate
 * rather than a widening of that one on purpose — `isBareReference` is the
 * exact complement of `resolveToUuid`'s syntactic refusal, its docstring makes
 * that the whole safety argument, and the day it also admits `#ops` the
 * argument stops being checkable against the resolver it names. Together the
 * two cover exactly what the agent namespace refuses before any request: not
 * blank, no `@`, not a UUID (a string that opens with `#` can be neither), so
 * routing either set to the group ladder can still take nothing away.
 *
 * 🔴 The two sets are NOT interchangeable, and the difference is the
 * collision guard. On the send path (`resolveRecipient`) the classifier's ARMS
 * enforce it: {@link refuseIfABareAgentName} stands in front of the `bare`
 * arm, because a bare `ops` may be a caller who meant `ops@acme` and dropped
 * the org. A sigiled `#ops` cannot be: `#` is the group sigil throughout this product's
 * addressing, no agent handle carries one, and an agent `name` is a DNS slug
 * that can never contain one. The caller has said which namespace it means, so
 * the guard is skipped — running it anyway would refuse a correct group send
 * with *"'ops' is the name of an agent of your org"*, a sentence that is false
 * about what the caller actually wrote.
 *
 * `#ops@acme.rine.network` is deliberately not one of these. It is a whole
 * handle, the server's own `?handle=` lookup answers it exactly, and it keeps
 * going there — which is the `@` test below, and the reason this is narrower
 * than {@link classifyReference}'s `group` class rather than equal to it. The
 * class says which NAMESPACE the caller named; this says which LADDER inside it
 * can answer, and a whole handle has its own.
 */
export function isSigilGroupReference(value: string): boolean {
	return classifyReference(value) === REF_CLASS.group && !value.includes("@");
}

/**
 * Whether `candidate` begins with all of `want`'s segments.
 *
 * Whole segments, never characters. A character prefix would make every short
 * reference ambiguous with a set of groups the caller cannot see the boundary
 * of; a segment boundary is one they can point at in the handle they were
 * shown.
 */
function startsWithSegments(candidate: string[], want: string[]): boolean {
	if (want.length === 0 || candidate.length < want.length) return false;
	return want.every((segment, i) => candidate[i] === segment);
}

/**
 * The candidates the first of tiers 1–3 that matches anything produces.
 *
 * Every match of that tier, never the first one and never a merge of two tiers:
 * the caller decides what one match, several, or none mean, and it must be able
 * to tell *"this tier was ambiguous"* from *"no tier matched"*.
 *
 * A group that matches by both its handle and its name is one candidate, not
 * two — the tiers are evaluated per group, so the identity of a match is the
 * group and never the spelling that found it.
 *
 * Not exported, and it stays that way: {@link groupReferenceMatches} re-runs
 * this whole body against a reduced reference, so a caller reaching it directly
 * would be asking for the ladder minus its last rung.
 */
function tiersOneToThree(
	groups: readonly GroupRead[],
	name: string,
): GroupRead[] {
	const exact = groups.filter((g) => groupLocalPart(g.handle ?? "") === name);
	const wanted = normalizeGroupRef(name);
	// An empty normalisation (`"#"`, `"---"`) would prefix-match every group in
	// the org, so tiers 2 and 3 are not reachable without one.
	if (exact.length > 0 || wanted === "") return exact;

	const spelt = (g: GroupRead) => spellings(g).map(normalizeGroupRef);
	const equal = groups.filter((g) => spelt(g).includes(wanted));
	if (equal.length > 0) return equal;

	const wantSegments = wanted.split("-");
	return groups.filter((g) =>
		spelt(g).some((s) => s !== "" && startsWithSegments(s.split("-"), wantSegments)),
	);
}

/**
 * The shorter references tier 4 tries, shortest peel first.
 *
 * ONE segment per step, the leading article before any trailing noun, and the
 * remainder yielded after each — because the caller re-runs the whole ladder
 * between two steps, and only that ordering lets a longer group win. An org
 * holding `#ops-chat` and `#ops`, given `ops chat room`, must resolve
 * `#ops-chat`: a single whole-run strip would yield `ops` and steal the answer
 * from the group that answers to more of what the caller wrote.
 *
 * Peeling only `while (segments.length > 1)` is the loop condition rather than
 * a check afterwards, which makes an empty remainder unrepresentable, bounds
 * the walk at `segments.length - 1` steps, and is what makes `the group`,
 * `groups` and `the` refuse instead of prefix-matching the whole org.
 *
 * @param wanted The reference, already through {@link normalizeGroupRef}.
 */
function* reducedReferences(wanted: string): Generator<string> {
	let segments = wanted.split("-");
	if (segments.length > 1 && LEADING_ARTICLES.has(segments[0] ?? "")) {
		segments = segments.slice(1);
		yield segments.join("-");
	}
	while (segments.length > 1 && GENERIC_GROUP_NOUNS.has(segments.at(-1) ?? "")) {
		segments = segments.slice(0, -1);
		yield segments.join("-");
	}
}

/**
 * The candidates the ladder produces, tier 4 included.
 *
 * Tiers 1–3 first, unchanged and unreachable-past: they decide alone whenever
 * they match anything at all, so no reference that resolved before tier 4
 * existed can move. Tier 4 fires ONLY on the empty result — it drops one
 * generic classifier noun (or the leading article) from the reference and
 * re-runs tiers 1–3 against the remainder, again and again while there is a
 * remainder to try.
 *
 * 🔴 That makes it strictly widening. The only transitions it can introduce are
 * *"no such group"* → resolved, *"no such group"* → an ambiguity refusal that
 * names the candidates, and *"no such group"* → *"no such group"*. A resolution
 * can neither move nor become a refusal.
 *
 * A loop over {@link tiersOneToThree}, never recursion through this function:
 * recursion would make the peel order depend on call depth and the termination
 * bound something a reader has to derive.
 */
function groupReferenceMatches(
	groups: readonly GroupRead[],
	name: string,
): GroupRead[] {
	const matches = tiersOneToThree(groups, name);
	if (matches.length > 0) return matches;
	for (const reduced of reducedReferences(normalizeGroupRef(name))) {
		const widened = tiersOneToThree(groups, reduced);
		if (widened.length > 0) return widened;
	}
	return [];
}

/**
 * The groups worth naming, one per line, in the one column set every refusal
 * prints.
 *
 * Module-private for the reason `formatActorList` is: the refusals below are
 * the only ways this list reaches a caller, and a third caller would mint a
 * third wording beside them.
 *
 * The handle leads each row because it is the spelling the caller can hand
 * straight back; the name follows in parentheses because it is the spelling
 * they started from.
 *
 * The empty-field arms are a guard against a wire that contradicts its own
 * type, and are worth naming precisely so nobody reads them as a fact about
 * groups: `groups.name` and `groups.handle` are both `nullable=False`
 * (`src/rine/db/models/groups.py`) and `GroupRead` types them `string`, so unlike
 * `agents.handle` — genuinely nullable, and the reason `bob (null)` once
 * shipped on the actor side — no row the server can mint reaches them. They
 * cost two `||` and they are what stands between a bad row and a refusal that
 * says `undefined`, which is a refusal a caller cannot act on at all.
 */
function formatGroupList(groups: readonly GroupRead[]): string {
	const shown = groups.slice(0, MAX_LISTED_GROUPS);
	const rows = shown.map((g) => {
		const handle = g.handle || g.id || "?";
		return g.name ? `  - ${handle} (${g.name})` : `  - ${handle}`;
	});
	if (groups.length > shown.length) {
		rows.push(`  … and ${groups.length - shown.length} more`);
	}
	return rows.join("\n");
}

/**
 * One refusal's tail: the groups worth naming, or the reason there are none.
 *
 * 🔴 The zero-group branch is the half a hand-rolled copy always drops — the
 * lesson `andTheAgentsThereAre` (`actor.ts`) was extracted for, whose docstring
 * records the shipped sentence that trailed off exactly where the caller most
 * needed to be told there was nothing to choose from. Every arm that refuses a
 * group reference ends here, so no arm can lose either half again.
 *
 * The two sentences and the rows are this module's; the JOINS are
 * {@link composeGroupRefusal}'s, so the group roster and the agent roster
 * cannot drift apart in their punctuation.
 */
function groupCandidates(groups: readonly GroupRead[]): RefusalCandidates {
	return {
		rows: formatGroupList(groups),
		rosterLead: GROUP_ROSTER_LEAD,
		whenEmpty: NO_GROUPS_IN_ORG,
	};
}

function andTheGroupsThereAre(
	lead: RefusalLead,
	spelling: string,
	groups: readonly GroupRead[],
): string {
	return composeGroupRefusal({
		lead,
		spelling,
		candidates: groupCandidates(groups),
	});
}

/**
 * Told to a caller whose reference answers to no group of this org.
 *
 * Exported for the one arm of the ladder that cannot reach it through
 * {@link matchGroupByName}: a UUID names a group by identity rather than by
 * spelling, so `resolveGroupRef` (`resolve-group.ts`) matches it on `id` and has
 * no tier to fall through into. Refusing it in its own words there would be the
 * second wording for "no such group" this module exists to prevent — and the
 * roster tail is exactly what a caller holding a stale id needs.
 */
export function unknownGroupRefusal(
	groups: readonly GroupRead[],
	name: string,
): string {
	return andTheGroupsThereAre(
		// The lead terminates itself, and the spelling sits in front of that
		// terminator rather than in place of it: a caller who wrote `ops.` is
		// quoted back as `ops.` and the sentence still ends, so the shipped
		// `Group not found: ops.. Name one of these groups:` is exactly what it
		// was before the composer existed.
		(said) => `${GROUP_NOT_FOUND_LEAD}: ${said}.`,
		name,
		groups,
	);
}

/**
 * The pointer an unknown-group refusal grows when the caller holds MLS state.
 *
 * The eviction sentence is reachable on a UUID and on nothing else: the
 * wrap that composes it needs a group id, and `holdsMlsState` is keyed by one.
 * A caller who names a group by handle or by bare name — which the help
 * advertises on twelve verbs — resolves to no row at all when removed, so
 * there is no id left to ask the local question with, and they read
 * {@link GROUP_NOT_FOUND_LEAD} over a roster they are no longer on.
 *
 * 🔴 This is a POINTER, not that sentence. Nothing here has checked any group's
 * ratchet tree; all that is known is that this agent holds state for something,
 * so the text says "may" and names the verb that can actually answer it. Saying
 * "You were removed" on this evidence would tell an agent who simply mistyped a
 * group name that it had been evicted.
 *
 * The verb is named with a UUID and not with the reference the caller actually
 * typed, which reads like a mismatch and is not one: {@link resolveGroupByHandle}
 * and {@link resolveGroupByName} both reach the group through `GET /groups`,
 * which is key-scoped, so neither rung can see a group this agent no longer
 * holds a seat in. `readableGroupById` reads the row directly. For an evicted
 * caller the UUID is the only spelling that resolves at all.
 *
 * Which leaves them needing one, so the tail says where. The ids are not
 * fetched from anywhere — they are already on disk, one directory per group
 * under the native core's store, each named by {@link mlsGroupIdBytes}: the
 * rine group UUID's own bytes in hex, which is the UUID with its dashes
 * removed. Naming that directory can never be a dead end, because the only
 * thing that puts this tail on a refusal is `holdsAnyMlsState` finding it
 * non-empty.
 */
export const EVICTION_POINTER_TAIL =
	"You may have been removed from a group you still hold state for — `rine group get <uuid>` will say so, and the groups you hold state for are one directory each under this agent's `mls2/groups` store, named by id with the dashes removed.";

/**
 * Append {@link EVICTION_POINTER_TAIL} to a refusal, and read as English after
 * whatever that refusal ended with.
 *
 * A group refusal ends one of two ways, and they take different punctuation. A
 * refusal for an org with no groups is one sentence, and the tail joins it
 * through {@link joinSentences} — never a hand-rolled `". "`, which is the
 * doubled full stop `rine-eve` shipped and that seam exists to make impossible.
 * A refusal that named a roster ends in bullet rows, and a sentence trailing a
 * bullet is not English at all: the tail takes its own line there, where no
 * terminator can double because none is being joined.
 */
export function withEvictionPointer(refusal: string): string {
	return refusal.includes("\n")
		? `${refusal}\n${EVICTION_POINTER_TAIL}`
		: joinSentences(refusal, EVICTION_POINTER_TAIL);
}

/**
 * Told to a caller whose reference answers to more than one group.
 *
 * Picking one would read, post to, or invite into a group the caller did not
 * choose — and `GET /groups` has no `ORDER BY`, so which one it picked could
 * differ between two identical calls. The candidates are printed instead, by
 * handle, which is the spelling that still tells two same-named groups of two
 * different orgs apart.
 */
function ambiguousGroupRefusal(
	matches: readonly GroupRead[],
	name: string,
): string {
	return andTheGroupsThereAre(
		(said) => `Group name '${said}' is ambiguous — more than one group answers to it.`,
		name,
		matches,
	);
}

/**
 * Resolve a bare group reference against the caller's own groups.
 *
 * The server's `GET /groups?handle=` matches a *full* `#name@org` handle only,
 * so a bare `ops` finds nothing there however many groups carry that name.
 * Listing the groups the key can see and running the ladder over them is what lets every
 * group verb take the name a caller says out loud.
 *
 * `spelling` is what a refusal quotes, and it exists because of the handle
 * fallback: a handle whose org half answered nothing is retried on its LOCAL
 * PART, and a refusal that then said *"Group not found: heron-count"* would be
 * answering a caller about a string they never typed. Matching is always on
 * `name`; only the sentence changes. Defaults to `name`, so every pre-existing
 * call site keeps the wording it had.
 *
 * @throws {Error} No group answers to that reference, or more than one does.
 */
export function matchGroupByName(
	groups: readonly GroupRead[],
	name: string,
	spelling?: string,
): GroupRead {
	// `/^#+/` and not `/^#/`, to strip what Python's `lstrip("#")` strips.
	const wanted = name.trim().replace(/^#+/, "").trim();
	const matches = groupReferenceMatches(groups, wanted);
	const said = spelling ?? name;
	const only = matches[0];
	if (matches.length === 1 && only) return only;
	if (matches.length > 1) throw new Error(ambiguousGroupRefusal(matches, said));
	throw new Error(unknownGroupRefusal(groups, said));
}

/**
 * The whole safety argument for resolving a bare recipient as a group.
 *
 * A caller who meant `ops@acme` and wrote `ops` must not silently post to a
 * group called `ops`. The two namespaces answer to the same word, and only one
 * of them can be entered by mistake here, so a bare name that is also an
 * agent's name is refused outright — never a silent DM either, because
 * recipient resolution requires a handle by design and widening the agent side
 * is a decision nobody has taken.
 *
 * Lives beside the group ladder rather than in `actor.ts` because it is not
 * part of the acting-agent contract: it exists only as the gate in front of
 * {@link recipientGroupForBareName}, over the org agent list the caller has
 * already fetched.
 *
 * ⚠️ The fold below carries the same `toLowerCase`/`casefold` divergence
 * {@link normalizeGroupRef} tabulates, and it is worth saying HERE because this
 * is the guard the safety argument rests on: a reference Python folds onto an
 * agent's name and this side does not is one this side does not refuse. It is
 * unreachable today — an agent's `name` is a DNS slug
 * (`src/rine/api/schemas_org.py`), so only the caller's spelling can carry a folding
 * case, and a caller who types `STRASSE` at an agent named `strasse` falls
 * through to the group ladder here, where nothing answers to it either.
 * Reachability would change the day an agent name stops being a slug.
 *
 * @throws {Error} An agent of this org carries that name.
 */
export function refuseIfABareAgentName(
	agents: readonly AgentRead[],
	name: string,
): void {
	const folded = name.trim().toLowerCase();
	const named = agents.filter((a) => (a.name ?? "").toLowerCase() === folded);
	if (named.length === 0) return;
	const spellings = named.map((a) => a.handle || a.id || "?").join(", ");
	// The caller's OWN org, taken from the handles this same refusal already
	// prints, so the second half is a reference they can paste rather than a
	// form with `org` left standing in it.
	//
	// 🔴 A slugless org mints no handles and has nothing to derive from, and a
	// placeholder domain inside a refusal is banned. It answers with the sigil
	// form of the caller's own word instead. `#ops` is not a hedge and not a
	// shape: it is a first-class recipient spelling
	// ({@link isSigilGroupReference}), it is the one spelling this guard is
	// deliberately SKIPPED for — so it turns this very refusal off — and it
	// needs no org half, which is the entire content of "slugless". A handle
	// spelling is the one thing this caller provably cannot construct.
	//
	// 🔴 `folded`, never the caller's own spelling, and it is the paste that
	// depends on it: a group name is a lowercase DNS slug on the server
	// (`validate_slug`, `src/rine/api/group_schemas.py`), the handle is minted
	// verbatim from it (`group_routes_crud.py`), and the handle lookup is an exact match —
	// so `#OPS@acme.rine.network` is a reference no group can ever carry. The
	// twin folds here too (`_group_spelling_for`, `rine-sdk/_group_ref.py`).
	const org = named.map((a) => a.handle).find(Boolean)?.split("@")[1];
	const asAGroup = org ? `#${folded}@${org}` : `#${folded}`;
	// The one refusal here with no roster to name: the caller's mistake is which
	// NAMESPACE they addressed, and the org's group list answers a question they
	// did not ask. So it carries a next step instead — the two spellings that
	// would have worked — and rule 3 never fires on it.
	throw new Error(
		composeGroupRefusal({
			lead: (said) =>
				`'${said}' is the name of an agent of your org, not a group reference`,
			spelling: name,
			nextStep:
				`To message that agent, name it by handle: ${spellings}. ` +
				`To post to a group of that name, write it as ${asAGroup}.`,
		}),
	);
}

/**
 * The group a bare `send()` recipient names, or a refusal that names both.
 *
 * Run only after {@link refuseIfABareAgentName} has cleared the name, and only
 * for a spelling the agent namespace has already declined on syntax.
 *
 * 🔴 **The zero-match arm does not open with a GROUP verdict.**
 * {@link GROUP_NOT_FOUND_LEAD} would be half an answer to a question the caller
 * had not asked in either namespace: by the time this arm fires the reference
 * cannot be an agent identifier AND no agent of this org carries the name, so
 * both halves have said no. It opens with {@link NEITHER_NAMESPACE_LEAD} — the
 * caller's spelling, then both verdicts at once — and still names both
 * spellings, because the caller's next attempt has to pick one of them.
 *
 * 🔴 The six surfaces that branch on a lead recognise this one; the roster
 * comes last. Changing the lead in `rine-core` alone is the silent reroute the
 * `_client.py` docblocks name.
 *
 * 🔴 What it must never say: *"a bare name is neither"*.
 * A bare name **is** read as a group — that is this function — and every tool
 * description on every surface now teaches a caller to write one. A refusal
 * that contradicts the instruction the caller has just followed teaches them
 * the product is broken rather than that this org has no such group. It says
 * what was looked for and where instead, and the roster tail names what there
 * was to find.
 *
 * 🔴 **The placeholder ban, second rung: the two spellings are DESCRIBED, never
 * shown.** An example handle baked into the LEAD could never be taken back out
 * by the suppression rule when the roster below is appended — a placeholder
 * domain in a refusal, under a list of the caller's real handles. A model
 * given a printed domain moves the local part with the conversation and leaves
 * the domain untouched. Rung 1 (the caller's own org, derived from a handle the sentence
 * already prints) is unreachable here — this function holds groups and no
 * agents, and the arm fires precisely when NO group answered — so it takes rung
 * 2, a structural description with nothing in it to paste. Not a `<slot>`
 * either: `check-model-facing-examples.mjs`'s `template-org` rule forbids that
 * for the measured `agent:"null"` reason. The advice itself is kept, which is
 * what separates this from removing the advice outright — a caller is still
 * told that the two namespaces are addressed differently and how each is
 * shaped.
 *
 * @throws {Error} No group answers to that reference, or more than one does.
 */
export function recipientGroupForBareName(
	groups: readonly GroupRead[],
	name: string,
): GroupRead {
	const matches = groupReferenceMatches(groups, name.trim());
	const only = matches[0];
	if (matches.length === 1 && only) return only;
	if (matches.length > 1) throw new Error(ambiguousGroupRefusal(matches, name));
	throw new Error(
		andTheGroupsThereAre(
			(said) =>
				`'${said}' ${NEITHER_NAMESPACE_LEAD}. A bare name is read as a group you ` +
				"hold a seat in, and none of them answers to it. An agent is " +
				"addressed in full — its name, an at sign, and its org's domain — " +
				"and a group by its whole handle, which is a leading hash and the " +
				"same three parts.",
			name,
			groups,
		),
	);
}
