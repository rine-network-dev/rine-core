/**
 * What a group reference MEANS when the verb is join — matchers and sentences.
 *
 * The pure half of the join ladder: which reference answers to which row, what
 * the directory is asked for, and every sentence a refused join says. The rungs
 * themselves, which need an `HttpClient`, are `resolve-group-join.ts`.
 *
 * 🔴 **Twin of `rine-sdk/src/rine/_group_join.py`.** Same matchers, same
 * bounds, and the five sentences below are byte-identical to that module's;
 * `tests/test_client-server-contract_group0.py` pins the copies against each
 * other. A join that resolved on one stack and 404'd on the other would make
 * every surface's tool description a lie on whichever SDK the caller happened
 * to be wired to.
 */

import { GROUP_NOT_FOUND_LEAD, groupLocalPart, sigiledGroupRef } from "./group-ref.js";
import { normalizeHandle } from "./resolve-handle.js";

/**
 * What `GET /directory/groups` will return in one page at most.
 *
 * The server's own ceiling (`limit` is bounded 1–50 in
 * `src/rine/api/directory_groups.py`); asking for it is asking for the fewest
 * round trips a join can be resolved in.
 */
export const DIRECTORY_PAGE_LIMIT = 50;

/**
 * How many directory pages a single join may read before it gives up.
 *
 * A bound rather than a full walk, so a caller cannot turn one join into an
 * unbounded crawl of an IP-rate-limited public route.
 *
 * 🔴 **A bound is only honest if the refusal says it was hit.** The directory
 * orders by recency, not by match quality, and its filter is `name ILIKE` OR
 * `description ILIKE` — so a crowded substring can push the named group past
 * this budget however exact the caller's handle was. That is what
 * {@link DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ} exists for: the shortfall is
 * stated from the `total_estimate` the response already carries, and the
 * exhausted sentence is never said about a search that stopped early.
 */
export const DIRECTORY_PAGES_FOR_A_JOIN = 2;

/**
 * What a caller must hand `join` instead, named in the refusals below.
 *
 * 🔴 Twin sentence — `rine._group_join.JOIN_TAKES_A_HANDLE_OR_AN_ID` restates
 * it byte for byte. It names the two spellings and stops there: WHICH verb
 * prints them is a per-surface fact the SDK cannot know, and every wrapper
 * appends it already — both TypeScript connectors and all three Python ones key
 * on {@link GROUP_NOT_FOUND_LEAD} and add *"Try rine_groups … or
 * rine_discover_groups …"* in that surface's own vocabulary. A verb named here
 * too would be named twice, in one of them wrongly.
 *
 * 🔴 **The placeholder ban, second rung.** This is a REFUSAL — it is spliced
 * into {@link bareNameJoinRefusal} and {@link unresolvedHandleJoinRefusal} — so
 * the placeholder domain it used to print is banned. Rung 1, the
 * caller's own org, is unreachable to a module-level constant by construction:
 * it has no client, no agent list and no roster, so there is no handle to
 * derive an org from. The handle is described part by part instead. The sigil
 * substitution that answered site 2 is not available either — join genuinely
 * needs the whole handle or the id, which is what the sentence says.
 *
 * ⚠️ {@link JOIN_REFERENCE_RULE} below keeps its worked example and must: it is
 * a tool DESCRIPTION, which the ban exempts explicitly, and it is rendered where a
 * caller is being taught rather than corrected.
 *
 * ⚠️ One flat double-quoted literal, no semicolon inside it: the backend gate
 * `JOIN_REFUSAL_TWIN_SENTENCES` extracts this by `\bNAME\s*=\s*([^;]+);` and
 * then parses the match as a single constant, so a `+` concatenation or an
 * embedded `;` makes it unpinnable rather than merely ugly.
 *
 * 🔴 That is also why the part-by-part clause inside it is written out here
 * rather than composed from `GROUP_HANDLE_PARTS` (`handle-words.ts`), which is
 * the constant `rine-mcp`'s two copies of the same clause now read. The two are
 * bound by `test/handle-words.test.ts` instead of by an interpolation, so a
 * re-pin of either goes red rather than quietly diverging.
 */
export const JOIN_TAKES_A_HANDLE_OR_AN_ID =
	"Join takes a group's whole handle — a leading hash, the group's name, an at sign, and its org's domain — or its id.";

/**
 * What `join` accepts, rendered verbatim by every surface that offers it.
 *
 * 🔴 **One sentence, not one per connector.** `join`'s reference rules differ
 * from every other group verb's — three rungs for a handle, exactly one for a
 * bare name — so each surface had to say something the shared group-reference
 * text does not. Five hand-written copies of that is what
 * {@link VOTE_ELECTORATE_RULE} and `MAX_GROUP_MEMBERS` both exist to prevent,
 * and the failure mode here is worse than drift: a surface whose copy is stale
 * advertises a spelling this ladder refuses, and the model reads the refusal as
 * the product being broken.
 *
 * Names no verb, for the reason {@link JOIN_TAKES_A_HANDLE_OR_AN_ID} names
 * none: which tool prints a directory row is a per-surface fact, and each
 * surface's own error module already appends it.
 *
 * 🔴 Twin sentence — `rine._group_join.JOIN_REFERENCE_RULE` restates it byte
 * for byte.
 */
export const JOIN_REFERENCE_RULE =
	"Join takes a group's handle or its id, and resolves either exactly: a handle answers whether your org already holds a seat, this agent holds a pending invitation, or the group is public in the directory. A bare name is read only against this agent's pending invitations, and is refused when none of them is for a group of that name — nothing wider is searched for a bare name, because a join cannot be taken back and is never aimed at a guess. Example: #logistics@acme.rine.network.";

/**
 * The bare-name arm, after this agent's invitations came back with no match.
 *
 * 🔴 **A bare name is looked for in ONE place and never widened.** The only
 * rung that can see a group this agent has no relationship with is a
 * network-wide ILIKE over name-or-description, and a bare name has no exactness
 * filter to put behind it — a wrong match would seat this agent in a group
 * nobody named, and a join cannot be taken back. The invitations list is
 * different in kind: it is bounded to
 * groups that have already asked for this agent, so a match there cannot be a
 * group the caller has no business in.
 *
 * It says what the reference WAS read as rather than that it was meaningless:
 * every group verb on every surface teaches a caller to write a bare name, and
 * a refusal that contradicts the instruction the caller just followed teaches
 * them the product is broken.
 */
export const BARE_NAME_IS_ONLY_AN_INVITATION =
	"A bare name is read as one of this agent's pending invitations, and none of them is for a group of that name. Nothing wider is searched for a bare name: a join cannot be taken back, so it is never aimed at a guess.";

/**
 * The bare-name arm when the invitations answer more than once.
 *
 * Two orgs may both invite this agent to a group called `ops`, and the
 * invitations list is the one rung with no org in the reference to tell them
 * apart. Picking either would be the guess the arm above refuses; the
 * candidates are printed instead, by handle, which is the spelling that still
 * tells two same-named groups of two different orgs apart.
 *
 * Ends on a colon: the composer appends the handles, so the sentence and the
 * list cannot drift into two different orderings of the same idea.
 */
export const TWO_INVITATIONS_OF_THAT_NAME =
	"More than one of this agent's pending invitations is for a group of that name, and a join cannot be taken back, so none of them is guessed at. Name the one you mean by its whole handle:";

/**
 * The handle arm, after all three rungs were searched to the end.
 *
 * Says which three places were looked in, so a caller can tell "I typed it
 * wrong" from "this group is in none of the three places a handle can be
 * resolved from" — the second is not a spelling mistake and no amount of
 * re-reading the directory will fix it.
 *
 * 🔴 It names the invitations rung as *"one this agent's pending invitations
 * name"* rather than "one this agent was invited to", and the two are not the
 * same claim: an OPEN group's invite mints no voucher and no request row
 * (`src/rine/api/groups.py`), so an agent genuinely invited to an open,
 * private-visibility group has nothing on that list. The wider sentence would
 * be false to the one caller most likely to read it.
 */
export const NO_SUCH_GROUP_TO_JOIN =
	"No group of that handle is one this org is seated in, one this agent's pending invitations name, or a public group in the directory. A group in none of those three is not reachable by handle at all, and its id is the only reference that reaches it.";

/**
 * The handle arm when the directory search hit its page budget.
 *
 * 🔴 **A bounded search must never report itself as an exhaustive one.** With
 * the budget spent there are matching rows this join did not look at, so "no
 * public group of that handle" is a claim the client has not earned — and the
 * sentence it would otherwise say goes further and tells the caller the group
 * is unreachable by handle, which for a public group is false and unrecoverable
 * advice.
 *
 * `{unread}` is replaced with the exact shortfall — `total_estimate` minus the
 * rows this pass read, both off the responses it already has, so stating it
 * costs no extra request. Same substitution on both stacks, which is what keeps
 * one literal pinnable against its Python twin.
 */
export const DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ =
	"No group of that handle is one this org is seated in or one this agent's pending invitations name, and the public directory holds {unread} more groups matching that name than this join read — so this is not a report that the group is absent from it. The id the directory prints beside a handle reaches the group in one step.";

/**
 * Whether `candidate` is the very handle `reference` names.
 *
 * 🔴 **The exactness filter the directory rung depends on.** Equality, never a
 * prefix, a substring or a case fold — a group handle is `UNIQUE` on the server,
 * so an equality test over any set of rows can return at most one group, and
 * that is what makes a fuzzy candidate list safe to feed an irreversible verb.
 * Loosen this and rung 5 becomes the bare-name widening this ladder refuses.
 *
 * Both sides are normalised the way every other handle comparison on this stack
 * normalises: the sigil is optional (`ops@acme` and `#ops@acme` name the same
 * group) and a domain with no dot gets `.rine.network` appended, so the short
 * handle a directory row is quoted by matches the full one it stores.
 *
 * `candidate` is optional because the rows this runs over carry it that way:
 * `JoinRequestRead.group_handle` is enriched by the server and absent on a row
 * from an older one. A row with no handle answers to nothing.
 */
export function isExactGroupHandle(
	candidate: string | undefined,
	reference: string,
): boolean {
	if (!candidate) return false;
	return (
		normalizeHandle(sigiledGroupRef(candidate)) ===
		normalizeHandle(sigiledGroupRef(reference))
	);
}

/**
 * Whether a pending invitation is for the group a BARE name calls.
 *
 * The two spellings an invitation row can be called by: the local part of its
 * handle, which is what the wire takes, and `group_name`, which is what the
 * creator typed and what every listing prints back. On every group this server
 * has minted they are the same string — `POST /groups` builds the handle as
 * `#${name}@${org}` — so the second arm matches nothing the first did not,
 * except on a row whose handle the server did not enrich.
 *
 * The reference is stripped of its leading `#`s before either comparison,
 * because a sigiled, org-less `#ops` has no `@` and so arrives here too: it says
 * which namespace the caller means and nothing more, and the name it carries is
 * the same name. A whole RUN of them goes, not one — {@link groupLocalPart}
 * carries why, and that it is the spelling both stacks agreed on.
 *
 * 🔴 There is no org in a bare name, so this can answer for two invitations at
 * once. The caller must treat two matches as {@link TWO_INVITATIONS_OF_THAT_NAME}
 * and not as a pick — see `resolve-group-join.ts`.
 */
export function isInvitationOfThatName(
	groupHandle: string | undefined,
	groupName: string | undefined,
	name: string,
): boolean {
	const want = groupLocalPart(name);
	if (!want) return false;
	if (groupHandle && groupLocalPart(groupHandle) === want) return true;
	return groupName === want;
}

/**
 * The `?q=` that will surface `handle`'s row in the public directory.
 *
 * The local part, because that is the column the directory actually searches —
 * see {@link groupLocalPart} for why the two are the same string. Never widened
 * past it: a broader query cannot find more (the filter is a substring match
 * either way) and would only spend the page budget on rows
 * {@link isExactGroupHandle} is going to reject.
 */
export function directoryQueryForHandle(handle: string): string {
	return groupLocalPart(handle);
}

/** Refuse a bare name no invitation of this agent's answers to. */
export function bareNameJoinRefusal(name: string): string {
	return `${GROUP_NOT_FOUND_LEAD}: ${name}. ${BARE_NAME_IS_ONLY_AN_INVITATION} ${JOIN_TAKES_A_HANDLE_OR_AN_ID}`;
}

/** Refuse a bare name two of this agent's invitations both answer to. */
export function ambiguousInvitationJoinRefusal(
	name: string,
	handles: readonly string[],
): string {
	return `${GROUP_NOT_FOUND_LEAD}: ${name}. ${TWO_INVITATIONS_OF_THAT_NAME} ${handles.join(", ")}.`;
}

/**
 * Refuse a handle no rung resolved, saying where it was looked for.
 *
 * `unread` is how many matching public directory rows the search never read —
 * `0` when it ran to the end, which is the only case the exhaustive sentence is
 * true of.
 */
export function unresolvedHandleJoinRefusal(
	handle: string,
	unread = 0,
): string {
	const searched =
		unread > 0
			? DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ.replace(
					"{unread}",
					String(unread),
				)
			: NO_SUCH_GROUP_TO_JOIN;
	return `${GROUP_NOT_FOUND_LEAD}: ${handle}. ${searched} ${JOIN_TAKES_A_HANDLE_OR_AN_ID}`;
}
