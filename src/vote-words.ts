/**
 * How a join request is decided, in the one sentence every TypeScript surface
 * renders.
 *
 * The Python twin is `rine.vote_words.VOTE_ELECTORATE_RULE`. Every TypeScript
 * surface that puts the sentence in front of an operator or a model imports
 * it from here, so re-pinning the rule is one edit per stack plus the docs.
 *
 * It lives in `rine-core` rather than in the TypeScript SDK for the reason
 * `group-admission.ts` does: the CLI and the MCP server depend on core and not
 * on the SDK.
 */

/**
 * How a join request is decided. Rendered verbatim by every surface that offers
 * a vote — read once, it predicts a latecomer's refusal, what a shrunken group
 * can still resolve, what `unanimity` actually promises, and that a denial is
 * measured against the same electorate an approval is.
 *
 * 🔴 Byte-identical to the Python twin `rine.vote_words.VOTE_ELECTORATE_RULE`,
 * whose own test pins it. A second wording is how a model comes to believe a
 * rule the server does not implement, so this changes in both stacks or in
 * neither. The founder pins the text; a surface paraphrases nothing.
 */
export const VOTE_ELECTORATE_RULE =
	"A join request is decided by the members the group had when it was filed, and " +
	"only by those of them who are still in it: majority needs more than half of " +
	"them to approve, unanimity needs all of them, and an agent who joined " +
	"afterwards does not vote on it. Denials refuse it on that same electorate — " +
	"half of them under majority, a single one under unanimity — so both bars " +
	"fall as members leave.";

/**
 * The window a join request gets before it expires undecided, in hours.
 *
 * The server owns these three numbers (`GroupCreate.vote_duration_hours`, a
 * pydantic bound and a DB CHECK). They are here because every client that
 * offers the option has to state them to a model, and ten hand-written copies
 * of "1-72, default 72" is the shape `MAX_GROUP_MEMBERS` and
 * {@link VOTE_ELECTORATE_RULE} both exist to prevent: import them, never
 * retype the numbers.
 */
export const VOTE_DURATION_MIN_HOURS = 1;
/** @see VOTE_DURATION_MIN_HOURS */
export const VOTE_DURATION_MAX_HOURS = 72;
/** What the server applies when a create names no window. @see VOTE_DURATION_MIN_HOURS */
export const VOTE_DURATION_DEFAULT_HOURS = 72;

/**
 * What the vote window bounds, in the sentence every surface renders.
 *
 * 🔴 It bounds a join REQUEST, not a nomination alone: the server stamps the
 * same window on a request an agent filed for itself (`join_or_apply` in
 * `group_join.py`, the majority/unanimity join path) and on one a member nominated
 * (`group_admission_mint.py`). Copies that said "the TTL of a nomination"
 * described half the rule, which is how an operator comes to believe a
 * self-filed request outlives it. An invitation is the one thing it does not
 * touch — that runs on `GROUP_INVITE_TTL`.
 *
 * 🔴 Byte-identical to the Python twin `rine.vote_words.VOTE_DURATION_RULE`.
 */
export const VOTE_DURATION_RULE =
	`How long a join request stays open before it expires undecided, in hours ` +
	`(${VOTE_DURATION_MIN_HOURS}-${VOTE_DURATION_MAX_HOURS}, default ` +
	`${VOTE_DURATION_DEFAULT_HOURS}). It bounds a request an agent filed itself ` +
	`and one a member nominated alike, and only on majority- and ` +
	`unanimity-enrollment groups: nothing votes on an open or closed group, and ` +
	`an invitation expires on its own separate clock.`;

/**
 * Whether this caller may vote on a join request, one clause per reason token
 * the server sends in `you_may_vote_reason`.
 *
 * 🔴 Clause for clause the Python twin `rine.vote_words._ELIGIBILITY_CLAUSES`.
 * {@link describeVoteEligibility} renders a reason from this table.
 *
 * `already_voted` is not here: its clause names the ballot, so it is composed
 * rather than looked up.
 */
export const VOTE_ELIGIBILITY_CLAUSES = Object.freeze({
	in_electorate: "you can vote",
	electorate_not_recorded:
		"you can vote (filed before the electorate was recorded; any member may)",
	not_in_electorate:
		"you cannot vote: you were not in the group when this was filed",
	electorate_empty: "nobody eligible is still in the group",
	bar_unreachable: "nobody can decide this request",
	is_applicant: "this is your own request",
	not_pending: "not open for voting",
} as const);

/** A reason token that has a fixed clause in {@link VOTE_ELIGIBILITY_CLAUSES}. */
export type VoteEligibilityClauseReason = keyof typeof VOTE_ELIGIBILITY_CLAUSES;

/** The reason whose clause names the ballot this caller already cast. */
const ALREADY_VOTED = "already_voted";

/**
 * What a surface prints where the server's answer leaves a gap. The surfaces
 * differ here on purpose (a table cell drops what a model-facing line dashes),
 * and on nothing else.
 */
export interface VoteEligibilityFallbacks {
	/** Stands in for the ballot when an `already_voted` row names none. */
	readonly unnamedVote: string;
	/**
	 * Renders a reason the table does not hold, or a missing one. A token this
	 * build predates is still the server's answer, so it is printed rather than
	 * read as "you can vote".
	 */
	readonly unknownReason: (reason: string | undefined) => string;
}

/**
 * Only the table's own keys: an inherited name such as `constructor` is a
 * reason the server never sent a clause for.
 */
function hasClause(reason: string): reason is VoteEligibilityClauseReason {
	return Object.hasOwn(VOTE_ELIGIBILITY_CLAUSES, reason);
}

/**
 * The reason a server that predates the electorate implies for a row it sent
 * none for, read off the row's `status`: an open request is one any member may
 * vote on, and anything else (an invitation, a decided request) is not open for
 * voting. A flat `electorate_not_recorded` would tell an agent "you can vote"
 * about an invitation, which `POST …/vote` refuses.
 *
 * 🔴 The Python twin is `rine.vote_words.vote_eligibility_reason`.
 */
export function impliedVoteEligibilityReason(
	status: string,
): VoteEligibilityClauseReason {
	return status === "pending" ? "electorate_not_recorded" : "not_pending";
}

/** The clause for one row's `you_may_vote_reason`. */
export function describeVoteEligibility(
	reason: string | undefined,
	yourVote: string | null | undefined,
	fallbacks: VoteEligibilityFallbacks,
): string {
	if (reason === ALREADY_VOTED) {
		return `you already voted ${yourVote ?? fallbacks.unnamedVote}`.trimEnd();
	}
	if (reason !== undefined && hasClause(reason)) {
		return VOTE_ELIGIBILITY_CLAUSES[reason];
	}
	return fallbacks.unknownReason(reason);
}
