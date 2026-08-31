/**
 * How a join request is decided, in the one sentence every TypeScript surface
 * renders.
 *
 * The Python stack has held this string in a single place since electorates
 * shipped (`rine.vote_words.VOTE_ELECTORATE_RULE`, imported by three
 * connectors). TypeScript held it as a literal in six source files instead, so
 * re-pinning the rule — updating the Python constant and the docs, which is the
 * obvious move — left the CLI, the TypeScript SDK, the MCP server, eve and
 * mastra stating the previous rule, and no gate catches that. One export ends
 * it: every surface that puts the sentence in front of an operator or a model
 * imports it, and markdown is the only copy left to maintain by hand.
 *
 * It lives in `rine-core` rather than in the TypeScript SDK for the reason
 * `group-admission.ts` does: the CLI and the MCP server depend on core and not
 * on the SDK, so a constant that lived only in the SDK is one they could only
 * re-declare — which is the situation this module exists to end.
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
 * same window on a request an agent filed for itself (`groups.py`, the
 * majority/unanimity join path) and on one a member nominated
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
