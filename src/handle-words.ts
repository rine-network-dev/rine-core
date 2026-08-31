/**
 * How a group handle is SPELLED, as a clause a refusal can describe it with.
 *
 * 🔴 **The answer to "name the shape without printing one".** A refusal may
 * not print a placeholder domain (a model was measured pasting one
 * back verbatim, domain and all) and may not offer a `<slot>` either
 * (`check-model-facing-examples.mjs`'s `template-org` rule, the measured
 * `agent:"null"` failure). What is left is describing the handle part by part,
 * and three refusals on two packages had each written that description out by
 * hand — `JOIN_TAKES_A_HANDLE_OR_AN_ID` here, and `rine-mcp`'s
 * `groupRefArgument` and `replyToGroupRefusal`. Third repetition is where the
 * clause becomes a constant.
 *
 * Its own module rather than an entry in `group-join-words.ts`: two of the
 * three sentences that carry it have nothing to do with `join`, and the file
 * that owns join's vocabulary is already past the size ceiling.
 */

/**
 * The parts of a group handle, in order, as a refusal names them.
 *
 * A CLAUSE and not a sentence: it carries no leading capital and no full stop,
 * because each of its readers sets it in different surrounding punctuation — an
 * em-dashed aside on the join refusal, the same on `rine_group_*`'s missing
 * argument, and a colon-introduced tail on `rine_reply`'s. Compose it; never
 * re-terminate it.
 *
 * 🔴 **{@link JOIN_TAKES_A_HANDLE_OR_AN_ID} restates it flat rather than
 * composing it, and must.** That constant is pinned against its Python twin by
 * `tests/test_client-server-contract_group0.py`, which parses the declaration
 * with `ast` and asserts the result is a single string literal — a `+` or a
 * template makes the ratified sentence unpinnable rather than merely ugly. The
 * binding between the two lives in this package's own suite instead
 * (`test/handle-words.test.ts`), so a re-pin on one side cannot pass silently.
 */
export const GROUP_HANDLE_PARTS =
	"a leading hash, the group's name, an at sign, and its org's domain";
