import { normalizeHandle } from "./resolve-handle.js";

/**
 * The one sentence that tells a caller their spelling was not the spelling
 * looked up — composed here, rendered by each surface in its own idiom.
 *
 * 🔴 **Why this lives in `rine-core` rather than on a surface.**
 * {@link resolveToUuid} completes a short handle before it reaches WebFinger —
 * `kofi@acme` is looked up as `kofi@acme.rine.network` — and it answers with
 * the resolved UUID, never the handle it resolved. The substitution is
 * therefore invisible at every call site by construction: the caller asked
 * about one agent and may be told about another, with nothing anywhere saying
 * so. The completion itself is a good default and stays. What changes is that
 * it stops being silent.
 *
 * Four surfaces say it and they cannot say it the same way: the CLI writes a
 * line to stderr, `@rine-network/mcp` returns objects so the notice rides as a
 * key, and `rine-mastra`/`rine-eve` return plain strings so it rides as a line.
 * What they must not do is each hold the bytes. This function is the bytes; a
 * surface decides only where to put them.
 *
 * 🔴 This composer **returns** and never prints. A library that writes to a
 * stream has taken a decision belonging to whoever is holding the terminal —
 * which is also why {@link resolveRecipient} and the two SDKs get no notice at
 * all: they report the completion through their RETURN VALUE, carrying the
 * caller's spelling beside the resolved handle so a consumer can compare the
 * two without being told.
 */

/**
 * The notice for one spelling, or nothing when the lookup used it verbatim.
 *
 * 🔴 {@link normalizeHandle} is CALLED, never restated. It owns the rule for
 * what a short handle completes to, and a second copy of that rule here could
 * disagree with the lookup and announce a substitution that never happened.
 *
 * The sentence quotes the caller's own spelling and the completion of it, and
 * nothing else — no third handle, which is the placeholder ban. A value
 * with no `@` comes back from `normalizeHandle` untouched and is silent here,
 * which is correct: `resolveToUuid` refuses that arm outright rather than
 * completing it, so there is no substitution to report. A UUID is silent for
 * the same reason.
 */
export function handleCompletionNote(spelling: string): string | undefined {
	const completed = normalizeHandle(spelling);
	if (completed === spelling) return undefined;
	return `Note: '${spelling}' was completed to '${completed}' before the lookup.`;
}

/**
 * The notice for a batch, in the order the caller named them, or nothing.
 *
 * A plural verb — a founding roster, a batch invite — is where a silent
 * completion does the most damage, because one wrong agent among twenty seats
 * itself unnoticed. Every completed spelling gets its own sentence: a caller
 * who named five agents and mistyped two needs to see which two.
 *
 * Duplicate sentences are dropped rather than repeated. The same spelling
 * twice in one roster is one substitution, and saying it twice reads as two
 * different agents having been rewritten.
 */
export function handleCompletionNotes(
	spellings: readonly string[],
): string | undefined {
	const seen = new Set<string>();
	for (const spelling of spellings) {
		const note = handleCompletionNote(spelling);
		if (note !== undefined) seen.add(note);
	}
	if (seen.size === 0) return undefined;
	return [...seen].join(" ");
}
