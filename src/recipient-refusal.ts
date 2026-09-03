/**
 * How a refusal is put together, in the one place this stack does it.
 *
 * Every refusal a resolution raises is the same three parts: a sentence naming
 * what went wrong, the candidates it could have meant, and — when there are
 * none to name — the step that would find one. What kept drifting was not the
 * words but the JOINS between them: a lead whose own full stop was doubled
 * against the next sentence (`rine-eve/src/errors.ts`, which had to grow
 * `detail.replace(/\.+$/, "")` to match Python's `detail.rstrip(".")`), and a
 * next step printed underneath a list that already answered it.
 *
 * 🔴 **Rule 3 is the whole reason this is a function and not a template.** A
 * refusal that lists candidates does NOT also name the verb that would list
 * them. Hermes measured that failure and wrote it down
 * (`rine-hermes/src/hermes_rine/_client.py`): naming a verb whose answer is
 * already in the refusal made models parrot the hint back instead of acting on
 * it. The suppression has to live where the list is appended, or every caller
 * re-decides it and half of them get it wrong.
 *
 * 🔴 Twin of the Python stack's composer (`rine-sdk/src/rine/_recipient.py`).
 * The two stacks share no module, so a joining rule that lives in one place
 * here and nowhere there is the divergence this module exists to end.
 */

/**
 * A refusal's opening sentence, written as a function of the one string it may
 * quote.
 *
 * 🔴 A function rather than a finished string, and that is the guarantee rather
 * than a style: the ONLY value the lead is handed is the caller's own spelling,
 * so a lead cannot quote the local part a fallback matched on or the normalised
 * form a tier compared. The spelling reaches the sentence, or the sentence does
 * not have it.
 *
 * It ends as a sentence, with or without writing the full stop itself:
 * {@link composeGroupRefusal} adds one at the seam if the lead did not, and
 * never takes away one the lead — or the spelling it quotes — did. A lead that
 * ends on a COLON is introducing the list itself and belongs in
 * {@link RefusalCandidates.rosterLead}.
 */
export type RefusalLead = (spelling: string) => string;

/**
 * The candidates a refusal names, already rendered by the roster its own
 * namespace prints.
 *
 * Rendered rather than typed, because the two rosters are different rows over
 * different wire types — `formatGroupList` (`group-ref.ts`) and
 * `formatActorList` (`actor.ts`) — and both already own the cap and the
 * overflow row. Handing this module the rows keeps `MAX_LISTED_GROUPS` in the
 * one place that applies it.
 */
export interface RefusalCandidates {
	/**
	 * The rows, one per line. Empty exactly when there is nothing to name —
	 * both renderers answer `""` for an empty list, which is what selects
	 * {@link whenEmpty}.
	 */
	readonly rows: string;
	/**
	 * The sentence that introduces the rows.
	 *
	 * Empty where the lead already introduced them, which is the shape of a
	 * refusal whose whole first sentence ends on a colon.
	 */
	readonly rosterLead: string;
	/**
	 * What the refusal says instead of the rows when there are none.
	 *
	 * 🔴 **Absent means the refusal HAS no empty arm**, and that is a claim about
	 * the caller rather than a formatting choice: `ambiguousActorRefusal` is
	 * reached only behind `matches.length > 1` (`resolve-agent.ts`), so it has
	 * never had a sentence for an empty roster and inventing one for it moved a
	 * shipped byte of `@rine-network/core`'s published output. Omitted, the rows
	 * block is printed as written — empty line and all — which is exactly what
	 * that arm shipped at `f4ccb034`.
	 */
	readonly whenEmpty?: string;
	/**
	 * A closing line under the rows: how to CHOOSE one of them.
	 *
	 * Not a next step — it names no verb that would fetch what is already on
	 * screen, so rule 3 does not reach it.
	 */
	readonly after?: string;
}

/** The parts every refusal this contract raises is composed from. */
export interface GroupRefusalParts {
	readonly lead: RefusalLead;
	/** Exactly what the caller passed in. */
	readonly spelling: string;
	/** The candidates, where this refusal has a roster to name. */
	readonly candidates?: RefusalCandidates;
	/**
	 * The verb that would find one, where the refusal has no roster.
	 *
	 * Dropped when a list was appended (rule 3).
	 */
	readonly nextStep?: string;
}

/**
 * Two sentences, joined with exactly one full stop between them.
 *
 * The `rine-eve` divergence, as a rule instead of as a patch: a lead that
 * carries its own stop must not print `id.. Try …`. Either half being empty
 * leaves the other unchanged, which is what lets a refusal whose whole text is
 * its roster carry no lead at all.
 *
 * 🔴 **The seam is normalised; the CONTENT never is.** A stop already at the
 * end of the opening is left where it is rather than stripped, because the
 * opening's tail is not the composer's to rewrite: `unknownGroupRefusal` quotes
 * the caller's own spelling there, so `rine group info "ops."` puts a period
 * into the sentence that the caller — not this module — wrote. Stripping it
 * moved a shipped byte (`Group not found: ops.. Name one of these groups:`
 * became `… ops. Name …`), which is the one thing this consolidation may not
 * do. The Python twin's `compose_group_refusal` reads the same way: terminate
 * what is not terminated, rewrite nothing that is.
 *
 * Exported for {@link module:group-ref}'s eviction pointer, which appends a
 * sentence to a refusal this module already composed. Exported rather than
 * copied for the reason the doubled stop existed in the first place: a second
 * implementation of this seam is a second place for it to diverge.
 *
 * @internal Cross-module seam, not a supported `@rine-network/core` API. It
 * reaches npm only because `index.ts` re-exports this module with `export *`.
 * Nothing outside this package should depend on it.
 *
 * ⚠️ Python holds no single twin for this one — the two stacks split the job
 * differently. `_terminated` (`rine-sdk/src/rine/_group_ref.py`) supplies the
 * stop and its callers compose inline. (The nearby `joinLines` DOES have a
 * one-to-one twin, `_join_lines`; do not conflate them — that one joins with a
 * newline, this one with a sentence stop.)
 */
export function joinSentences(opening: string, next: string): string {
	if (next === "") return opening;
	if (opening === "") return next;
	return opening.endsWith(".") ? `${opening} ${next}` : `${opening}. ${next}`;
}

/**
 * The refusal a caller reads, from its parts.
 *
 * In order:
 * 1. the lead, quoting the caller's spelling and nothing else;
 * 2. the candidates, if there are any, under the sentence that introduces them
 *    and above the line that says how to choose;
 * 3. otherwise the reason there are none, and the next step that would find
 *    one — 🔴 **never underneath a list**, which is rule 3;
 * 4. one full stop between any two sentences, never two.
 *
 * A refusal whose caller guarantees a roster declares no
 * {@link RefusalCandidates.whenEmpty}, and then step 3 is not reached at all:
 * the rows are printed as they came, because there is no second thing to say.
 */
export function composeGroupRefusal({
	lead,
	spelling,
	candidates,
	nextStep,
}: GroupRefusalParts): string {
	const opening = lead(spelling);
	if (candidates && (candidates.rows !== "" || candidates.whenEmpty === undefined)) {
		const sentence = joinSentences(opening, candidates.rosterLead);
		const lines = [sentence, candidates.rows];
		if (candidates.after !== undefined) lines.push(candidates.after);
		return lines.join("\n");
	}
	let composed = opening;
	if (candidates?.whenEmpty !== undefined) {
		composed = joinSentences(composed, candidates.whenEmpty);
	}
	if (nextStep !== undefined) composed = joinSentences(composed, nextStep);
	return composed;
}
