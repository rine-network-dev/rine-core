/**
 * How often a render says WHY a group message could not be opened: once.
 *
 * `sender-key-words.ts` decides what the refusal says; this decides how many
 * times a single render says it. They are split because they are answered by
 * different people — the sentence is a founder ruling about wording, this is a
 * founder ruling about volume — and because a module of constants that
 * also holds state is a module two callers can no longer read.
 *
 * The rule, which is the same on every surface and is chosen by how many
 * messages the CALLER asked for, never by which package renders:
 *
 *  - **One message asked for** (`rine message read`, an SDK `decrypt`, an MCP
 *    single-row open) — the full {@link senderKeyUnavailableMessage}. There is
 *    nothing to repeat.
 *  - **N messages rendered** (a thread, an inbox, a stream, a list) — the first
 *    row carrying this cause prints the full sentence, and every row after it
 *    in the same render prints {@link SENDER_KEY_UNAVAILABLE_PREVIEW}. An
 *    eight-row inbox of unopenable messages goes from ~4.8 KB to ~1.0 KB and
 *    the agent still learns the cause in-band, with no second call.
 *
 * 🔴 The state is per render and lives in the closure a renderer creates for
 * its own render — never in this module. A flag at module scope leaks across
 * calls, groups and agents: the second `thread()` in a process would explain
 * nothing, the output would depend on what ran before it, and no test could
 * pin either. Per-render scope also means a PAGED inbox explains once per
 * page, which is the intended reading.
 *
 * 🔴 Scoped to this cause alone. "Explain once" is not pooled with the other
 * ways a row renders `[unavailable]` — a row with no authenticated sender, a
 * legacy pre-self-seal blob, or a refused signature are different failures with
 * no remedy to offer, and they keep the sentinel they have always had.
 */

import {
	SENDER_KEY_UNAVAILABLE_CODE,
	SENDER_KEY_UNAVAILABLE_PREVIEW,
} from "./sender-key-words.js";

/**
 * The two fields a degrade writes on a row it could not open: the sentence, and
 * the typed code that says which cause wrote it.
 *
 * Declared structurally rather than against `DecryptedMessage` because the row
 * shape belongs to the SDKs and this package sits under both of them — and
 * because the connectors reach here holding three different row types that
 * agree on exactly these two fields.
 */
export interface SenderKeyRefusedRow {
	readonly decrypt_error?: string | null;
	readonly decrypt_error_code?: string | null;
}

/**
 * The sentence this row would explain if it is the first in its render to carry
 * the no-sender-key cause, or `null` for every other row.
 *
 * The predicate a renderer would otherwise hand-roll beside its call to
 * {@link senderKeyExplainer} — and it was hand-rolled identically at three
 * sites (the TS SDK's thread render, and the mastra and eve message renders)
 * before it lived here. 🔴 Classification is the typed code and never the words
 * of `decrypt_error`: the code exists precisely so a wording change cannot
 * silently stop a renderer recognising the cause.
 *
 * A row carrying the code but no sentence answers `null`, so a caller's
 * `?? row.decrypt_error` fallback keeps whatever it already rendered instead of
 * tiering an empty string.
 */
export function senderKeyExplanation(row: SenderKeyRefusedRow): string | null {
	if (row.decrypt_error_code !== SENDER_KEY_UNAVAILABLE_CODE) return null;
	return row.decrypt_error ?? null;
}

/** What one row of a render is told, once the explainer has decided. */
export interface SenderKeyExplained {
	/**
	 * What a row whose text is its only slot renders: the full sentence on the
	 * first row of this render carrying this cause, the bounded marker on every
	 * one after it.
	 */
	readonly line: string;
	/**
	 * The full sentence on that first row only, `null` on every row after.
	 *
	 * For a surface whose row is one line and cannot hold a paragraph — `rine
	 * stream` — which puts this beside the marked line as its own notice rather
	 * than squeezing it in. A surface that renders {@link line} has already said
	 * it and must not print this too.
	 */
	readonly notice: string | null;
}

/**
 * Ask how this row should say it, given what the render has already said.
 *
 * `explanation` is the full sentence the caller would otherwise have printed —
 * {@link senderKeyUnavailableMessage} composed for this row, or the one an SDK
 * already put on `decrypt_error`. It is passed in rather than composed here so
 * that the two stacks and the five connectors, which reach this failure with
 * different amounts of the error left in their hands, all get the same tiering
 * from the same code.
 */
export type SenderKeyExplainer = (explanation: string) => SenderKeyExplained;

/**
 * Open a render and get its explainer. Call once per render, then per row.
 *
 * A renderer that fans out over rows CONCURRENTLY must apply this in row order
 * after its decrypts settle, or which row carries the paragraph is decided by
 * whichever decrypt finished first — the rule says the first row, and a render
 * that cannot be predicted cannot be tested either.
 *
 * `marker` is what rows 2..N get, and a render passes the one belonging to the
 * sentence its first row prints: the default {@link SENDER_KEY_UNAVAILABLE_PREVIEW}
 * for the earned verdict, {@link SENDER_KEY_NOT_RECOVERED_PREVIEW} for a render
 * that never let the recovery run. 🔴 The tier text and its marker must come
 * from the same sentence — a render whose first row says "this is not a final
 * answer" and whose later rows assert the final answer's remedy contradicts
 * itself once per row, and the row that is right is the one an operator is least
 * likely to be looking at.
 */
export function senderKeyExplainer(
	marker: string = SENDER_KEY_UNAVAILABLE_PREVIEW,
): SenderKeyExplainer {
	let explained = false;
	return (explanation: string): SenderKeyExplained => {
		if (explained) {
			return { line: marker, notice: null };
		}
		explained = true;
		return { line: explanation, notice: explanation };
	};
}
