/**
 * Third-party text a surface places inline in a larger string (a wake prompt, a
 * transcript) rather than in its own row field.
 *
 * The text sits inside a per-message random delimiter, and any copy of a rine
 * notice inside it is replaced, so a sender cannot paste the sentence that
 * grants authority into the body that is being read as data. A copy still
 * matches when Unicode format characters (category Cf: zero-width space and
 * joiners, soft hyphen, word joiner) are hidden anywhere inside it, or when its
 * final period is left off. The match ignores the case of ASCII letters and the
 * width and kind of whitespace; the whitespace class is written out, the case
 * folding is ASCII-only and the format characters are the Unicode category, so
 * the Python twin matches the very same characters.
 */

import { randomBytes } from "node:crypto";
import {
	OPERATOR_CONTENT_NOTICE,
	OPERATOR_HISTORY_NOTICE,
	UNTRUSTED_CONTENT_NOTICE,
} from "./control-frames.js";

/** What replaces a neutralised notice. */
export const NEUTRALISED_NOTICE = "[a rine notice was removed from this text]";

const FORMAT = "\\p{Cf}";
const SPACE_CHARS =
	" \\t\\n\\r\\f\\v\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
/** A gap between two words: whitespace, or a format character standing in for it, in any number. */
const WORD_GAP = `[${SPACE_CHARS}${FORMAT}]+`;
const HIDDEN = `[${FORMAT}]*`;

/** One character as a pattern: an ASCII letter in both cases, anything else as itself. */
function charPattern(char: string): string {
	if (/[A-Za-z]/.test(char))
		return `[${char.toLowerCase()}${char.toUpperCase()}]`;
	return char.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function wordPattern(word: string): string {
	return [...word].map(charPattern).join(HIDDEN);
}

/** The notice as a pattern whose last period, when it ends in one, may be missing. */
function patternFor(notice: string): RegExp {
	const bare = notice.endsWith(".") ? notice.slice(0, -1) : notice;
	const body = bare.split(" ").map(wordPattern).join(WORD_GAP);
	const period = bare === notice ? "" : `${HIDDEN}\\.?`;
	return new RegExp(`${body}${period}`, "gu");
}

const NOTICE_PATTERNS: readonly RegExp[] = [
	UNTRUSTED_CONTENT_NOTICE,
	OPERATOR_CONTENT_NOTICE,
	OPERATOR_HISTORY_NOTICE,
].map(patternFor);

/** `text` with every copy of a rine notice replaced by {@link NEUTRALISED_NOTICE}. */
export function neutraliseNotices(text: string): string {
	return NOTICE_PATTERNS.reduce(
		(out, pattern) => out.replace(pattern, NEUTRALISED_NOTICE),
		text,
	);
}

/** A fresh delimiter token: 128 random bits, so a sender cannot write the closing line in advance. */
export function randomDelimiter(): string {
	return `rine-${randomBytes(16).toString("hex")}`;
}

/**
 * `text` neutralised and fenced between a begin and an end line naming
 * `delimiter`. A copy of the delimiter inside the text is removed first, so the
 * fence cannot be closed from within.
 */
export function wrapThirdPartyText(text: string, delimiter: string): string {
	const inner = neutraliseNotices(text).split(delimiter).join("");
	return `BEGIN ${delimiter}\n${inner}\nEND ${delimiter}`;
}
