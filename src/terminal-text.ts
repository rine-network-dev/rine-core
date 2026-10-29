/** Terminal-safe text: strips everything a terminal would act on or a reader could not see. */

export type Scrubbed = { text: string; hiddenChars: number };
export type Block = {
	text: string;
	hiddenChars: number;
	truncatedChars: number;
};

/** Longest input a scrub looks at; the rest is counted as truncated. */
export const MAX_SCRUBBED_CHARS = 16384;

// A control string runs to its terminator, or to the end of the input when it has none, so an unterminated
// sequence never leaves its payload on screen. The 8-bit introducers are handled like their ESC forms.
const OSC = /(?:\x1b\]|\u009d)[\s\S]*?(?:\x07|\x1b\\|\u009c|$)/g;
const OTHER_STRING =
	/(?:\x1b[PX^_]|[\u0090\u0098\u009e\u009f])[\s\S]*?(?:\x1b\\|\u009c|$)/g;
const CSI = /(?:\x1b\[|\u009b)[0-?]*[ -/]*[@-~]?/g;
const LONE_ESC = /\x1b/g;

const INVISIBLE =
	/[\u0000-\u0008\u000B-\u001F\u007F-\u009F\p{Cf}\p{Default_Ignorable_Code_Point}]/gu;

const codePoints = (s: string): number => Array.from(s).length;

/** Removes control sequences and invisible characters, counting every removed code point as hidden. */
export function scrub(s: string, isOneLine: boolean): Scrubbed {
	const before = codePoints(s);
	const deleted = s
		.replace(OSC, "")
		.replace(OTHER_STRING, "")
		.replace(CSI, "")
		.replace(LONE_ESC, "")
		.replace(INVISIBLE, "");
	const hiddenChars = before - codePoints(deleted);
	const newlined = deleted.replace(/\t/g, " ").replace(/[\u2028\u2029]/g, "\n");
	const text = isOneLine
		? newlined.replace(/\n/g, " ").replace(/\s+/g, " ").trim()
		: newlined.replace(/\n{3,}/g, "\n\n");
	return { text, hiddenChars };
}

/** A scrubbed multi-line block, cut to `maxChars` code points; `truncatedChars` counts everything cut. */
export function safeBlock(s: string, maxChars: number): Block {
	const chars = Array.from(s);
	const dropped = Math.max(0, chars.length - MAX_SCRUBBED_CHARS);
	const scrubbed = scrub(
		dropped ? chars.slice(0, MAX_SCRUBBED_CHARS).join("") : s,
		false,
	);
	const kept = Array.from(scrubbed.text);
	if (kept.length <= maxChars) return { ...scrubbed, truncatedChars: dropped };
	return {
		text: kept.slice(0, maxChars).join(""),
		hiddenChars: scrubbed.hiddenChars,
		truncatedChars: kept.length - maxChars + dropped,
	};
}
