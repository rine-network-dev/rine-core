/**
 * How many terminal columns text occupies, by grapheme cluster.
 *
 * A cluster is as wide as its widest code point: wide (East Asian Wide/Fullwidth, emoji presentation) is 2, a
 * combining mark, format or control character is 0, anything else 1. East Asian Ambiguous is narrow. There is no
 * ZWJ joining: the terminal scrub removes ZWJ before text reaches here, so an emoji sequence is its component emoji.
 * The wide table is generated (`scripts/gen-terminal-width.mjs`); segmentation is `Intl.Segmenter`, so cluster
 * boundaries follow the running Node's ICU.
 */
import { WIDE_RANGES } from "./terminal-width-table.js";

const SEGMENTER = new Intl.Segmenter(undefined, { granularity: "grapheme" });
const ZERO_WIDTH = /^[\p{M}\p{Cf}\p{Cc}]$/u;

function isWide(cp: number): boolean {
	let lo = 0;
	let hi = WIDE_RANGES.length - 1;
	while (lo <= hi) {
		const mid = (lo + hi) >> 1;
		const [first, last] = WIDE_RANGES[mid] as readonly [number, number];
		if (cp < first) hi = mid - 1;
		else if (cp > last) lo = mid + 1;
		else return true;
	}
	return false;
}

/** The grapheme clusters of `text`, in order. Run it on clipped text only: it is linear in the input. */
export function graphemes(text: string): string[] {
	return Array.from(SEGMENTER.segment(text), (s) => s.segment);
}

/** Columns one grapheme cluster occupies: 0, 1 or 2. */
export function clusterWidth(cluster: string): 0 | 1 | 2 {
	let width: 0 | 1 | 2 = 0;
	for (const ch of cluster) {
		const cp = ch.codePointAt(0) as number;
		if (isWide(cp)) return 2;
		if (!ZERO_WIDTH.test(ch)) width = 1;
	}
	return width;
}

/** Columns `text` occupies. */
export function displayWidth(text: string): number {
	let total = 0;
	for (const cluster of graphemes(text)) total += clusterWidth(cluster);
	return total;
}

/** The longest prefix of `text`, whole clusters only, that fits in `columns`; a wide cluster that would straddle the edge is dropped. */
export function clipToWidth(text: string, columns: number): string {
	let used = 0;
	let out = "";
	for (const cluster of graphemes(text)) {
		used += clusterWidth(cluster);
		if (used > columns) break;
		out += cluster;
	}
	return out;
}

/** `text` cut to at most `columns` columns, the cut marked with `ellipsis`; text that fits is returned as is. */
export function clipWithEllipsis(text: string, columns: number, ellipsis: string): string {
	if (displayWidth(text) <= columns) return text;
	const mark = displayWidth(ellipsis);
	if (columns <= mark) return clipToWidth(ellipsis, columns);
	return clipToWidth(text, columns - mark) + ellipsis;
}
