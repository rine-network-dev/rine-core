import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { safeBlock, scrub, MAX_SCRUBBED_CHARS } from "../src/terminal-text.js";

interface ScrubVector {
	name: string;
	input: string;
	oneLine: boolean;
	text: string;
	hiddenChars: number;
}
interface BlockVector {
	name: string;
	input: string;
	maxChars: number;
	text: string;
	hiddenChars: number;
	truncatedChars: number;
}
const vectors = JSON.parse(
	readFileSync(
		new URL("./fixtures/terminal-text-vectors.json", import.meta.url),
		"utf8",
	),
) as { scrub: ScrubVector[]; safeBlock: BlockVector[] };

describe("terminal-text shared vectors", () => {
	for (const v of vectors.scrub) {
		it(`test_scrub_${v.name}`, () => {
			expect(scrub(v.input, v.oneLine)).toEqual({
				text: v.text,
				hiddenChars: v.hiddenChars,
			});
		});
	}
	for (const v of vectors.safeBlock) {
		it(`test_safeBlock_${v.name}`, () => {
			expect(safeBlock(v.input, v.maxChars)).toEqual({
				text: v.text,
				hiddenChars: v.hiddenChars,
				truncatedChars: v.truncatedChars,
			});
		});
	}
});

describe("terminal-text properties", () => {
	it("test_scrub_everyVectorOutput_isIdempotent", () => {
		for (const v of vectors.scrub) {
			const once = scrub(v.input, v.oneLine);
			expect(scrub(once.text, v.oneLine)).toEqual({
				text: once.text,
				hiddenChars: 0,
			});
		}
	});

	it("test_safeBlock_inputPastClamp_countsDroppedAsTruncated", () => {
		const result = safeBlock(
			"a".repeat(MAX_SCRUBBED_CHARS + 10),
			MAX_SCRUBBED_CHARS,
		);
		expect(result.text).toHaveLength(MAX_SCRUBBED_CHARS);
		expect(result.truncatedChars).toBe(10);
	});
});
