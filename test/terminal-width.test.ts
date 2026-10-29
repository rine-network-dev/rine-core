import { describe, expect, it } from "vitest";
import { clipToWidth, clusterWidth, displayWidth, graphemes } from "../src/terminal-width.js";

describe("terminal width", () => {
	it("counts ASCII as one column each", () => {
		expect(displayWidth("hello")).toBe(5);
		expect(displayWidth("")).toBe(0);
	});

	it("counts CJK, fullwidth and emoji presentation as two", () => {
		expect(displayWidth("漢字")).toBe(4);
		expect(displayWidth("ＡＢ")).toBe(4);
		expect(clusterWidth("\u{1F600}")).toBe(2);
		expect(clusterWidth("\u{1F1E9}\u{1F1EA}")).toBe(2);
	});

	it("counts East Asian Ambiguous as narrow", () => {
		expect(displayWidth("±°·α")).toBe(4);
	});

	it("gives combining marks no width of their own", () => {
		expect(displayWidth("é")).toBe(1);
		expect(graphemes("éx")).toEqual(["é", "x"]);
		expect(displayWidth("́")).toBe(0);
	});

	it("takes the widest code point of a cluster, not the sum", () => {
		expect(clusterWidth("\u{1F44D}\u{1F3FD}")).toBe(2);
	});

	it("measures a flag by its cluster, not by its two code points", () => {
		const flags = "\u{1F1E9}\u{1F1EA}\u{1F1EB}\u{1F1F7}";
		expect(graphemes(flags)).toHaveLength(2);
		expect(displayWidth(flags)).toBe(4);
		expect(displayWidth(`a${flags}`)).toBe(5);
		expect(clipToWidth(flags, 3)).toBe("\u{1F1E9}\u{1F1EA}");
	});

	it("clips at a cluster boundary and never splits a wide cell", () => {
		expect(clipToWidth("abcdef", 3)).toBe("abc");
		expect(clipToWidth("a漢b", 2)).toBe("a");
		expect(clipToWidth("a漢b", 3)).toBe("a漢");
		expect(clipToWidth("éé", 1)).toBe("é");
		expect(clipToWidth("abc", 0)).toBe("");
	});
});
