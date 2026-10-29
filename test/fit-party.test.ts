import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { fitFromTo, fitGroupSender, fitHandle } from "../src/fit-party.js";

type Pair = [string, string];
interface Vectors {
	handle: { name: string; label: string; cells: number; want: string }[];
	group: { name: string; group: string; sender: string; room: number; want: Pair }[];
	pair: { name: string; from: string; to: string; room: number; want: Pair }[];
}
const vectors = JSON.parse(
	readFileSync(new URL("./fixtures/fit-party-vectors.json", import.meta.url), "utf8"),
) as Vectors;

describe("fit-party shared vectors", () => {
	for (const v of vectors.handle) {
		it(`test_fitHandle_${v.name}`, () => {
			expect(fitHandle(v.label, v.cells)).toBe(v.want);
		});
	}
	for (const v of vectors.group) {
		it(`test_fitGroupSender_${v.name}`, () => {
			expect(fitGroupSender(v.group, v.sender, v.room)).toEqual(v.want);
		});
	}
	for (const v of vectors.pair) {
		it(`test_fitFromTo_${v.name}`, () => {
			expect(fitFromTo(v.from, v.to, v.room)).toEqual(v.want);
		});
	}
});

describe("fitHandle with the ASCII ellipsis", () => {
	it("test_fitHandle_asciiEllipsis_nameBeforeDomainAndMarksTheCut", () => {
		expect(fitHandle("salesteam-europe@fjord21735", 20, "...")).toBe("salesteam-...@fjo...");
	});
	it("test_fitHandle_asciiEllipsis_narrowestFormKeepsTheAt", () => {
		expect(fitHandle("salesteam-europe@fjord21735", 7, "...")).toBe("...@...");
		expect(fitHandle("salesteam-europe@fjord21735", 2, "...")).toBe(".@");
	});
});
