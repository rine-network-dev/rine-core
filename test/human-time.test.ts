import { readFileSync } from "node:fs";
import { afterAll, describe, expect, it } from "vitest";
import { humanTime } from "../src/human-time.js";

interface Vector {
	name: string;
	iso: string;
	nowMs: number;
	tz: string;
	want: string;
}
const vectors = JSON.parse(
	readFileSync(
		new URL("./fixtures/human-time-vectors.json", import.meta.url),
		"utf8",
	),
) as Vector[];

describe("humanTime shared vectors", () => {
	const zone = process.env.TZ;
	afterAll(() => {
		if (zone === undefined) delete process.env.TZ;
		else process.env.TZ = zone;
	});
	it("holds at least 25 vectors", () => {
		expect(vectors.length).toBeGreaterThanOrEqual(25);
	});
	for (const v of vectors) {
		it(`test_humanTime_${v.name}`, () => {
			process.env.TZ = v.tz;
			expect(humanTime(v.iso, v.nowMs)).toBe(v.want);
			expect([...v.want].length).toBeLessThanOrEqual(9);
		});
	}
});
