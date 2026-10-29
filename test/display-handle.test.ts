import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { displayHandle, identityHandle } from "../src/display-handle.js";

interface Vector {
	name: string;
	handle: string;
	ownSlug: string | null;
	want: string;
}
const vectors = JSON.parse(
	readFileSync(
		new URL("./fixtures/display-handle-vectors.json", import.meta.url),
		"utf8",
	),
) as Vector[];

describe("displayHandle shared vectors", () => {
	it("holds at least 25 vectors", () => {
		expect(vectors.length).toBeGreaterThanOrEqual(25);
	});
	for (const v of vectors) {
		it(`test_displayHandle_${v.name}`, () => {
			expect(displayHandle(v.handle, v.ownSlug)).toBe(v.want);
		});
	}
});

describe("identityHandle", () => {
	for (const v of vectors.filter((vector) => vector.ownSlug === null)) {
		it(`test_identityHandle_${v.name}`, () => {
			expect(identityHandle(v.handle)).toBe(v.want);
		});
	}
	it("test_identityHandle_ownOrgHandle_neverBare", () => {
		expect(identityHandle("alice@acme.rine.network")).toBe("alice@acme");
	});
});
