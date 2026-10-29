import { describe, expect, it } from "vitest";
import * as core from "../src/index.js";

describe("core barrel", () => {
	it.each([
		"OrgReader",
		"ReadGapReason",
		"ReadKey",
		"ReaderClient",
		"gapToJson",
		"messageToJson",
		"scrub",
		"safeBlock",
		"clipToWidth",
		"clusterWidth",
		"displayWidth",
		"graphemes",
	])("exports %s for the terminal view", (name) => {
		expect(typeof (core as Record<string, unknown>)[name]).toMatch(/function|object/);
	});

	it("keeps test-only helpers off the public surface", () => {
		expect(core).not.toHaveProperty("pageToJson");
	});
});
