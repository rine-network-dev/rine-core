import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ESCROW_MAX_PAGES, ESCROW_MAX_ROWS } from "../src/org-reader/client.js";
import { toBase64Url } from "../src/crypto/keys.js";
import { parseSenderKeyDistribution } from "../src/crypto/sk-distribution.js";
import { MAX_GENERATIONS } from "../src/org-reader/direct.js";
import { MAX_BODY_BYTES } from "../src/org-reader/fetch-budget.js";
import { divergences as recorded, recordedCases } from "./org-reader-recorded.js";

const SENDER_KEY_ID = "11111111-1111-4111-8111-111111111111";

const BOUNDS: Record<string, number> = { MAX_GENERATIONS, ESCROW_MAX_PAGES, ESCROW_MAX_ROWS, MAX_BODY_BYTES };

describe("hostile divergences from the Python reader", () => {
	it("records_every_ruled_divergence_with_its_ruling_and_reason", () => {
		expect(recorded.length).toBeGreaterThan(0);
		for (const entry of recorded) {
			expect(entry.decision, entry.id).toMatch(/^(malformed-input|resource-bound|not-built)$/);
			expect(entry.python, entry.id).not.toBe("");
			expect(entry.typescript, entry.id).not.toBe("");
			expect(entry.reason, entry.id).not.toBe("");
		}
		expect(new Set(recorded.map((e) => e.id)).size).toBe(recorded.length);
	});

	it("records_the_float_literal_message_index_divergence_the_sender_key_parser_has", () => {
		const payload = JSON.parse(
			`{"chain_key":"${toBase64Url(new Uint8Array(32))}","sender_key_id":"${SENDER_KEY_ID}","message_index":5.0}`,
		) as Record<string, unknown>;
		const state = parseSenderKeyDistribution(payload, SENDER_KEY_ID, SENDER_KEY_ID);
		expect(state?.messageIndex).toBe(5);
		expect(recorded.map((e) => e.id)).toContain("float-literal-message-index");
	});

	it("records_each_resource_bound_at_the_value_the_reader_enforces", () => {
		const bounded = recorded.flatMap((e) => (e.bound ? [e.bound] : []));
		expect(bounded.map((b) => b.name).sort()).toEqual(Object.keys(BOUNDS).sort());
		for (const bound of bounded) expect(bound.value, bound.name).toBe(BOUNDS[bound.name]);
	});

	it("ties_every_divergence_to_recorded_cases_or_to_the_unit_test_that_pins_it", () => {
		const hostile = new Set(recordedCases("hostile").map((c) => c.name));
		for (const entry of recorded) {
			const cases = entry.cases ?? [];
			expect(cases.length > 0 || entry.pinnedBy !== undefined, entry.id).toBe(true);
			for (const name of cases) expect(hostile.has(name), `${entry.id}: ${name}`).toBe(true);
			if (entry.pinnedBy === undefined) continue;
			const { file, test, because } = entry.pinnedBy;
			const path = join(import.meta.dirname, file);
			expect(existsSync(path), `${entry.id}: ${file}`).toBe(true);
			expect(readFileSync(path, "utf8"), `${entry.id}: ${test}`).toContain(test);
			expect(because, entry.id).not.toBe("");
		}
	});
});
