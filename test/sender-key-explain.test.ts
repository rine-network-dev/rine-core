/**
 * The render policy, tested where it is written rather than only through the
 * six surfaces that spend it.
 *
 * Two halves, and they fail differently. `senderKeyExplanation` decides WHICH
 * rows the policy is for — its failure mode is a renderer that tiers a refusal
 * that has no remedy to offer, or misses the one that does. `senderKeyExplainer`
 * decides HOW MANY TIMES a render says it — its failure mode is a paragraph per
 * row, or state that outlives the render that opened it.
 *
 * Every surface's own suite covers its own render. None of them covered the
 * rule itself, so a change to the rule broke six suites at once or none of
 * them, depending on which way it broke.
 */

import { describe, expect, it } from "vitest";
import {
	senderKeyExplainer,
	senderKeyExplanation,
} from "../src/sender-key-explain.js";
import {
	SENDER_KEY_NOT_RECOVERED_PREVIEW,
	SENDER_KEY_UNAVAILABLE_CODE,
	SENDER_KEY_UNAVAILABLE_PREVIEW,
} from "../src/sender-key-words.js";

const SENTENCE = "the whole refusal, composed by whoever degraded the row";

describe("senderKeyExplanation (which rows the policy is for)", () => {
	it("returns the row's own sentence when the typed code says this cause", () => {
		expect(
			senderKeyExplanation({
				decrypt_error: SENTENCE,
				decrypt_error_code: SENDER_KEY_UNAVAILABLE_CODE,
			}),
		).toBe(SENTENCE);
	});

	it("returns null for a row that failed for any other reason", () => {
		// A signature refusal names no remedy, so it keeps the sentinel it has
		// always had and is not pooled into this render's "explained" state.
		expect(
			senderKeyExplanation({
				decrypt_error: "signature does not cover these bytes",
				decrypt_error_code: null,
			}),
		).toBeNull();
	});

	it("reads the code and never the words of the sentence", () => {
		// The whole reason the code exists: a row whose prose names the cause but
		// whose code does not is not this cause. If this ever passes the sentence
		// through, a wording change silently re-classifies rows.
		expect(
			senderKeyExplanation({
				decrypt_error: SENDER_KEY_UNAVAILABLE_PREVIEW,
				decrypt_error_code: "some_other_code",
			}),
		).toBeNull();
	});

	it("returns null for a coded row carrying no sentence", () => {
		// So a caller's `?? row.decrypt_error` fallback keeps what it already had
		// instead of tiering an empty string into the first row of a render.
		expect(
			senderKeyExplanation({
				decrypt_error: null,
				decrypt_error_code: SENDER_KEY_UNAVAILABLE_CODE,
			}),
		).toBeNull();
	});
});

describe("senderKeyExplainer (how many times a render says it)", () => {
	it("explains on the first row and marks every row after it", () => {
		const explain = senderKeyExplainer();

		const first = explain(SENTENCE);
		const second = explain(SENTENCE);
		const third = explain(SENTENCE);

		expect(first.line).toBe(SENTENCE);
		expect(second.line).toBe(SENDER_KEY_UNAVAILABLE_PREVIEW);
		expect(third.line).toBe(SENDER_KEY_UNAVAILABLE_PREVIEW);
	});

	it("offers the sentence as a notice on the first row only", () => {
		// `rine stream` renders one line per row and prints the sentence beside it
		// rather than inside it. A non-null notice on row 2 is that surface
		// printing the paragraph once per row.
		const explain = senderKeyExplainer();

		expect(explain(SENTENCE).notice).toBe(SENTENCE);
		expect(explain(SENTENCE).notice).toBeNull();
	});

	it("marks with the marker belonging to the sentence it was given", () => {
		// A render that never let the recovery run says so on its first row, so its
		// later rows must not assert the recovered verdict's remedy. The two
		// contradict each other, and the row an operator is least likely to read is
		// the one that would be right.
		const explain = senderKeyExplainer(SENDER_KEY_NOT_RECOVERED_PREVIEW);

		explain(SENTENCE);

		expect(explain(SENTENCE).line).toBe(SENDER_KEY_NOT_RECOVERED_PREVIEW);
	});

	it("gives each render its own state, so a second transcript explains again", () => {
		// The invariant a module-level flag breaks: the second `thread()` in a
		// long-lived process would explain nothing, and what a render printed would
		// depend on what ran before it.
		const first = senderKeyExplainer();
		first(SENTENCE);

		const second = senderKeyExplainer();

		expect(second(SENTENCE).line).toBe(SENTENCE);
	});
});
