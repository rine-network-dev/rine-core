/**
 * How a refusal is put together, pinned as rules rather than as strings.
 *
 * The shipped sentences are pinned where they are written — `group-ref.test.ts`
 * and `actor.test.ts` hold those, unmodified, and they are the proof that
 * routing them through this composer moved nothing. What is pinned HERE is the
 * part no single refusal's test can see: the joins.
 *
 * Three of the four rules exist because a stack got them wrong in production.
 * The double full stop is `rine-eve/src/errors.ts`, which had to grow
 * `detail.replace(/\.+$/, "")` to stop printing `id.. Try …`. The suppression
 * is Hermes' measured over-suggestion: a refusal that names the verb whose
 * answer it already printed makes a model parrot the hint instead of acting.
 * The spelling-as-a-parameter rule is the one that keeps a refusal from quoting
 * the local part a fallback matched on rather than what the caller wrote.
 */

import { describe, expect, it } from "vitest";
import { ambiguousActorRefusal } from "../src/actor.js";
import { composeGroupRefusal } from "../src/recipient-refusal.js";

const ROWS = "  #ops@acme.rine.network\n  #labels@acme.rine.network";

describe("composeGroupRefusal", () => {
	it("hands the lead the caller's spelling and nothing else", () => {
		const seen: string[] = [];
		composeGroupRefusal({
			lead: (said) => {
				seen.push(said);
				return `No group named '${said}'`;
			},
			spelling: "#Heron Count@acme",
		});
		expect(seen).toEqual(["#Heron Count@acme"]);
	});

	it("puts exactly one full stop between two sentences", () => {
		const composed = composeGroupRefusal({
			lead: () => "No group named 'ops'.",
			spelling: "ops",
			nextStep: "Run `rine group list` to see yours.",
		});
		expect(composed).toBe(
			"No group named 'ops'. Run `rine group list` to see yours.",
		);
	});

	it("adds the stop a lead that ends without one is missing", () => {
		const composed = composeGroupRefusal({
			lead: () => "No group named 'ops'",
			spelling: "ops",
			nextStep: "Run `rine group list` to see yours.",
		});
		expect(composed).toBe(
			"No group named 'ops'. Run `rine group list` to see yours.",
		);
	});

	it("leaves the stop the spelling itself contributed where it is", () => {
		// 🔴 The seam is normalised; the sentence's tail is not. That tail is the
		// caller's own spelling — `rine group info "ops."` quotes `ops.` back —
		// so stripping it answers a different sentence than the one that ships.
		const composed = composeGroupRefusal({
			lead: (said) => `Group not found: ${said}.`,
			spelling: "ops.",
			nextStep: "Run `rine group list` to see yours.",
		});
		expect(composed).toBe(
			"Group not found: ops.. Run `rine group list` to see yours.",
		);
	});

	it("leaves a lead alone when there is nothing to join it to", () => {
		expect(
			composeGroupRefusal({ lead: () => "No group named 'ops'.", spelling: "ops" }),
		).toBe("No group named 'ops'.");
	});

	describe("rule 3 — a refusal that lists candidates does not also name the verb that would list them", () => {
		it("drops the next step when the rows were appended", () => {
			const composed = composeGroupRefusal({
				lead: () => "No group named 'ops'",
				spelling: "ops",
				candidates: {
					rows: ROWS,
					rosterLead: "Name one of these groups:",
					whenEmpty: "This org is in no groups yet.",
				},
				nextStep: "Run `rine group list` to see yours.",
			});
			expect(composed).toBe(
				"No group named 'ops'. Name one of these groups:\n" + ROWS,
			);
			expect(composed).not.toContain("rine group list");
		});

		it("keeps the next step when there was nothing to list", () => {
			const composed = composeGroupRefusal({
				lead: () => "No group named 'ops'",
				spelling: "ops",
				candidates: {
					rows: "",
					rosterLead: "Name one of these groups:",
					whenEmpty: "This org is in no groups yet.",
				},
				nextStep: "Run `rine group create` to make one.",
			});
			expect(composed).toBe(
				"No group named 'ops'. This org is in no groups yet. Run `rine group create` to make one.",
			);
		});

		it("keeps the line that says how to CHOOSE, which names no verb", () => {
			const composed = composeGroupRefusal({
				lead: () => "More than one agent is named 'kofi'",
				spelling: "kofi",
				candidates: {
					rows: ROWS,
					rosterLead: "Say which one is acting:",
					whenEmpty: "No active agents in this org.",
					after: "A name is not unique in an org — name it by handle or UUID.",
				},
			});
			expect(composed).toBe(
				"More than one agent is named 'kofi'. Say which one is acting:\n" +
					ROWS +
					"\nA name is not unique in an org — name it by handle or UUID.",
			);
		});
	});

	it("lets a refusal whose whole text is its roster carry no lead", () => {
		const composed = composeGroupRefusal({
			lead: () => "",
			spelling: "",
			candidates: {
				rows: ROWS,
				rosterLead: "This org has more than one agent. Say which one is acting:",
				whenEmpty: "No active agents in this org.",
			},
		});
		expect(composed.startsWith("This org has")).toBe(true);
		expect(composed).not.toContain("\n\n");
		expect(composed.startsWith(".")).toBe(false);
	});

	it("says only the empty reason when there is neither a roster nor a next step", () => {
		expect(
			composeGroupRefusal({
				lead: () => "",
				spelling: "",
				candidates: {
					rows: "",
					rosterLead: "Say which one is acting:",
					whenEmpty: "No active agents in this org.",
				},
			}),
		).toBe("No active agents in this org.");
	});

	it("prints the rows as they came when the refusal declares no empty arm", () => {
		// A caller that guarantees a roster has no sentence for the case where
		// there is none, and the composer must not invent one for it: `whenEmpty`
		// absent means the rows block is printed exactly as handed over.
		expect(
			composeGroupRefusal({
				lead: (said) => `More than one agent is named '${said}'`,
				spelling: "ops",
				candidates: {
					rows: "",
					rosterLead: "Say which one is acting:",
					after: "A name is not unique in an org — name it by handle or UUID.",
				},
			}),
		).toBe(
			"More than one agent is named 'ops'. Say which one is acting:\n" +
				"\nA name is not unique in an org — name it by handle or UUID.",
		);
	});
});

/**
 * The one arm of a published refusal that no test pinned, and therefore moved.
 *
 * `ambiguousActorRefusal` is unreachable with an empty roster through this
 * monorepo — `resolve-agent.ts` guards it behind `matches.length > 1` — but
 * `index.ts` re-exports it, so it is `@rine-network/core`'s output and the
 * consolidation's safety property covers it. It is pinned here rather than in
 * `actor.test.ts` because the byte is a property of the COMPOSER's empty-arm
 * rule; the reachable arms stay pinned where they are written, untouched.
 */
describe("ambiguousActorRefusal, with a roster our own callers cannot give it", () => {
	it("is byte-identical to what f4ccb034 shipped for an empty match list", () => {
		expect(ambiguousActorRefusal([], "ops")).toBe(
			"More than one agent is named 'ops'. Say which one is acting:\n" +
				"\nA name is not unique in an org — name it by handle or UUID.",
		);
	});
});
