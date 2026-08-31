/**
 * The one sentence every TypeScript surface renders about how a join request is
 * decided, and the predicate that says what an invite to a group actually did.
 *
 * Both are pinned from the PACKAGE ROOT, never from the module that declares
 * them: the CLI, the MCP server, eve and mastra import `@rine-network/core`, so
 * a symbol that is not re-exported there is one they cannot reach — which is
 * exactly how `groups.sync()` shipped with its own result type unexported and
 * untypeable. The text is pinned character for character because its Python
 * twin is, and a rule that reads differently depending on which stack an
 * operator is holding is the defect this constant exists to end.
 */
import { describe, expect, it } from "vitest";

import { VOTE_ELECTORATE_RULE, inviteNominates } from "../src/index.js";

describe("VOTE_ELECTORATE_RULE", () => {
	it("is the founder-pinned sentence, character for character", () => {
		expect(VOTE_ELECTORATE_RULE).toBe(
			"A join request is decided by the members the group had when it was " +
				"filed, and only by those of them who are still in it: majority needs " +
				"more than half of them to approve, unanimity needs all of them, and " +
				"an agent who joined afterwards does not vote on it. Denials refuse " +
				"it on that same electorate — half of them under majority, a single " +
				"one under unanimity — so both bars fall as members leave.",
		);
	});

	it("states the denial bar as well as the approval one", () => {
		// The row on the wire carries a denial bar, so this sentence has to name
		// it too — a rule that states only the approval half leaves the prose and
		// the wire disagreeing about the same row. It let a surface report
		// `approvals_needed` beside a `denials` count whose weight nothing
		// explained, and the denial bar is the one that moves under a member's
		// feet, because it is measured against a shrinking electorate.
		expect(VOTE_ELECTORATE_RULE).toContain("Denials refuse it");
		expect(VOTE_ELECTORATE_RULE).toContain("both bars fall as members leave");
	});
});

describe("inviteNominates", () => {
	it("says an invite to a voting group nominates rather than seats", () => {
		expect(inviteNominates("majority")).toBe(true);
		expect(inviteNominates("unanimity")).toBe(true);
	});

	it("leaves closed and open alone — neither of them nominates", () => {
		expect(inviteNominates("closed")).toBe(false);
		expect(inviteNominates("open")).toBe(false);
	});

	it("treats a policy it does not recognise the way every client did before", () => {
		// The safe default is the old behaviour: an unminted Welcome is
		// recovered by the next resume, an unwanted one costs an O(N)
		// reclamation commit billed to every member.
		expect(inviteNominates("some_future_policy")).toBe(false);
		expect(inviteNominates(undefined)).toBe(false);
		expect(inviteNominates(null)).toBe(false);
	});
});
