/**
 * The once-per-gap orphan reclamation. A reclamation is an O(N) commit per
 * orphan billed to every member, so the same gap never repeats it, but a later,
 * different gap in the same group is a new case.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-orphans.js", () => ({
	reclaimOrphanLeaves: vi.fn(async () => undefined),
}));

import { reclaimOnceForGap } from "../src/mls-escrow-leaves.js";
import { resetProcessGates } from "../src/process-gate.js";
import { reclaimOrphanLeaves } from "../src/mls-orphans.js";

const GROUP = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const actor = {
	configDir: "/cfg",
	agentId: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
	client: {} as never,
};

beforeEach(() => {
	resetProcessGates();
	vi.mocked(reclaimOrphanLeaves).mockReset();
	vi.mocked(reclaimOrphanLeaves).mockResolvedValue(undefined as never);
});

describe("reclaimOnceForGap", () => {
	it("test_reclaim_once_for_gap_when_asked_twice_for_the_same_gap_then_it_runs_once", async () => {
		expect(await reclaimOnceForGap(actor, GROUP, 5)).toBe(true);
		expect(await reclaimOnceForGap(actor, GROUP, 5)).toBe(false);
		expect(reclaimOrphanLeaves).toHaveBeenCalledTimes(1);
	});

	it("test_reclaim_once_for_gap_when_a_later_epoch_has_its_own_gap_then_it_runs_again", async () => {
		await reclaimOnceForGap(actor, GROUP, 5);

		expect(await reclaimOnceForGap(actor, GROUP, 9)).toBe(true);
		expect(reclaimOrphanLeaves).toHaveBeenCalledTimes(2);
	});

	it("test_reclaim_once_for_gap_when_the_reclamation_throws_then_it_is_not_repeated_for_that_gap", async () => {
		vi.mocked(reclaimOrphanLeaves).mockRejectedValue(new Error("boom"));

		expect(await reclaimOnceForGap(actor, GROUP, 5)).toBe(true);
		expect(await reclaimOnceForGap(actor, GROUP, 5)).toBe(false);
	});

	it("test_reclaim_once_for_gap_when_the_agent_differs_then_it_runs_for_each", async () => {
		await reclaimOnceForGap(actor, GROUP, 5);

		expect(await reclaimOnceForGap({ ...actor, agentId: "b2c3d4e5-f6a7-8901-bcde-f12345678901" }, GROUP, 5)).toBe(true);
	});
});
