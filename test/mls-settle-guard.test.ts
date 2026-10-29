/**
 * The settlement guard: a process-wide hold that keeps a heartbeat running
 * inside a key-rotation settlement from starting a second settlement.
 *
 * The guard is pure process state, so these cases drive it directly rather than
 * through a settlement: what matters is that the hold is visible for the whole
 * of `run`, that it is released on both exits, and that a nested call for an
 * agent already settling does not drop the outer hold.
 */
import { describe, expect, it } from "vitest";

import { isSettling, whileSettling } from "../src/mls-settle-guard.js";

const actor = { configDir: "/tmp/rine-settle", agentId: "a1b2c3d4-e5f6-7890-abcd-ef1234567890" };
const otherAgent = { configDir: actor.configDir, agentId: "b2c3d4e5-f6a7-8901-bcde-f12345678901" };
const otherDir = { configDir: "/tmp/rine-settle-other", agentId: actor.agentId };

describe("whileSettling", () => {
	it("test_isSettling_when_no_settlement_is_running_then_it_is_false", () => {
		expect(isSettling(actor)).toBe(false);
	});

	it("test_isSettling_when_run_is_in_flight_then_it_is_true", async () => {
		let during = false;
		await whileSettling(actor, async () => {
			during = isSettling(actor);
		});
		expect(during).toBe(true);
	});

	it("test_isSettling_when_run_resolves_then_the_hold_is_released", async () => {
		await whileSettling(actor, async () => {});
		expect(isSettling(actor)).toBe(false);
	});

	it("test_whileSettling_when_run_rejects_then_the_hold_is_released_and_the_rejection_propagates", async () => {
		const failure = new Error("settlement failed");
		await expect(
			whileSettling(actor, async () => {
				throw failure;
			}),
		).rejects.toBe(failure);
		expect(isSettling(actor)).toBe(false);
	});

	it("test_isSettling_when_a_nested_run_finishes_then_the_outer_hold_stands", async () => {
		await whileSettling(actor, async () => {
			await whileSettling(actor, async () => {});
			expect(isSettling(actor)).toBe(true);
		});
		expect(isSettling(actor)).toBe(false);
	});

	it("test_isSettling_when_another_agent_settles_then_this_agent_is_unaffected", async () => {
		await whileSettling(otherAgent, async () => {
			expect(isSettling(actor)).toBe(false);
		});
	});

	it("test_isSettling_when_another_config_dir_settles_then_this_agent_is_unaffected", async () => {
		await whileSettling(otherDir, async () => {
			expect(isSettling(actor)).toBe(false);
		});
	});
});
