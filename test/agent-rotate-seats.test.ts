/**
 * `rotateAgentWithSeats`: the key rotation first, then the settlement on this
 * host, and one report that carries both.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const calls: string[] = [];
const agent = { id: "a1a1a1a1-0000-4000-8000-000000000001", key_gen: 1 };

vi.mock("../src/agent-rotate.js", () => ({
	performKeyRotation: vi.fn(async () => {
		calls.push("rotate");
		return agent;
	}),
}));
vi.mock("../src/mls-seat-sweep.js", () => ({
	settleRotation: vi.fn(async () => {
		calls.push("settle");
		return {
			key_packages: "republished",
			group_seats: [{ group_id: "g", status: "updated", epoch: 3 }],
		};
	}),
}));

import { performKeyRotation } from "../src/agent-rotate.js";
import { rotateAgentWithSeats } from "../src/agent-rotate-seats.js";
import { settleRotation } from "../src/mls-seat-sweep.js";

const client = { get: vi.fn(), post: vi.fn() } as never;
const dirs = { configDir: "/cfg", ownerDir: "/owner" } as never;

beforeEach(() => {
	calls.length = 0;
	vi.clearAllMocks();
});

describe("rotateAgentWithSeats", () => {
	it("test_rotate_when_the_key_moves_then_the_settlement_runs_after_it_and_both_are_reported", async () => {
		const report = await rotateAgentWithSeats(client, dirs, agent.id);

		expect(calls).toEqual(["rotate", "settle"]);
		expect(report).toEqual({
			agent,
			key_packages: "republished",
			group_seats: [{ group_id: "g", status: "updated", epoch: 3 }],
		});
		expect(vi.mocked(settleRotation)).toHaveBeenCalledWith({
			configDir: "/cfg",
			agentId: agent.id,
			client,
		});
	});

	it("test_rotate_when_the_server_refuses_the_key_then_nothing_is_settled", async () => {
		vi.mocked(performKeyRotation).mockRejectedValueOnce(new Error("refused"));

		await expect(rotateAgentWithSeats(client, dirs, agent.id)).rejects.toThrow("refused");

		expect(vi.mocked(settleRotation)).not.toHaveBeenCalled();
	});
});
