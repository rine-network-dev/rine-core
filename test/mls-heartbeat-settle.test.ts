/**
 * The order of a heartbeat: a rotation is settled before the key-package top-up.
 *
 * A rotation replaces the whole published pool, and a top-up run first would
 * count the private halves of the pool being replaced. The pieces are stubbed
 * because the order is the whole subject; what each one does is covered in
 * its own suite.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const calls: string[] = [];

vi.mock("../src/mls-seat-sweep.js", () => ({
	settleRotation: vi.fn(async () => {
		calls.push("settle");
		return { key_packages: "republished", group_seats: [] };
	}),
}));
vi.mock("../src/mls-keypackages.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../src/mls-keypackages.js")>()),
	ensureMlsKeyPackages: vi.fn(async () => {
		calls.push("top-up");
	}),
}));
vi.mock("../src/mls-escrow-sweep.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../src/mls-escrow-sweep.js")>()),
	sweepPendingEscrow: vi.fn(async () => {
		calls.push("escrow");
	}),
}));

import { mlsHeartbeat, resetMlsHeartbeatGate } from "../src/mls-heartbeat.js";

const actor = { configDir: "/nowhere", agentId: "a1a1a1a1-0000-4000-8000-000000000001", client: {} as never };

beforeEach(() => {
	calls.length = 0;
	resetMlsHeartbeatGate();
});

describe("mlsHeartbeat", () => {
	it("test_heartbeat_when_it_runs_then_the_rotation_is_settled_before_the_top_up", async () => {
		await mlsHeartbeat(actor, "forced");

		expect(calls).toEqual(["settle", "top-up", "escrow"]);
	});

	it("test_heartbeat_when_the_floor_is_not_lifted_then_neither_the_settlement_nor_the_top_up_runs", async () => {
		await mlsHeartbeat(actor, "forced");
		calls.length = 0;

		await mlsHeartbeat(actor, "gated");

		expect(calls).toEqual([]);
	});
});
