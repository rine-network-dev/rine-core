/**
 * The stale-leaf sweep against the REAL native core: which groups it moves, and
 * what it reports when it cannot start.
 *
 * Only the network is faked, by the rotation scene's stand-in server (see
 * `mls-seat-sweep-scene.ts`).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-escrow-key.js", async () =>
	(await import("./mls-escrow-harness.js")).escrowKeyModule(),
);

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<typeof import("../src/crypto/mls-api.js")>(
		"../src/crypto/mls-api.js",
	);
	return {
		...actual,
		uploadKeyPackages: vi.fn(async (_c: unknown, _a: unknown, p: string[]) => ({ stored: p.length })),
		claimKeyPackages: vi.fn(),
		claimKeyPackagesBatch: vi.fn(),
		mlsInit: vi.fn(),
		mlsCommit: vi.fn(),
		mlsAck: vi.fn(),
		mlsNack: vi.fn(),
		fetchHandshakes: vi.fn(),
		fetchWelcomes: vi.fn(),
		fetchGroupInfo: vi.fn(),
	};
});

import { selfUpdateStaleLeaves } from "../src/mls-seat-sweep.js";
import { hold } from "./mls-hold-scene.js";
import { setUpSweepScene, sweptActor } from "./mls-seat-sweep-scene.js";
import { A, G1, G2, groupOf, scene, tearDownRotationScene } from "./mls-rotation-scene.js";

beforeEach(setUpSweepScene);
afterEach(tearDownRotationScene);

describe("selfUpdateStaleLeaves", () => {
	it("test_sweep_when_the_published_key_is_not_the_one_on_disk_then_nothing_is_attempted", async () => {
		const actor = sweptActor(7);
		scene.omitted.add(A);

		const seats = await selfUpdateStaleLeaves(actor);

		expect(seats).toEqual([{ group_id: null, status: "failed", reason: "key_not_current" }]);
		expect(hold.posts).toEqual([]);
	});

	it("test_sweep_when_a_group_is_listed_but_this_host_holds_no_state_for_it_then_it_is_skipped", async () => {
		const actor = sweptActor(8);

		const seats = await selfUpdateStaleLeaves(actor);

		expect(seats.map((seat) => seat.group_id)).toEqual([G1]);
		expect(() => groupOf(actor.configDir, A, G2)).toThrow();
	});

	it("test_sweep_when_the_group_list_cannot_be_read_then_it_is_deferred_as_unreachable", async () => {
		const actor = sweptActor(9);
		const reads = (actor.client as unknown as {
		get: (path: string, ...rest: unknown[]) => Promise<unknown>;
	});
		const real = reads.get;
		reads.get = async (path: string, ...rest: unknown[]) => {
			if (path === "/groups") throw new Error("list down");
			return real(path, ...rest);
		};

		const seats = await selfUpdateStaleLeaves(actor);

		expect(seats).toHaveLength(1);
		expect(seats[0]).toMatchObject({ status: "deferred", reason: "unreachable" });
	});
});
