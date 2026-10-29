/**
 * A seat that stays deferred must not make every heartbeat re-sweep every group.
 *
 * The background sweep backs off after a sweep that left a seat deferred, and an
 * explicit settlement (a rotation, a `group sync`) always runs.
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

import { ascii } from "../src/crypto/bytes.js";
import { RineApiError } from "../src/errors.js";
import { allowedFor } from "../src/mls-allowed.js";
import { settleRotation } from "../src/mls-seat-sweep.js";
import { resetProcessGates } from "../src/process-gate.js";
// The settlement re-seats through the slot mls-self-update.js fills when it loads.
import "../src/mls-self-update.js";
import { clientFor, hold, installHoldServer } from "./mls-hold-scene.js";
import {
	A,
	B,
	G1,
	R,
	found,
	joinGroup,
	proc,
	rotate,
	scene,
	setUpRotationScene,
	tearDownRotationScene,
} from "./mls-rotation-scene.js";

const MINUTE_MS = 60_000;

/** The two lost races that make one group's sweep end deferred and leave nothing pending. */
const lostRaces = () => [
	new RineApiError(409, "race", undefined, "epoch_conflict"),
	new RineApiError(409, "race", undefined, "epoch_conflict"),
];

/** A's actor after a rotation, plus a counter of the group-list reads the sweep makes. */
function rotatedActor(n: number) {
	rotate(A, scene.d1);
	const configDir = proc(scene.d1, n);
	const old = scene.world.agents.get(A)!.find((g) => g.gen === 0)!.derived.mlsEd25519.publicKey;
	allowedFor(configDir, A).insert(ascii(A), old, 0);
	const base = clientFor(A) as unknown as {
		get: (path: string, ...rest: unknown[]) => Promise<unknown>;
	};
	const listReads = { count: 0 };
	const client = {
		...base,
		get: async (path: string, ...rest: unknown[]) => {
			if (path !== "/groups") return base.get(path, ...rest);
			listReads.count += 1;
			return { items: [{ id: G1, mls_group_id: G1, member_agent_ids: [A, B, R] }] };
		},
	} as never;
	return { actor: { configDir, agentId: A, client }, listReads };
}

beforeEach(async () => {
	setUpRotationScene();
	installHoldServer();
	resetProcessGates();
	await found(scene.dr, R, G1, [A, B]);
	await joinGroup(scene.d1, A, G1);
	await joinGroup(scene.d1, B, G1);
	vi.useFakeTimers({ toFake: ["Date"] });
});
afterEach(() => {
	vi.useRealTimers();
	tearDownRotationScene();
});

describe("the background seat sweep", () => {
	it("test_settle_when_a_background_sweep_left_a_seat_deferred_then_the_next_one_waits_out_the_backoff", async () => {
		const { actor, listReads } = rotatedActor(1);
		hold.postErrors.push(...lostRaces());
		await settleRotation(actor, { background: true });
		const reads = listReads.count;

		const again = await settleRotation(actor, { background: true });

		expect(again.group_seats).toEqual([]);
		expect(listReads.count).toBe(reads);
	});

	it("test_settle_when_the_backoff_has_elapsed_then_a_background_sweep_runs_and_settles", async () => {
		const { actor } = rotatedActor(2);
		hold.postErrors.push(...lostRaces());
		await settleRotation(actor, { background: true });
		vi.setSystemTime(Date.now() + 2 * MINUTE_MS);

		const settled = await settleRotation(actor, { background: true });

		expect(settled.group_seats).toMatchObject([{ group_id: G1, status: "updated" }]);
	});

	it("test_settle_when_the_sweep_is_explicit_then_it_ignores_the_backoff", async () => {
		const { actor } = rotatedActor(3);
		hold.postErrors.push(...lostRaces());
		await settleRotation(actor, { background: true });

		const settled = await settleRotation(actor);

		expect(settled.group_seats).toMatchObject([{ group_id: G1, status: "updated" }]);
	});

	it("test_settle_when_the_backoff_keeps_failing_then_the_wait_doubles", async () => {
		const { actor, listReads } = rotatedActor(4);
		hold.postErrors.push(...lostRaces(), ...lostRaces());
		await settleRotation(actor, { background: true });
		vi.setSystemTime(Date.now() + MINUTE_MS + 1);
		await settleRotation(actor, { background: true });
		const reads = listReads.count;
		vi.setSystemTime(Date.now() + MINUTE_MS + 1);

		await settleRotation(actor, { background: true });

		expect(listReads.count).toBe(reads);
	});
});
