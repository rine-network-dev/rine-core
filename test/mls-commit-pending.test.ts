/**
 * A commit refused because this agent's own key update is still pending says so
 * by name, against the REAL native core.
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
import { loadAgentKeys } from "../src/crypto/keys.js";
import { allowedFor } from "../src/mls-allowed.js";
import {
	MlsCommitPendingError,
	commitPendingMessage,
	whenCommitPending,
} from "../src/mls-commit-pending.js";
import { addMlsGroupMember } from "../src/mls-ops.js";
import { clientFor, installHoldServer } from "./mls-hold-scene.js";
import {
	A,
	B,
	C,
	G1,
	R,
	found,
	groupOf,
	joinGroup,
	proc,
	rotate,
	scene,
	setUpRotationScene,
	tearDownRotationScene,
} from "./mls-rotation-scene.js";

beforeEach(async () => {
	setUpRotationScene();
	installHoldServer();
	await found(scene.dr, R, G1, [A, B]);
	await joinGroup(scene.d1, A, G1);
	await joinGroup(scene.d1, B, G1);
});
afterEach(tearDownRotationScene);

describe("whenCommitPending", () => {
	it("test_whenCommitPending_when_a_member_is_added_during_a_pending_update_then_the_refusal_is_named", async () => {
		rotate(A, scene.d1);
		const dir = proc(scene.d1, 1);
		const old = scene.world.agents.get(A)!.find((g) => g.gen === 0)!;
		allowedFor(dir, A).insert(ascii(A), old.derived.mlsEd25519.publicKey, 0);
		const group = groupOf(dir, A, G1);
		group.commitUpdate(loadAgentKeys(dir, A).mls.privateKey);
		group.save();
		scene.rosters.set(G1, [R, A, B, C]);

		const failure = await addMlsGroupMember(dir, A, G1, C, clientFor(A)).catch((e: unknown) => e);

		expect(failure).toBeInstanceOf(MlsCommitPendingError);
		expect((failure as Error).message).toBe(commitPendingMessage(G1));
	});

	it("test_whenCommitPending_when_the_builder_fails_otherwise_then_the_failure_passes_through", async () => {
		const boom = new Error("boom");

		await expect(
			whenCommitPending(G1, () => {
				throw boom;
			}),
		).rejects.toBe(boom);
	});

	it("test_whenCommitPending_when_the_builder_succeeds_then_its_value_is_returned", async () => {
		await expect(whenCommitPending(G1, async () => 7)).resolves.toBe(7);
	});
});
