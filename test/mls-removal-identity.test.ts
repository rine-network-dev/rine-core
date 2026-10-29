/**
 * Removing a member resolves its leaf from the agent id, against the REAL native
 * core.
 *
 * The credential identity of a leaf is the id of the agent that holds it, so a
 * rotation, a revoked agent and an agent on a revoked branch change nothing about
 * which leaf is theirs. Resolving the leaf from the key the server publishes made
 * all three delivery-filter removals: the leaf stayed in the tree and every epoch
 * secret it held stayed valid. A member no leaf names still gets the path-only
 * commit that declares the removal.
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

import { removeMlsGroupMember, syncMlsGroup } from "../src/mls-ops.js";
import {
	A,
	C,
	G1,
	R,
	found,
	joinGroup,
	proc,
	rotate,
	scene,
	setUpRotationScene,
	tearDownRotationScene,
	treeIds,
} from "./mls-rotation-scene.js";

beforeEach(async () => {
	setUpRotationScene();
	await found(scene.dr, R, G1, [A, C]);
	await joinGroup(scene.d1, A, G1);
	await joinGroup(scene.dc, C, G1);
});
afterEach(tearDownRotationScene);

describe("removeMlsGroupMember", () => {
	it("test_remove_when_the_batch_key_read_omits_the_member_then_its_leaf_is_taken_out", async () => {
		scene.omitted.add(A);

		const removal = await removeMlsGroupMember(proc(scene.dr, 1), R, G1, A, scene.client);

		expect(removal).toMatchObject({ epoch: 2, removedLeaf: true });
		expect(treeIds(proc(scene.dr, 1), R, G1)).toEqual([R, C]);
		const synced = await syncMlsGroup(scene.dc, C, G1, scene.client);
		expect(synced).toMatchObject({ epoch: 2, processed: 1 });
		expect(treeIds(scene.dc, C, G1)).toEqual([R, C]);
	});

	it("test_remove_when_the_member_rotated_its_key_then_its_old_leaf_is_taken_out_and_it_is_evicted", async () => {
		rotate(A, scene.d1);

		const removal = await removeMlsGroupMember(scene.dr, R, G1, A, scene.client);

		expect(removal).toMatchObject({ epoch: 2, removedLeaf: true });
		expect(treeIds(scene.dr, R, G1)).toEqual([R, C]);
		const evicted = await syncMlsGroup(proc(scene.d1, 1), A, G1, scene.client);
		expect(evicted).toMatchObject({ evicted: true });
	});

	it("test_remove_when_no_leaf_names_the_member_then_a_path_only_commit_declares_the_removal", async () => {
		await removeMlsGroupMember(scene.dr, R, G1, A, scene.client);
		const commitsBefore = scene.posted.get(G1)!.length;

		const again = await removeMlsGroupMember(scene.dr, R, G1, A, scene.client);

		expect(again).toMatchObject({ epoch: 3, removedLeaf: false });
		expect(scene.posted.get(G1)!.length).toBe(commitsBefore + 1);
		expect(treeIds(scene.dr, R, G1)).toEqual([R, C]);
	});
});
