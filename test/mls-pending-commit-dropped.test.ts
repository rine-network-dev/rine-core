/**
 * Settling a pending self-update commit the server no longer holds, against the
 * REAL native core.
 *
 * The standing a holding handle's handshakes read answers decides the outcome:
 * `rolled_back` (the group quarantined or orphaned our commit), `superseded` (a
 * peer's commit took the pending epoch) and `absent` (the server never accepted
 * it) each drop the pending commit and save the handle at the epoch it was at.
 * A failed read keeps the commit, because a caller that cannot tell "gone" from
 * an outage would drop a commit the server may still be holding.
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

import { OwnCommitStanding } from "../src/crypto/mls-handshake-feed.js";
import { RineApiError } from "../src/errors.js";
import { addMlsGroupMember, syncMlsGroup } from "../src/mls-ops.js";
import { clientFor, hold } from "./mls-hold-scene.js";
import { holdPendingUpdate, rotatedDir, setUpHeldGroup } from "./mls-pending-commit-scene.js";
import { A, B, C, G1, R, groupOf, rotate, scene, tearDownRotationScene, treeIds } from "./mls-rotation-scene.js";

beforeEach(setUpHeldGroup);
afterEach(tearDownRotationScene);

describe("settling a pending self-update commit the server no longer holds", () => {
	it("test_settle_when_the_group_rolled_the_commit_back_then_it_is_cleared_and_saved", async () => {
		rotate(A, scene.d1);
		const dir = rotatedDir(4);
		const n = holdPendingUpdate(dir);
		hold.standings.set(G1, OwnCommitStanding.RolledBack);

		const result = await syncMlsGroup(dir, A, G1, clientFor(A), undefined);

		expect(result.pendingCommit?.outcome).toBe("rolled_back");
		const reloaded = groupOf(dir, A, G1);
		expect(reloaded.epoch()).toBe(n);
		expect(reloaded.pendingCommitEpoch()).toBeNull();
	});

	it("test_settle_when_the_server_never_accepted_the_commit_then_it_is_cleared_as_not_posted", async () => {
		rotate(A, scene.d1);
		const dir = rotatedDir(5);
		const n = holdPendingUpdate(dir);

		const result = await syncMlsGroup(dir, A, G1, clientFor(A), undefined);

		expect(result.pendingCommit?.outcome).toBe("not_posted");
		const reloaded = groupOf(dir, A, G1);
		expect(reloaded.epoch()).toBe(n);
		expect(reloaded.pendingCommitEpoch()).toBeNull();
	});

	it("test_settle_when_a_peer_commit_holds_the_pending_epoch_then_lost_and_the_peer_commit_applied", async () => {
		rotate(A, scene.d1);
		const dir = rotatedDir(6);
		const n = holdPendingUpdate(dir);
		scene.rosters.set(G1, [R, A, B, C]);
		await addMlsGroupMember(scene.dr, R, G1, C, scene.client);

		const result = await syncMlsGroup(dir, A, G1, clientFor(A), undefined);

		expect(result.pendingCommit?.outcome).toBe("lost");
		const reloaded = groupOf(dir, A, G1);
		expect(reloaded.epoch()).toBe(n + 1);
		expect(reloaded.pendingCommitEpoch()).toBeNull();
		expect(treeIds(dir, A, G1)).toEqual(treeIds(scene.dr, R, G1));
	});

	it("test_settle_when_the_read_fails_then_sync_throws_and_the_commit_stays_pending", async () => {
		rotate(A, scene.d1);
		const dir = rotatedDir(7);
		const n = holdPendingUpdate(dir);
		const client = clientFor(A) as unknown as { get: () => Promise<never> };
		client.get = async () => {
			throw new RineApiError(503, "down");
		};

		await expect(syncMlsGroup(dir, A, G1, client as never, undefined)).rejects.toThrow("down");

		expect(groupOf(dir, A, G1).pendingCommitEpoch()).toBe(n + 1);
	});
});
