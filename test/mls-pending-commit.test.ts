/**
 * Settling a pending self-update commit inside a sync, against the REAL native
 * core, when the server confirms it or still holds it.
 *
 * An agent that rotated its key moves its own leaf with a native self-update,
 * which leaves the commit pending on the handle. A holding handle's handshakes
 * read names the pending epoch, and the server answers where the commit stands:
 * `confirmed` applies it, `tentative` leaves it alone and stops the sync, because
 * a peer's commit at or past the pending epoch may be built on ours.
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

import { fetchGroupInfo, fetchHandshakes, mlsAck, mlsNack } from "../src/crypto/mls-api.js";
import { OwnCommitStanding } from "../src/crypto/mls-handshake-feed.js";
import { addMlsGroupMember, syncMlsGroup } from "../src/mls-ops.js";
import { selfUpdateGroup } from "../src/mls-self-update.js";
import { clientFor, hold } from "./mls-hold-scene.js";
import { holdPendingUpdate, leafKey, rotatedDir, setUpHeldGroup } from "./mls-pending-commit-scene.js";
import { A, B, C, G1, R, groupOf, proc, rotate, scene, tearDownRotationScene, treeIds } from "./mls-rotation-scene.js";

beforeEach(setUpHeldGroup);
afterEach(tearDownRotationScene);

describe("settling a pending self-update commit the server confirms or holds", () => {
	it("test_settle_when_nothing_pending_then_the_request_names_no_pending_epoch_and_nothing_is_settled", async () => {
		const result = await syncMlsGroup(proc(scene.d1, 1), A, G1, clientFor(A), undefined);

		expect(result.pendingCommit).toBeUndefined();
		expect(vi.mocked(fetchHandshakes)).toHaveBeenCalled();
		expect(hold.pendingReads).toEqual([{ groupId: G1, pendingEpoch: undefined }]);
	});

	it("test_settle_when_a_commit_is_pending_then_the_request_names_the_pending_epoch", async () => {
		rotate(A, scene.d1);
		const dir = rotatedDir(9);
		const n = holdPendingUpdate(dir);

		await syncMlsGroup(dir, A, G1, clientFor(A), undefined);

		expect(hold.pendingReads).toEqual([{ groupId: G1, pendingEpoch: n + 1 }]);
	});

	it("test_settle_when_the_server_confirmed_the_commit_then_it_is_applied_and_no_resync_is_forced", async () => {
		rotate(A, scene.d1);
		const dir = rotatedDir(2);
		const n = holdPendingUpdate(dir);
		hold.standings.set(G1, OwnCommitStanding.Confirmed);

		const result = await syncMlsGroup(dir, A, G1, clientFor(A), undefined);

		expect(result.pendingCommit?.outcome).toBe("applied");
		expect(result.epoch).toBe(n + 1);
		expect(fetchGroupInfo).not.toHaveBeenCalled();
		const reloaded = groupOf(dir, A, G1);
		expect(reloaded.epoch()).toBe(n + 1);
		expect(reloaded.pendingCommitEpoch()).toBeNull();
		expect(reloaded.ownLeafSignatureKey()).toEqual(leafKey(A, 1));
	});

	it("test_settle_when_confirmed_and_a_peer_commit_follows_then_ours_is_applied_and_the_peer_commit_after_it", async () => {
		rotate(A, scene.d1);
		const dir = rotatedDir(3);
		const actor = { configDir: dir, agentId: A, client: clientFor(A) };
		hold.confirmed = false;
		await selfUpdateGroup(actor, G1);
		const n = groupOf(dir, A, G1).epoch();
		await syncMlsGroup(scene.dr, R, G1, clientFor(R), undefined);
		scene.rosters.set(G1, [R, A, B, C]);
		await addMlsGroupMember(scene.dr, R, G1, C, scene.client);
		hold.standings.set(G1, OwnCommitStanding.Confirmed);

		const result = await syncMlsGroup(dir, A, G1, clientFor(A), undefined);

		expect(result.pendingCommit?.outcome).toBe("applied");
		expect(result.processed).toBe(1);
		expect(result.epoch).toBe(n + 2);
		expect(treeIds(dir, A, G1)).toEqual(treeIds(scene.dr, R, G1));
	});

	it("test_settle_when_still_tentative_then_held_and_nothing_changes", async () => {
		rotate(A, scene.d1);
		const dir = rotatedDir(4);
		const n = holdPendingUpdate(dir);
		hold.standings.set(G1, OwnCommitStanding.Tentative);

		const result = await syncMlsGroup(dir, A, G1, clientFor(A), undefined);

		expect(result.pendingCommit?.outcome).toBe("held");
		expect(result.processed).toBe(0);
		expect(mlsAck).not.toHaveBeenCalled();
		expect(mlsNack).not.toHaveBeenCalled();
		const reloaded = groupOf(dir, A, G1);
		expect(reloaded.epoch()).toBe(n);
		expect(reloaded.pendingCommitEpoch()).toBe(n + 1);
	});

	it("test_settle_when_held_then_a_later_handshake_in_the_feed_is_neither_applied_nor_nacked", async () => {
		rotate(A, scene.d1);
		const dir = rotatedDir(5);
		const n = holdPendingUpdate(dir);
		hold.standings.set(G1, OwnCommitStanding.Tentative);
		hold.extraHandshakes.push({ epoch: n + 2, blob: "AAAA" });

		const result = await syncMlsGroup(dir, A, G1, clientFor(A), undefined);

		expect(result.pendingCommit?.outcome).toBe("held");
		expect(result.processed).toBe(0);
		expect(mlsNack).not.toHaveBeenCalled();
		expect(groupOf(dir, A, G1).pendingCommitEpoch()).toBe(n + 1);
	});

	it("test_settle_when_the_response_lacks_the_standing_then_sync_throws_and_the_commit_stays_pending", async () => {
		rotate(A, scene.d1);
		const dir = rotatedDir(6);
		const n = holdPendingUpdate(dir);
		hold.omitStanding = true;

		await expect(syncMlsGroup(dir, A, G1, clientFor(A), undefined)).rejects.toThrow(
			"did not say where the pending commit stands",
		);

		expect(groupOf(dir, A, G1).pendingCommitEpoch()).toBe(n + 1);
	});
});
