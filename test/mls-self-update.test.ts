/**
 * `selfUpdateGroup` against the REAL native core: an agent that rotated its key
 * moves its own leaf in a group, and every outcome is reported rather than thrown.
 *
 * Only the network (`crypto/mls-api.js`) is faked, by the rotation scene's
 * stand-in server. Device `d1` holds the rotated agent A and its sibling B;
 * device `dr` holds the founder R.
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
import { mlsToBase64 } from "../src/crypto/mls-api.js";
import { openMlsClient } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import { allowedFor } from "../src/mls-allowed.js";
import { syncMlsGroup } from "../src/mls-ops.js";
import { selfUpdateGroup } from "../src/mls-self-update.js";
import { clientFor, hold } from "./mls-hold-scene.js";
import { leafKey, rotatedActor, setUpHeldGroup } from "./mls-pending-commit-scene.js";
import {
	A,
	G1,
	G2,
	R,
	found,
	joinGroup,
	groupOf,
	proc,
	rotate,
	scene,
	tearDownRotationScene,
} from "./mls-rotation-scene.js";

beforeEach(setUpHeldGroup);
afterEach(tearDownRotationScene);

describe("selfUpdateGroup", () => {
	it("test_selfUpdateGroup_when_the_leaf_carries_an_older_key_then_it_moves_and_the_group_follows", async () => {
		const actor = rotatedActor(1);
		const before = groupOf(actor.configDir, A, G1).epoch();

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ group_id: G1, status: "updated", epoch: before + 1 });
		const mine = groupOf(actor.configDir, A, G1);
		expect(mine.epoch()).toBe(before + 1);
		expect(mine.ownLeafSignatureKey()).toEqual(leafKey(A, 1));
		const remote = await syncMlsGroup(scene.dr, R, G1, clientFor(R), undefined);
		expect(remote.epoch).toBe(before + 1);
		expect(groupOf(scene.dr, R, G1).epoch()).toBe(before + 1);
	});

	it("test_syncMlsGroup_when_the_leaf_is_stale_then_the_implicit_catch_up_posts_nothing", async () => {
		const actor = rotatedActor(12);

		await syncMlsGroup(actor.configDir, A, G1, actor.client, undefined);

		expect(hold.posts).toEqual([]);
		expect(groupOf(actor.configDir, A, G1).ownLeafSignatureKey()).toEqual(leafKey(A, 0));
	});

	it("test_selfUpdateGroup_when_the_leaf_already_carries_the_current_key_then_nothing_is_posted", async () => {
		const actor = { configDir: proc(scene.d1, 2), agentId: A, client: clientFor(A) };

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat.status).toBe("current");
		expect(hold.posts).toEqual([]);
	});

	it("test_selfUpdateGroup_when_posting_then_the_pending_commit_is_already_on_disk", async () => {
		const actor = rotatedActor(3);
		let onDisk: number | null | undefined;
		hold.onPost = () => {
			onDisk = groupOf(actor.configDir, A, G1).pendingCommitEpoch();
		};
		const before = groupOf(actor.configDir, A, G1).epoch();

		await selfUpdateGroup(actor, G1);

		expect(onDisk).toBe(before + 1);
	});

	it("test_selfUpdateGroup_when_one_epoch_race_is_lost_then_it_retries_once_and_lands", async () => {
		const actor = rotatedActor(7);
		hold.postErrors.push(new RineApiError(409, "race", undefined, "epoch_conflict"));

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat.status).toBe("updated");
		expect(hold.posts).toHaveLength(1);
	});

	it("test_selfUpdateGroup_when_two_epoch_races_are_lost_then_it_stops_and_clears_the_pending_commit", async () => {
		const actor = rotatedActor(8);
		hold.postErrors.push(
			new RineApiError(409, "race", undefined, "epoch_conflict"),
			new RineApiError(409, "race", undefined, "epoch_conflict"),
		);

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "deferred", reason: "epoch_race" });
		expect(groupOf(actor.configDir, A, G1).pendingCommitEpoch()).toBeNull();
	});

	it("test_selfUpdateGroup_when_every_post_meets_an_epoch_race_then_it_posts_twice_and_defers", async () => {
		const actor = rotatedActor(13);
		hold.postErrors.push(
			new RineApiError(409, "race", undefined, "epoch_conflict"),
			new RineApiError(409, "race", undefined, "epoch_conflict"),
			new RineApiError(409, "race", undefined, "epoch_conflict"),
		);

		const seat = await selfUpdateGroup(actor, G1);

		// Two attempts took two of the three queued races; nothing landed.
		expect(hold.postErrors).toHaveLength(1);
		expect(hold.posts).toHaveLength(0);
		expect(seat).toMatchObject({ status: "deferred", reason: "epoch_race" });
	});

	it("test_selfUpdateGroup_when_the_server_refuses_with_a_4xx_then_the_pending_commit_is_dropped", async () => {
		const actor = rotatedActor(9);
		hold.postErrors.push(new RineApiError(403, "refused", undefined, "forbidden"));

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "deferred", reason: "unreachable" });
		expect(groupOf(actor.configDir, A, G1).pendingCommitEpoch()).toBeNull();
	});

	it("test_selfUpdateGroup_when_the_post_fails_in_transit_then_the_pending_commit_is_kept", async () => {
		const actor = rotatedActor(10);
		hold.postErrors.push(new Error("socket hang up"));
		const before = groupOf(actor.configDir, A, G1).epoch();

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "deferred", reason: "unreachable", detail: "socket hang up" });
		expect(groupOf(actor.configDir, A, G1).pendingCommitEpoch()).toBe(before + 1);
	});

	it("test_selfUpdateGroup_when_the_leaf_key_is_not_a_key_this_agent_can_sign_for_then_it_is_unhealable", async () => {
		// A joins G2 from a key package minted under generation 0 after its disk keys
		// moved to generation 1: the leaf carries the old key while the handle signs
		// with the new one.
		scene.keyPackages.set(A, [mlsToBase64(openMlsClient(scene.d1, A).generateKeyPackage())]);
		await found(scene.dr, R, G2, [A]);
		rotate(A, scene.d1);
		const configDir = proc(scene.d1, 11);
		allowedFor(configDir, A).insert(ascii(A), leafKey(A, 0), 0);
		await joinGroup(configDir, A, G2);

		const seat = await selfUpdateGroup({ configDir, agentId: A, client: clientFor(A) }, G2);

		expect(seat).toMatchObject({ group_id: G2, status: "failed", reason: "seat_unhealable" });
		expect(groupOf(configDir, A, G2).pendingCommitEpoch()).toBeNull();
	});
});
