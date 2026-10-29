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

import { OwnCommitStanding } from "../src/crypto/mls-handshake-feed.js";
import { selfUpdateGroup } from "../src/mls-self-update.js";
import { dropNewestCommit, hold } from "./mls-hold-scene.js";
import { rotatedActor, setUpHeldGroup } from "./mls-pending-commit-scene.js";
import { A, G1, groupOf, tearDownRotationScene } from "./mls-rotation-scene.js";

beforeEach(setUpHeldGroup);
afterEach(tearDownRotationScene);

describe("selfUpdateGroup while the server holds the commit", () => {
	it("test_selfUpdateGroup_when_the_server_holds_the_commit_then_it_is_deferred_and_not_applied", async () => {
		const actor = rotatedActor(4);
		hold.confirmed = false;
		const before = groupOf(actor.configDir, A, G1).epoch();

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "deferred", reason: "awaiting_ack", epoch: before + 1 });
		const mine = groupOf(actor.configDir, A, G1);
		expect(mine.epoch()).toBe(before);
		expect(mine.pendingCommitEpoch()).toBe(before + 1);
	});

	it("test_selfUpdateGroup_when_a_commit_from_an_earlier_call_is_still_held_then_nothing_new_is_posted", async () => {
		const actor = rotatedActor(5);
		hold.confirmed = false;
		const before = groupOf(actor.configDir, A, G1).epoch();
		await selfUpdateGroup(actor, G1);
		const posted = hold.posts.length;

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "deferred", reason: "awaiting_ack", epoch: before + 1 });
		expect(hold.posts).toHaveLength(posted);
		expect(hold.pendingReads.at(-1)).toEqual({ groupId: G1, pendingEpoch: before + 1 });
	});

	it("test_selfUpdateGroup_when_the_group_rolled_the_commit_back_then_it_is_cleared_and_reported", async () => {
		const actor = rotatedActor(6);
		hold.confirmed = false;
		await selfUpdateGroup(actor, G1);
		hold.standings.set(G1, OwnCommitStanding.RolledBack);
		dropNewestCommit(G1);
		const posted = hold.posts.length;

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "deferred", reason: "rolled_back" });
		expect(hold.posts).toHaveLength(posted);
		expect(groupOf(actor.configDir, A, G1).pendingCommitEpoch()).toBeNull();
	});

	it("test_selfUpdateGroup_when_a_peer_commit_superseded_the_held_one_then_deferred_epoch_race", async () => {
		const actor = rotatedActor(7);
		hold.confirmed = false;
		await selfUpdateGroup(actor, G1);
		hold.standings.set(G1, OwnCommitStanding.Superseded);
		const posted = hold.posts.length;

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "deferred", reason: "epoch_race" });
		expect(hold.posts).toHaveLength(posted);
		expect(groupOf(actor.configDir, A, G1).pendingCommitEpoch()).toBeNull();
	});

	it("test_selfUpdateGroup_when_the_server_never_saw_the_commit_then_unreachable_without_a_detail", async () => {
		const actor = rotatedActor(8);
		hold.postErrors.push(new Error("socket hang up"));
		await selfUpdateGroup(actor, G1);
		const posted = hold.posts.length;

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toEqual(expect.objectContaining({ status: "deferred", reason: "unreachable" }));
		expect(seat).not.toHaveProperty("detail");
		expect(hold.posts).toHaveLength(posted);
		expect(groupOf(actor.configDir, A, G1).pendingCommitEpoch()).toBeNull();
	});
});
