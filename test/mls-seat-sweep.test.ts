/**
 * Settling a key rotation against the REAL native core: republish the key
 * packages, move every seat this host holds, and remember how far it got.
 *
 * Only the network is faked, by the rotation scene's stand-in server. Device
 * `d1` holds the rotated agent A and its sibling B and sits in group G1; A is
 * also in G2, for which `d1` holds no state.
 */
import * as fs from "node:fs";
import { join } from "node:path";
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

import { claimKeyPackages, claimKeyPackagesBatch, uploadKeyPackages } from "../src/crypto/mls-api.js";
import { OwnCommitStanding } from "../src/crypto/mls-handshake-feed.js";
import { RineApiError } from "../src/errors.js";
import { readRotationMarker, writeRotationMarker } from "../src/mls-rotation-marker.js";
import { settleRotation } from "../src/mls-seat-sweep.js";
import { hold } from "./mls-hold-scene.js";
import { reads, setUpSweepScene, sweepClient, sweptActor } from "./mls-seat-sweep-scene.js";
import { A, G1, proc, scene, tearDownRotationScene } from "./mls-rotation-scene.js";

const raceError = () => new RineApiError(409, "race", undefined, "epoch_conflict");

beforeEach(setUpSweepScene);
afterEach(tearDownRotationScene);

describe("settleRotation", () => {
	it("test_settle_when_the_host_holds_the_state_then_it_republishes_and_moves_the_seat", async () => {
		const actor = sweptActor(1);

		const settled = await settleRotation(actor);

		expect(settled.key_packages).toBe("republished");
		expect(settled.group_seats).toMatchObject([{ group_id: G1, status: "updated" }]);
		expect(vi.mocked(uploadKeyPackages)).toHaveBeenCalled();
		expect(readRotationMarker(actor.configDir, A)).toEqual({ key_packages: 1, seats: 1 });
	});

	it("test_settle_when_the_marker_is_current_then_it_reports_current_and_asks_nothing", async () => {
		const actor = sweptActor(2);
		writeRotationMarker(actor.configDir, A, { key_packages: 1, seats: 1 });

		const settled = await settleRotation(actor);

		expect(settled).toEqual({ key_packages: "current", group_seats: [] });
		expect(vi.mocked(uploadKeyPackages)).not.toHaveBeenCalled();
		expect(hold.posts).toEqual([]);
		expect(reads).toEqual([]);
	});

	it("test_settle_when_the_agent_never_rotated_then_nothing_is_done", async () => {
		const configDir = proc(scene.d1, 3);

		const settled = await settleRotation({ configDir, agentId: A, client: sweepClient() });

		expect(settled.group_seats).toEqual([]);
		expect(vi.mocked(uploadKeyPackages)).not.toHaveBeenCalled();
		expect(hold.posts).toEqual([]);
	});

	it("test_settle_when_the_host_holds_no_mls_store_then_it_is_not_held_and_the_marker_is_untouched", async () => {
		const bare = join(scene.root, "bare");
		fs.mkdirSync(bare);
		scene.world.save(bare, scene.world.addAgent({ id: A, gen: 1 }));

		const settled = await settleRotation({ configDir: bare, agentId: A, client: sweepClient() });

		expect(settled).toEqual({ key_packages: "not_held", group_seats: [] });
		expect(readRotationMarker(bare, A)).toEqual({ key_packages: 0, seats: 0 });
		expect(vi.mocked(uploadKeyPackages)).not.toHaveBeenCalled();
	});

	it.each([
		["epoch_race", () => hold.postErrors.push(raceError(), raceError()), () => undefined],
		[
			"awaiting_ack",
			() => {
				hold.confirmed = false;
			},
			() => hold.standings.set(G1, OwnCommitStanding.Confirmed),
		],
		["unreachable", () => hold.postErrors.push(new Error("socket hang up")), () => undefined],
	])("test_settle_when_a_seat_is_deferred_for_%s_then_the_marker_stays_behind_and_the_next_call_retries", async (reason, arrange, recover) => {
		const actor = sweptActor(4);
		arrange();

		const first = await settleRotation(actor);

		expect(first.group_seats[0]).toMatchObject({ group_id: G1, status: "deferred", reason });
		expect(readRotationMarker(actor.configDir, A)).toEqual({ key_packages: 1, seats: 0 });
		const uploads = vi.mocked(uploadKeyPackages).mock.calls.length;
		hold.postErrors = [];
		hold.confirmed = true;
		recover();
		// A dropped commit is rebuilt by the call after the one that drops it.
		for (let call = 0; call < 3 && readRotationMarker(actor.configDir, A).seats < 1; call++) {
			await settleRotation(actor);
		}
		expect(vi.mocked(uploadKeyPackages).mock.calls.length).toBe(uploads);
		expect(readRotationMarker(actor.configDir, A)).toEqual({ key_packages: 1, seats: 1 });
	});

	it("test_settle_when_a_post_was_unanswered_then_the_next_call_clears_it_and_the_one_after_lands", async () => {
		const actor = sweptActor(11);
		hold.postErrors.push(new Error("socket hang up"));

		const first = await settleRotation(actor);
		expect(first.group_seats[0]).toMatchObject({ status: "deferred", reason: "unreachable" });
		expect(readRotationMarker(actor.configDir, A)).toEqual({ key_packages: 1, seats: 0 });

		const second = await settleRotation(actor);
		expect(second.group_seats[0]).toMatchObject({ status: "deferred", reason: "unreachable" });
		expect(second.group_seats[0]).not.toHaveProperty("detail");
		expect(readRotationMarker(actor.configDir, A).seats).toBe(0);

		const third = await settleRotation(actor);
		expect(third.group_seats[0]).toMatchObject({ group_id: G1, status: "updated" });
		expect(readRotationMarker(actor.configDir, A)).toEqual({ key_packages: 1, seats: 1 });
		expect(vi.mocked(uploadKeyPackages)).toHaveBeenCalledTimes(1);
	});

	it("test_settle_when_the_disk_holds_an_earlier_key_then_the_drain_is_refused_and_nothing_is_claimed", async () => {
		const actor = sweptActor(12);
		scene.omitted.add(A);

		const settled = await settleRotation(actor);

		expect(settled.key_packages).toBe("key_not_current");
		expect(vi.mocked(claimKeyPackages)).not.toHaveBeenCalled();
		expect(vi.mocked(claimKeyPackagesBatch)).not.toHaveBeenCalled();
		expect(vi.mocked(uploadKeyPackages)).not.toHaveBeenCalled();
		expect(readRotationMarker(actor.configDir, A).key_packages).toBe(0);
		expect(hold.posts).toEqual([]);
	});

	it("test_settle_when_a_seat_failed_for_good_then_the_marker_advances_and_nothing_is_retried", async () => {
		const actor = sweptActor(10);
		scene.omitted.add(A);

		const settled = await settleRotation(actor);

		expect(settled.group_seats).toEqual([{ group_id: null, status: "failed", reason: "key_not_current" }]);
		expect(readRotationMarker(actor.configDir, A)).toEqual({ key_packages: 0, seats: 1 });
		const posted = hold.posts.length;
		expect(await settleRotation(actor)).toEqual({ key_packages: "key_not_current", group_seats: [] });
		expect(hold.posts).toHaveLength(posted);
		expect(vi.mocked(uploadKeyPackages)).not.toHaveBeenCalled();
	});

	it("test_settle_when_the_key_package_republish_fails_then_it_is_pending_and_the_seats_are_still_swept", async () => {
		const actor = sweptActor(5);
		vi.mocked(uploadKeyPackages).mockRejectedValueOnce(new Error("down"));

		const settled = await settleRotation(actor);

		expect(settled.key_packages).toBe("pending");
		expect(settled.group_seats).toMatchObject([{ group_id: G1, status: "updated" }]);
		expect(readRotationMarker(actor.configDir, A)).toEqual({ key_packages: 0, seats: 1 });
	});

	it("test_settle_when_the_settlement_is_already_running_for_the_agent_then_the_re_entry_does_nothing", async () => {
		const actor = sweptActor(6);
		let inner: ReturnType<typeof settleRotation> | undefined;
		hold.onPost = () => {
			inner = settleRotation(actor);
		};

		await settleRotation(actor);

		expect(await inner).toEqual({ key_packages: "not_held", group_seats: [] });
		expect(hold.posts).toHaveLength(1);
	});
});
