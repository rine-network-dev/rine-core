/**
 * How `selfUpdateGroup` reports and survives the ways a leaf move goes wrong,
 * against the REAL native core.
 *
 * A seat the sweep cannot finish yet must stay deferred so the next beat retries
 * it; only a failure no retry can change is final. Two processes of one agent
 * share a store, so a loser must not write its stale handle over the winner's.
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

import { loadAgentKeys } from "../src/crypto/keys.js";
import { fetchHandshakes, mlsCommit } from "../src/crypto/mls-api.js";
import { RineApiError } from "../src/errors.js";
import { addMlsGroupMember, removeMlsGroupMember } from "../src/mls-ops.js";
import { selfUpdateGroup } from "../src/mls-self-update.js";
import { buildFailure } from "../src/mls-seat-failure.js";
import { escrowKeyOutage } from "./mls-escrow-harness.js";
import { hold } from "./mls-hold-scene.js";
import {
	holdPendingUpdate,
	leafKey,
	rotatedActor,
	setUpHeldGroup,
} from "./mls-pending-commit-scene.js";
import {
	A,
	B,
	C,
	G1,
	R,
	groupOf,
	scene,
	tearDownRotationScene,
} from "./mls-rotation-scene.js";

beforeEach(setUpHeldGroup);
afterEach(() => {
	escrowKeyOutage.clear();
	tearDownRotationScene();
});

describe("selfUpdateGroup failures", () => {
	it("test_selfUpdateGroup_when_another_process_holds_a_pending_commit_then_deferred_awaiting_ack", async () => {
		const actor = rotatedActor(1);
		const n = groupOf(actor.configDir, A, G1).epoch();
		const feed = vi.mocked(fetchHandshakes).getMockImplementation()!;
		vi.mocked(fetchHandshakes).mockImplementationOnce(async (...args) => {
			const real = await feed(...args);
			const other = groupOf(actor.configDir, A, G1);
			other.commitUpdate(loadAgentKeys(actor.configDir, A).mls.privateKey);
			other.save();
			return real;
		});

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "deferred", reason: "awaiting_ack", epoch: n + 1 });
		expect(hold.posts).toEqual([]);
	});

	it("test_selfUpdateGroup_when_a_peer_commit_took_the_pending_epoch_then_deferred_epoch_race", async () => {
		const actor = rotatedActor(2);
		const group = groupOf(actor.configDir, A, G1);
		group.commitUpdate(loadAgentKeys(actor.configDir, A).mls.privateKey);
		group.save();
		scene.rosters.set(G1, [R, A, B, C]);
		await addMlsGroupMember(scene.dr, R, G1, C, scene.client);

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "deferred", reason: "epoch_race" });
	});

	it("test_selfUpdateGroup_when_a_lost_epoch_race_meets_the_winners_saved_epoch_then_the_store_is_not_rolled_back", async () => {
		const actor = rotatedActor(3);
		const n = groupOf(actor.configDir, A, G1).epoch();
		vi.mocked(mlsCommit).mockImplementationOnce(async () => {
			const winner = groupOf(actor.configDir, A, G1);
			winner.clearPendingCommit();
			winner.commitUpdate(loadAgentKeys(actor.configDir, A).mls.privateKey);
			winner.applyPendingCommit();
			winner.save();
			throw new RineApiError(409, "race", undefined, "epoch_conflict");
		});

		await selfUpdateGroup(actor, G1);

		const stored = groupOf(actor.configDir, A, G1);
		expect(stored.epoch()).toBe(n + 1);
		expect(stored.ownLeafSignatureKey()).toEqual(leafKey(A, 1));
	});

	it.each([
		[400, "dropped"],
		[499, "dropped"],
		[500, "kept"],
	])("test_selfUpdateGroup_when_the_post_answers_%i_then_the_pending_commit_is_%s", async (status, fate) => {
		const actor = rotatedActor(4);
		const n = groupOf(actor.configDir, A, G1).epoch();
		hold.postErrors.push(new RineApiError(status, "no", undefined, "x"));

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "deferred", reason: "unreachable" });
		expect(groupOf(actor.configDir, A, G1).pendingCommitEpoch()).toBe(fate === "kept" ? n + 1 : null);
	});

	it("test_selfUpdateGroup_when_a_commit_removed_this_agent_then_failed_evicted", async () => {
		const actor = rotatedActor(5);
		await removeMlsGroupMember(scene.dr, R, G1, A, scene.client);

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ group_id: G1, status: "failed", reason: "evicted" });
		expect(hold.posts.filter((post) => post.as === A)).toEqual([]);
	});

	it("test_selfUpdateGroup_when_the_sync_cannot_reach_the_server_then_deferred_unreachable_with_its_text", async () => {
		const actor = rotatedActor(6);
		vi.mocked(fetchHandshakes).mockRejectedValueOnce(new Error("feed down"));

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "deferred", reason: "unreachable", detail: "feed down" });
		expect(hold.posts).toEqual([]);
	});

	it("test_selfUpdateGroup_when_the_commit_is_confirmed_and_escrow_is_stored_then_escrow_pending_is_false", async () => {
		const actor = rotatedActor(7);

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "updated", escrow_pending: false });
	});

	it("test_selfUpdateGroup_when_the_escrow_key_is_unavailable_then_the_update_lands_with_escrow_pending", async () => {
		const actor = rotatedActor(8);
		escrowKeyOutage.add(A);

		const seat = await selfUpdateGroup(actor, G1);

		expect(seat).toMatchObject({ status: "updated", escrow_pending: true });
	});
});

describe("buildFailure", () => {
	const group = { pendingCommitEpoch: () => 7, epoch: () => 6 } as never;
	const native = (code: string) => Object.assign(new Error("core said no"), { code });

	it("test_buildFailure_when_a_commit_is_pending_then_deferred_awaiting_ack_at_its_epoch", () => {
		expect(buildFailure(native("RINE_MLS_COMMIT_PENDING"), group)).toEqual({
			status: "deferred",
			reason: "awaiting_ack",
			epoch: 7,
		});
	});

	it("test_buildFailure_when_the_signer_is_not_the_leaf_then_failed_seat_unhealable", () => {
		expect(buildFailure(native("RINE_MLS_SIGNER_LEAF_MISMATCH"), group)).toMatchObject({
			status: "failed",
			reason: "seat_unhealable",
		});
	});

	it("test_buildFailure_when_the_core_refuses_then_failed_refused_with_its_text", () => {
		expect(buildFailure(native("RINE_MLS_PROTOCOL"), group)).toEqual({
			status: "failed",
			reason: "refused",
			detail: "core said no",
		});
	});

	it("test_buildFailure_when_the_network_fails_then_deferred_unreachable", () => {
		expect(buildFailure(new RineApiError(503, "down", undefined, "x"), group)).toMatchObject({
			status: "deferred",
			reason: "unreachable",
		});
	});
});
