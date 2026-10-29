/**
 * A member recovering past a gap meets a leaf its roster does not list: the Add of
 * C is in the GroupInfo tree its external commit must walk, but C is no longer (or
 * not yet) on the roster. Against the REAL native core, the resync and the reseat
 * each admit C once through a chain-verified key read and retry; a leaf that does
 * not verify surfaces as the typed refusal, with the member's state untouched and
 * nothing posted.
 *
 * The removal and orphan commit builds are wrapped the same way, but a core only
 * refuses a commit build over the committer's own leaf, which no honest setup
 * produces, so those sites cannot be driven here.
 */
import * as fs from "node:fs";
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
		uploadKeyPackages: vi.fn(async (_c: unknown, _a: unknown, p: string[]) => ({
			stored: p.length,
		})),
		claimKeyPackages: vi.fn(async () => ({ packages: [], agent_id: "" })),
		claimKeyPackagesBatch: vi.fn(async () => ({ claims: [] })),
		mlsInit: vi.fn(async () => ({ mls_pending: true, members: [] })),
		mlsCommit: vi.fn(async () => ({ epoch: null, delivered_to: 1 })),
		mlsAck: vi.fn(async () => ({ confirmed: true, acks: 1, needed: 1 })),
		mlsNack: vi.fn(async () => ({ quarantined: true })),
		fetchHandshakes: vi.fn(async () => ({ handshakes: [] })),
		fetchWelcomes: vi.fn(async () => ({ welcomes: [] })),
		fetchGroupInfo: vi.fn(async () => ({ group_info: null, epoch: null })),
	};
});

import { fetchGroupInfo, fetchHandshakes, mlsCommit } from "../src/crypto/mls-api.js";
import { RineApiError } from "../src/errors.js";
import { MLS_RESYNC_REQUIRED_CODE, recoverMlsGroup } from "../src/mls-ops-resync.js";
import { ReseatStatus, reseatClosedGroups } from "../src/recover-reseat.js";
import {
	B_ID,
	C_ID,
	GROUP_ID,
	groupOf,
	scene,
	setUpScene,
	tearDownScene,
} from "./mls-admission-scene.js";

/** The tree after A's Add: C is in it, and B's roster read does not list C. */
beforeEach(async () => {
	await setUpScene({ removeC: false });
	const add = scene.posted[1]!;
	vi.mocked(fetchGroupInfo).mockResolvedValue({
		group_info: add.group_info ?? null,
		epoch: add.epoch ?? null,
	});
	vi.mocked(fetchHandshakes).mockRejectedValue(
		new RineApiError(409, "replay cannot help", undefined, MLS_RESYNC_REQUIRED_CODE),
	);
	scene.keyReads.length = 0;
	vi.mocked(mlsCommit).mockClear();
});
afterEach(tearDownScene);

/** The group list a reseat reads, with B seated in the one MLS group. */
function listingClient() {
	const base = scene.client as { get: (...a: unknown[]) => Promise<unknown> };
	return {
		...base,
		get: async (path: string, ...rest: unknown[]) =>
			path === "/groups"
				? { items: [{ id: GROUP_ID, mls_group_id: "latched", member_agent_ids: [B_ID] }] }
				: base.get(path, ...rest),
	} as never;
}

describe("a resync whose tree holds a peer the roster lacks", () => {
	it("test_recover_when_the_tree_holds_a_verifying_peer_the_roster_lacks_then_it_verifies_once", async () => {
		const result = await recoverMlsGroup(scene.dirB, B_ID, GROUP_ID, scene.client);

		expect(result).toMatchObject({ rung: "resync", fromEpoch: 1 });
		expect(scene.keyReads.filter((ids) => ids.includes(C_ID))).toHaveLength(1);
		expect(mlsCommit).toHaveBeenCalledTimes(1);
		expect(groupOf(scene.dirB, B_ID).epoch()).toBe(result.epoch);
	});

	it("test_recover_when_the_peer_does_not_verify_then_the_refusal_surfaces_and_nothing_is_posted", async () => {
		scene.cKeys = "tampered";

		await expect(recoverMlsGroup(scene.dirB, B_ID, GROUP_ID, scene.client)).rejects.toThrow(
			new RegExp(`resync rung.*has not admitted: ${C_ID}`, "s"),
		);

		expect(scene.keyReads.filter((ids) => ids.includes(C_ID))).toHaveLength(1);
		expect(mlsCommit).not.toHaveBeenCalled();
		expect(groupOf(scene.dirB, B_ID).epoch()).toBe(1);
	});
});

describe("a reseat whose tree holds a peer the roster lacks", () => {
	function restoredDevice(): string {
		const dir = `${scene.root}/restored`;
		fs.mkdirSync(dir);
		scene.world.save(dir, scene.world.agents.get(B_ID)![0]!);
		return dir;
	}

	it("test_reseat_when_the_tree_holds_a_verifying_peer_the_roster_lacks_then_it_verifies_once", async () => {
		const restored = restoredDevice();

		const [outcome] = await reseatClosedGroups(listingClient(), restored, [B_ID]);

		expect(outcome).toMatchObject({ status: ReseatStatus.Reseated, agent_id: B_ID });
		expect(scene.keyReads.filter((ids) => ids.includes(C_ID))).toHaveLength(1);
		expect(mlsCommit).toHaveBeenCalledTimes(1);
		expect(groupOf(restored, B_ID).epoch()).toBeGreaterThan(1);
	});

	it("test_reseat_when_the_peer_does_not_verify_then_it_is_reported_failed_and_nothing_is_posted", async () => {
		scene.cKeys = "foreign";
		const restored = restoredDevice();

		const [outcome] = await reseatClosedGroups(listingClient(), restored, [B_ID]);

		expect(outcome?.status).toBe(ReseatStatus.Failed);
		expect(scene.keyReads.filter((ids) => ids.includes(C_ID))).toHaveLength(1);
		expect(mlsCommit).not.toHaveBeenCalled();
	});
});
