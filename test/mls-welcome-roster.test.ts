/**
 * What the welcome guard does when the roster read names nobody holding a leaf
 * in the tree the Welcome seats the agent in, against the REAL native core.
 *
 * A Welcome minted by a founder the roster does not name: the tree holds that
 * founder and the victim, the roster names neither, so the guard refuses the
 * Welcome and nothing is installed. A Welcome whose tree holds two members the
 * roster omits: each is chain-verified once, the roster corroborates the join
 * through a third member, and the Welcome installs.
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

import { fetchWelcomes, mlsFromBase64 } from "../src/crypto/mls-api.js";
import { loadMlsGroup, mlsGroupIdBytes, openMlsClient } from "../src/crypto/mls.js";
import { processMlsWelcomes } from "../src/mls-ops.js";
import { WelcomeSpool } from "../src/mls-welcome-spool.js";
import {
	A_ID,
	B_ID,
	C_ID,
	GROUP_ID,
	agent,
	offerKeyPackage,
	scene,
	setUpScene,
	tearDownScene,
} from "./mls-admission-scene.js";
import {
	D_ID,
	OTHER_GROUP_ID,
	X_ID,
	addD,
	delivery,
	joiner,
	readsNaming,
	spoolEntry,
} from "./mls-welcome-catchup-scene.js";
import { mintHonestWelcome } from "./mls-welcome-harness.js";
import { buildRosterScene } from "./mls-welcome-roster-scene.js";

beforeEach(async () => {
	await setUpScene({ removeC: false });
	await addD();
});
afterEach(tearDownScene);

describe("a Welcome whose tree the roster read does not corroborate", () => {
	it("test_welcome_when_the_only_other_leaf_verifies_but_is_off_the_roster_then_the_guard_refuses_it_and_nothing_is_installed", async () => {
		const xDir = join(scene.root, "x");
		fs.mkdirSync(xDir);
		agent(xDir, X_ID);
		// addD consumed D's first key package for the real Welcome, so this one
		// needs a fresh half D still holds.
		offerKeyPackage(D_ID, joiner.dir);
		scene.roster = [X_ID, D_ID];
		const blob = await mintHonestWelcome({
			founderDir: xDir,
			founder: X_ID,
			victim: D_ID,
			groupId: GROUP_ID,
			client: scene.client,
			posted: scene.posted,
		});
		scene.roster = [A_ID, B_ID, D_ID];
		scene.keyReads.length = 0;
		vi.mocked(fetchWelcomes).mockResolvedValueOnce({
			welcomes: [delivery("w-x", GROUP_ID, blob)],
		});

		await expect(
			processMlsWelcomes(joiner.dir, D_ID, scene.client),
		).rejects.toMatchObject({
			reason: "roster_uncorroborated",
			groupId: GROUP_ID,
		});

		expect(readsNaming(X_ID)).toHaveLength(1);
		expect(loadMlsGroup(openMlsClient(joiner.dir, D_ID), GROUP_ID)).toBeNull();
		expect(new WelcomeSpool(joiner.dir, D_ID).pending()).toHaveLength(1);
		expect(spoolEntry().refused).toBe(true);
		expect(
			openMlsClient(joiner.dir, D_ID).discardWelcomeKeyPackage(
				mlsFromBase64(blob),
			),
		).toBe(true);
	});

	it("test_welcome_when_the_tree_holds_two_unlisted_members_then_each_is_read_once_and_it_installs", async () => {
		const blob = await buildRosterScene();
		vi.mocked(fetchWelcomes).mockResolvedValueOnce({
			welcomes: [delivery("w-g3", OTHER_GROUP_ID, blob)],
		});

		const outcome = await processMlsWelcomes(joiner.dir, D_ID, scene.client);

		expect(outcome.groupIds).toEqual([OTHER_GROUP_ID]);
		expect(outcome.discarded).toBe(0);
		expect(readsNaming(C_ID)).toHaveLength(1);
		expect(readsNaming(X_ID)).toHaveLength(1);
		expect(scene.keyReads).toHaveLength(4);
		const envelope = new TextEncoder().encode("after the join");
		const sealed = openMlsClient(scene.dirA, A_ID)
			.loadGroup(mlsGroupIdBytes(OTHER_GROUP_ID))!
			.encryptApplicationMessage(envelope);
		expect(
			openMlsClient(joiner.dir, D_ID)
				.loadGroup(mlsGroupIdBytes(OTHER_GROUP_ID))!
				.decryptApplicationMessage(sealed).envelope,
		).toEqual(envelope);
	});
});
