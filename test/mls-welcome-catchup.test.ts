/**
 * A Welcome whose ratchet tree holds a member the roster read did not name, against
 * the REAL native core.
 *
 * D is added to a group that already holds A, B and C, so D's tree names C while
 * the roster D reads lacks it. The welcome pass opens the Welcome, the core refuses
 * C by name, and the pass chain-verifies C once and opens the same bytes again. A
 * member that does not verify leaves the Welcome unjoinable: discarded, with the
 * key package it was sealed to released. A member removed behind the Welcome still
 * verifies, so the join lands and the removal replays without a NACK.
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

import { ascii } from "../src/crypto/bytes.js";
import { mlsFromBase64, mlsNack } from "../src/crypto/mls-api.js";
import { loadMlsGroup, openMlsClient } from "../src/crypto/mls.js";
import { allowedFor } from "../src/mls-allowed.js";
import {
	processMlsWelcomes,
	removeMlsGroupMember,
	syncMlsGroup,
} from "../src/mls-ops.js";
import { WelcomeSpool } from "../src/mls-welcome-spool.js";
import {
	A_ID,
	B_ID,
	C_ID,
	type CKeys,
	GROUP_ID,
	groupOf,
	scene,
	serveHandshakes,
	setUpScene,
	tearDownScene,
} from "./mls-admission-scene.js";
import {
	D_ID,
	addD,
	joiner,
	readsNaming,
	serveWelcome,
	wrapGet,
} from "./mls-welcome-catchup-scene.js";

beforeEach(async () => {
	await setUpScene({ removeC: false });
	await addD();
});
afterEach(tearDownScene);

describe("a Welcome naming a member the roster read did not list", () => {
	it("test_welcome_when_the_tree_holds_an_unlisted_member_then_it_installs_after_one_key_read", async () => {
		serveWelcome();

		const outcome = await processMlsWelcomes(joiner.dir, D_ID, scene.client);

		expect(outcome).toMatchObject({
			processed: 1,
			groupIds: [GROUP_ID],
			discarded: 0,
		});
		expect(readsNaming(C_ID)).toHaveLength(1);
		const envelope = new TextEncoder().encode("after the join");
		const sealed = groupOf(scene.dirA, A_ID).encryptApplicationMessage(envelope);
		expect(
			groupOf(joiner.dir, D_ID).decryptApplicationMessage(sealed).envelope,
		).toEqual(envelope);
		expect(new WelcomeSpool(joiner.dir, D_ID).pending()).toHaveLength(0);
	});

	it("test_welcome_when_the_member_was_added_then_removed_behind_it_then_it_installs_and_syncs_without_a_nack", async () => {
		scene.roster = [A_ID, B_ID, C_ID, D_ID];
		await removeMlsGroupMember(scene.dirA, A_ID, GROUP_ID, C_ID, scene.client);
		scene.roster = [A_ID, B_ID, D_ID];
		scene.keyReads.length = 0;
		serveHandshakes();
		serveWelcome();

		const outcome = await processMlsWelcomes(joiner.dir, D_ID, scene.client);

		expect(outcome.groupIds).toEqual([GROUP_ID]);
		await syncMlsGroup(joiner.dir, D_ID, GROUP_ID, scene.client);
		expect(groupOf(joiner.dir, D_ID).epoch()).toBe(
			groupOf(scene.dirA, A_ID).epoch(),
		);
		expect(mlsNack).not.toHaveBeenCalled();
	});

	it.each<[string, CKeys]>([
		["its_chain_does_not_verify", "tampered"],
		["the_agent_is_gone", "absent"],
		["its_published_key_is_not_the_leaf_key", "foreign"],
	])(
		"test_welcome_when_%s_then_it_is_discarded_with_its_key_package_released",
		async (_label, mode) => {
			scene.cKeys = mode;
			const paths: string[] = [];
			wrapGet((path) => paths.push(path));
			serveWelcome();

			const outcome = await processMlsWelcomes(joiner.dir, D_ID, scene.client);

			expect(outcome).toMatchObject({
				groupIds: [],
				discarded: 1,
				processed: 0,
			});
			expect(new WelcomeSpool(joiner.dir, D_ID).pending()).toHaveLength(0);
			expect(
				openMlsClient(joiner.dir, D_ID).discardWelcomeKeyPackage(
					mlsFromBase64(joiner.blob),
				),
			).toBe(false);
			expect(
				allowedFor(joiner.dir, D_ID).contains(
					ascii(C_ID),
					scene.world.agents.get(C_ID)![0]!.derived.mlsEd25519.publicKey,
				),
			).toBe(false);
			expect(
				paths.some((path) => path.endsWith("/mls/key-packages/count")),
			).toBe(false);
			expect(readsNaming(C_ID)).toHaveLength(1);
			expect(loadMlsGroup(openMlsClient(joiner.dir, D_ID), GROUP_ID)).toBeNull();
		},
	);
});
