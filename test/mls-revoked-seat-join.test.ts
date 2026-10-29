/**
 * A join over a revoked member's unreclaimed leaf, against the REAL native core.
 *
 * A founds with B and adds C; C is then revoked, so the batch key read omits C
 * (`cKeys = "absent"`, the shape `live_agent()` gives `GET /agents/keys`) and the
 * roster omits C. C's leaf stays in the tree until a member reclaims it.
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

import { loadAgentKeys, saveAgentKeys } from "../src/crypto/keys.js";
import { fetchGroupInfo } from "../src/crypto/mls-api.js";
import { loadMlsState } from "../src/crypto/mls-state.js";
import {
	addMlsGroupMembers,
	externalJoinMlsGroup,
	processMlsWelcomes,
} from "../src/mls-ops.js";
import { WELCOME_REFUSED_CODE } from "../src/mls-welcome-guard.js";
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
	addD,
	joiner,
	readsNaming,
	serveWelcome,
} from "./mls-welcome-catchup-scene.js";

beforeEach(async () => {
	await setUpScene({ removeC: false });
});
afterEach(tearDownScene);

/** C is revoked: its keys are no longer served and the roster omits it. */
function revokeC(): void {
	scene.cKeys = "absent";
	scene.roster = [A_ID, B_ID];
	scene.keyReads.length = 0;
}

describe("a join over a revoked member's unreclaimed leaf", () => {
	it("test_add_when_the_tree_holds_a_revoked_unreclaimed_leaf_then_no_welcome_is_minted", async () => {
		revokeC();
		joiner.dir = join(scene.root, "d");
		fs.mkdirSync(joiner.dir);
		agent(joiner.dir, D_ID);
		offerKeyPackage(D_ID, joiner.dir);
		scene.roster = [A_ID, B_ID, D_ID];
		const postedBefore = scene.posted.length;

		const result = await addMlsGroupMembers(
			scene.dirA,
			A_ID,
			GROUP_ID,
			[D_ID],
			scene.client,
		);

		// Expected: the adder holds D back while C's leaf stands, so no
		// Welcome D could never open is minted and D's leaf never enters the tree.
		expect(scene.posted.length).toBe(postedBefore);
		// The tree's agents ride in the one batch read the roster already costs.
		expect(readsNaming(C_ID)).toHaveLength(1);
		expect(result.outcomes).toEqual([
			{ agentId: D_ID, status: "skipped", reason: "revoked_seat_unreclaimed" },
		]);
	});

	it("test_add_when_a_live_sibling_whose_keys_are_on_this_device_is_in_the_tree_then_the_joiner_is_admitted", async () => {
		saveAgentKeys(scene.dirA, C_ID, loadAgentKeys(scene.dirC, C_ID));
		joiner.dir = join(scene.root, "d");
		fs.mkdirSync(joiner.dir);
		agent(joiner.dir, D_ID);
		offerKeyPackage(D_ID, joiner.dir);
		scene.roster = [A_ID, B_ID, C_ID, D_ID];

		const result = await addMlsGroupMembers(
			scene.dirA,
			A_ID,
			GROUP_ID,
			[D_ID],
			scene.client,
		);

		// Expected: the server still serves C, so its leaf is verifiable and the
		// add goes through, wherever C's keys live.
		expect(result.outcomes).toEqual([{ agentId: D_ID, status: "added" }]);
		expect(readsNaming(C_ID)).toHaveLength(1);
	});

	it("test_add_when_the_revoked_leaf_belongs_to_an_agent_whose_keys_are_on_this_device_then_the_joiner_is_held", async () => {
		revokeC();
		agent(scene.dirA, C_ID);
		joiner.dir = join(scene.root, "d");
		fs.mkdirSync(joiner.dir);
		agent(joiner.dir, D_ID);
		offerKeyPackage(D_ID, joiner.dir);
		scene.roster = [A_ID, B_ID, D_ID];
		const postedBefore = scene.posted.length;

		const result = await addMlsGroupMembers(
			scene.dirA,
			A_ID,
			GROUP_ID,
			[D_ID],
			scene.client,
		);

		// Expected: local keys do not vouch for a leaf the server no longer serves,
		// because the joiner's core cannot verify it either.
		expect(scene.posted.length).toBe(postedBefore);
		expect(result.outcomes).toEqual([
			{ agentId: D_ID, status: "skipped", reason: "revoked_seat_unreclaimed" },
		]);
	});

	it("test_welcome_for_the_group_being_joined_when_a_tree_member_is_revoked_then_the_refusal_is_raised_not_counted", async () => {
		// The race shape: A's Add (and D's Welcome) predate C's revocation.
		await addD();
		revokeC();
		serveWelcome();

		// Expected: the join's own Welcome pass names the refusal instead of
		// resolving `{ groupIds: [], discarded: 1 }` and letting the join report
		// joined, and the Welcome leaves the spool because it can never open.
		const pass = processMlsWelcomes(joiner.dir, D_ID, scene.client, {
			forGroup: GROUP_ID,
		});
		await expect(pass).rejects.toMatchObject({
			code: WELCOME_REFUSED_CODE,
			groupId: GROUP_ID,
			reason: "peer_not_admitted",
		});
		expect(new WelcomeSpool(joiner.dir, D_ID).pending()).toHaveLength(0);
	});

	it("test_external_join_when_a_tree_member_is_revoked_then_the_refusal_is_raised", async () => {
		revokeC();
		joiner.dir = join(scene.root, "d");
		fs.mkdirSync(joiner.dir);
		agent(joiner.dir, D_ID);
		scene.roster = [A_ID, B_ID, D_ID];
		const info = scene.posted.at(-1)!.group_info!;
		vi.mocked(fetchGroupInfo).mockResolvedValue({ group_info: info, epoch: 1 });

		// Expected: the same typed refusal as the Welcome path, so the join verb
		// stops instead of warning and reporting joined.
		await expect(
			externalJoinMlsGroup(joiner.dir, D_ID, GROUP_ID, scene.client),
		).rejects.toMatchObject({
			code: WELCOME_REFUSED_CODE,
			groupId: GROUP_ID,
			reason: "peer_not_admitted",
		});
		expect(loadMlsState(joiner.dir, D_ID, GROUP_ID)).toBeNull();
	});
});
