/**
 * The join's local MLS setup, against the REAL native core.
 *
 * A founds with B and adds C; D is added by A and joins. `cKeys` and the roster
 * choose what the fake server vouches for, as the other admission scenes do.
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

import { fetchGroupInfo, fetchWelcomes, mlsCommit } from "../src/crypto/mls-api.js";
import { loadMlsState } from "../src/crypto/mls-state.js";
import { RineApiError } from "../src/errors.js";
import {
	ALREADY_A_MEMBER_CODE,
	MlsEstablishStep,
	MlsMembershipOutcome,
	type MlsMembershipResult,
	establishMlsMembership,
	isAlreadyAMember,
	mlsStateEstablished,
} from "../src/mls-join-establish.js";
import { WELCOME_REFUSED_CODE } from "../src/mls-welcome-guard.js";
import { WelcomeSpool } from "../src/mls-welcome-spool.js";
import {
	A_ID,
	B_ID,
	GROUP_ID,
	agent,
	offerKeyPackage,
	scene,
	setUpScene,
	tearDownScene,
} from "./mls-admission-scene.js";
import {
	D_ID,
	DELIVERY_ID,
	OTHER_GROUP_ID,
	X_ID,
	addD,
	delivery,
	joiner,
	serveWelcome,
} from "./mls-welcome-catchup-scene.js";
import { publishLatestGroupInfo, reclaimC, strandD } from "./mls-join-stranded-scene.js";
import { mintHonestWelcome } from "./mls-welcome-harness.js";

beforeEach(async () => {
	await setUpScene({ removeC: false });
});
afterEach(tearDownScene);

type Get = (path: string, ...rest: unknown[]) => Promise<unknown>;

/** Answer `GET /groups/{id}` with the group as the server reports it. */
function serveGroup(group: Record<string, unknown>): void {
	const client = scene.client as unknown as { get: Get };
	const real = client.get;
	client.get = async (path, ...rest) =>
		path === `/groups/${GROUP_ID}` ? group : real(path, ...rest);
}

const mlsGroup = { id: GROUP_ID, mls_group_id: GROUP_ID };

const establish = (dir = joiner.dir, id = D_ID) =>
	establishMlsMembership(dir, id, GROUP_ID, scene.client);

describe("establishing the local MLS state of a joined agent", () => {
	it("test_establish_when_the_group_has_no_ratchet_tree_then_nothing_is_set_up", async () => {
		await addD();
		serveGroup({ id: GROUP_ID });
		vi.mocked(fetchWelcomes).mockClear();

		const result = await establish();

		expect(result).toEqual({ outcome: MlsMembershipOutcome.NotMls });
		expect(fetchWelcomes).not.toHaveBeenCalled();
	});

	it("test_establish_when_the_group_read_fails_then_the_failure_is_returned_at_that_step", async () => {
		await addD();
		const client = scene.client as unknown as { get: Get };
		client.get = async () => {
			throw new RineApiError(503, "group read down");
		};

		const result = await establish();

		expect(result).toMatchObject({
			outcome: MlsMembershipOutcome.Failed,
			failure: { step: MlsEstablishStep.GroupRead },
		});
		expect(result.reason).toContain("group read down");
	});

	it("test_establish_when_a_welcome_is_waiting_then_it_installs_before_any_leaf_is_touched", async () => {
		await addD();
		serveGroup(mlsGroup);
		serveWelcome();
		publishLatestGroupInfo();
		const before = scene.posted.length;

		const result = await establish();

		expect(result.outcome).toBe(MlsMembershipOutcome.Installed);
		expect(loadMlsState(joiner.dir, D_ID, GROUP_ID)).not.toBeNull();
		expect(scene.posted.length).toBe(before);
		expect(fetchGroupInfo).not.toHaveBeenCalled();
	});

	it("test_establish_when_the_state_is_already_held_then_it_is_reported_as_held", async () => {
		await addD();
		serveGroup(mlsGroup);
		serveWelcome();
		await establish();

		const again = await establish();

		expect(again.outcome).toBe(MlsMembershipOutcome.Held);
	});

	it("test_establish_when_the_seat_was_reclaimed_then_the_agent_takes_its_own_leaf_back", async () => {
		await strandD();
		await reclaimC();
		serveGroup(mlsGroup);
		const before = scene.posted.length;

		const result = await establish();

		expect(result.outcome).toBe(MlsMembershipOutcome.Reseated);
		expect(loadMlsState(joiner.dir, D_ID, GROUP_ID)).not.toBeNull();
		expect(scene.posted.length).toBe(before + 1);
	});

	it("test_establish_when_the_tree_holds_a_member_the_agent_cannot_verify_then_the_refusal_is_raised", async () => {
		await strandD();
		publishLatestGroupInfo();
		serveGroup(mlsGroup);
		const before = scene.posted.length;

		await expect(establish()).rejects.toMatchObject({
			code: WELCOME_REFUSED_CODE,
			groupId: GROUP_ID,
			reason: "peer_not_admitted",
		});
		expect(scene.posted.length).toBe(before);
		expect(loadMlsState(joiner.dir, D_ID, GROUP_ID)).toBeNull();
	});

	it("test_establish_when_the_agent_holds_no_leaf_then_it_joins_by_external_commit", async () => {
		await strandD();
		await reclaimC();
		serveGroup(mlsGroup);
		const E_ID = "f2e3d4c5-b6a7-4890-9123-456789abcdef";
		const stranger = join(scene.root, "e");
		fs.mkdirSync(stranger);
		agent(stranger, E_ID);
		scene.roster = [A_ID, B_ID, D_ID, E_ID];
		const before = scene.posted.length;

		const result = await establish(stranger, E_ID);

		expect(result.outcome).toBe(MlsMembershipOutcome.ExternalJoined);
		expect(loadMlsState(stranger, E_ID, GROUP_ID)).not.toBeNull();
		expect(scene.posted.length).toBe(before + 1);
	});

	it("test_establish_when_a_welcome_for_the_group_is_kept_then_no_leaf_is_replaced_under_it", async () => {
		await addD();
		serveGroup(mlsGroup);
		serveWelcome();
		const client = scene.client as unknown as { get: Get };
		const real = client.get;
		client.get = async (path, ...rest) => {
			if (path === `/groups/${GROUP_ID}/members`) throw new RineApiError(503, "roster down");
			return real(path, ...rest);
		};
		publishLatestGroupInfo();
		const before = scene.posted.length;

		const result = await establish();

		expect(result.outcome).toBe(MlsMembershipOutcome.Failed);
		expect(result.failure?.step).toBe(MlsEstablishStep.WelcomeInstall);
		expect(result.reason).toContain("kept for a later attempt");
		expect(scene.posted.length).toBe(before);
		expect(new WelcomeSpool(joiner.dir, D_ID).pending()).toHaveLength(1);
	});

	it("test_establish_when_the_external_join_fails_for_another_reason_then_it_is_returned_not_thrown", async () => {
		await strandD();
		await reclaimC();
		serveGroup(mlsGroup);
		const stranger = join(scene.root, "e");
		fs.mkdirSync(stranger);
		const E_ID = "f2e3d4c5-b6a7-4890-9123-456789abcdef";
		agent(stranger, E_ID);
		scene.roster = [A_ID, B_ID, D_ID, E_ID];
		vi.mocked(mlsCommit).mockRejectedValueOnce(new RineApiError(503, "commit down"));

		const result = await establish(stranger, E_ID);

		expect(result).toMatchObject({
			outcome: MlsMembershipOutcome.Failed,
			failure: { step: MlsEstablishStep.ExternalJoin },
		});
		expect(result.reason).toContain("commit down");
	});

	it("test_establish_when_the_retake_finds_no_group_info_then_it_fails_at_the_retake_without_an_external_join", async () => {
		await strandD();
		await reclaimC();
		serveGroup(mlsGroup);
		vi.mocked(fetchGroupInfo).mockResolvedValue({ group_info: null, epoch: 1 });

		const result = await establish();

		expect(result).toMatchObject({
			outcome: MlsMembershipOutcome.Failed,
			failure: { step: MlsEstablishStep.SeatRetake },
		});
		expect(result.reason).toContain("the group has published no GroupInfo");
		expect(loadMlsState(joiner.dir, D_ID, GROUP_ID)).toBeNull();
	});

	it("test_establish_when_another_groups_welcome_is_refused_then_this_group_still_installs", async () => {
		await addD();
		serveGroup(mlsGroup);
		const xDir = join(scene.root, "x");
		fs.mkdirSync(xDir);
		agent(xDir, X_ID);
		offerKeyPackage(D_ID, joiner.dir);
		scene.roster = [X_ID, D_ID];
		const decoy = await mintHonestWelcome({
			founderDir: xDir,
			founder: X_ID,
			victim: D_ID,
			groupId: OTHER_GROUP_ID,
			client: scene.client,
			posted: scene.posted,
		});
		scene.roster = [A_ID, B_ID, D_ID];
		vi.mocked(fetchWelcomes).mockResolvedValueOnce({
			welcomes: [
				delivery("w-decoy", OTHER_GROUP_ID, decoy),
				delivery(DELIVERY_ID, GROUP_ID, joiner.blob),
			],
		});

		const result = await establish();

		expect(result).toEqual({ outcome: MlsMembershipOutcome.Installed });
		expect(loadMlsState(joiner.dir, D_ID, OTHER_GROUP_ID)).toBeNull();
	});
});

describe("the join answers", () => {
	it("test_already_a_member_when_the_status_and_code_match_then_it_is_recognised", () => {
		expect(isAlreadyAMember(new RineApiError(409, "x", undefined, ALREADY_A_MEMBER_CODE))).toBe(true);
		expect(isAlreadyAMember({ status: 409, code: ALREADY_A_MEMBER_CODE })).toBe(true);
	});

	it("test_already_a_member_when_either_half_differs_then_it_is_not_recognised", () => {
		expect(isAlreadyAMember(new RineApiError(409, "x", undefined, "other"))).toBe(false);
		expect(isAlreadyAMember(new RineApiError(403, "x", undefined, ALREADY_A_MEMBER_CODE))).toBe(false);
		expect(isAlreadyAMember(new Error("409"))).toBe(false);
		expect(isAlreadyAMember(null)).toBe(false);
	});

	it("test_state_established_when_the_outcome_is_each_kind_then_only_the_three_that_leave_state_count", () => {
		const verdicts = Object.values(MlsMembershipOutcome).map((outcome) => [
			outcome,
			mlsStateEstablished({ outcome } satisfies MlsMembershipResult),
		]);
		expect(verdicts).toEqual([
			["not_mls", false],
			["held", false],
			["installed", true],
			["reseated", true],
			["external_joined", true],
			["failed", false],
		]);
	});
});
