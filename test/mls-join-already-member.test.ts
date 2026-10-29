/**
 * The already-a-member answer to a join, against the REAL native core.
 *
 * A seated agent that holds no state for the group gets the same local MLS setup
 * as a fresh join, and the result comes back whether or not it left state, so a
 * caller can report a failed setup before it re-throws the 409; any other 409 is
 * left to the caller.
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

import { fetchGroupInfo } from "../src/crypto/mls-api.js";
import { loadMlsState } from "../src/crypto/mls-state.js";
import { RineApiError } from "../src/errors.js";
import {
	ALREADY_A_MEMBER_CODE,
	MlsEstablishStep,
	MlsMembershipOutcome,
	establishAfterAlreadyAMember,
} from "../src/mls-join-establish.js";
import { processMlsWelcomes } from "../src/mls-ops.js";
import { WELCOME_REFUSED_CODE } from "../src/mls-welcome-guard.js";
import {
	A_ID,
	B_ID,
	GROUP_ID,
	scene,
	setUpScene,
	tearDownScene,
} from "./mls-admission-scene.js";
import { reclaimC, strandD } from "./mls-join-stranded-scene.js";
import { D_ID, addD, joiner, serveWelcome } from "./mls-welcome-catchup-scene.js";

beforeEach(async () => {
	await setUpScene({ removeC: false });
});
afterEach(tearDownScene);

type Get = (path: string, ...rest: unknown[]) => Promise<unknown>;

const alreadyAMember = () => new RineApiError(409, "already", undefined, ALREADY_A_MEMBER_CODE);

const settle = (err: unknown) =>
	establishAfterAlreadyAMember(err, joiner.dir, D_ID, GROUP_ID, scene.client);

/** Answer `GET /groups/{id}` with the group as the server reports it. */
function serveGroup(group: Record<string, unknown>): void {
	const client = scene.client as unknown as { get: Get };
	const real = client.get;
	client.get = async (path, ...rest) =>
		path === `/groups/${GROUP_ID}` ? group : real(path, ...rest);
}

const mlsGroup = { id: GROUP_ID, mls_group_id: GROUP_ID };

describe("a join answered with already_a_member", () => {
	it("test_already_a_member_when_the_error_is_another_failure_then_nothing_is_set_up", async () => {
		await addD();

		const other = new RineApiError(409, "other", undefined, "other");

		expect(await settle(other)).toBeNull();
		expect(await settle(new Error("boom"))).toBeNull();
		expect(loadMlsState(joiner.dir, D_ID, GROUP_ID)).toBeNull();
	});

	it("test_already_a_member_when_no_state_loads_then_the_setup_runs_and_its_result_is_returned", async () => {
		await addD();
		serveGroup(mlsGroup);
		serveWelcome();

		const result = await settle(alreadyAMember());

		expect(result?.outcome).toBe(MlsMembershipOutcome.Installed);
		expect(loadMlsState(joiner.dir, D_ID, GROUP_ID)).not.toBeNull();
	});

	it("test_already_a_member_when_state_is_already_held_then_the_409_is_left_to_the_caller", async () => {
		await addD();
		serveGroup(mlsGroup);
		serveWelcome();
		await processMlsWelcomes(joiner.dir, D_ID, scene.client, { forGroup: GROUP_ID });
		const reads: string[] = [];
		const client = scene.client as unknown as { get: Get };
		const real = client.get;
		client.get = async (path, ...rest) => {
			reads.push(path);
			return real(path, ...rest);
		};

		expect(await settle(alreadyAMember())).toBeNull();
		expect(reads).toEqual([]);
	});

	it("test_already_a_member_when_the_setup_fails_then_the_failed_result_comes_back", async () => {
		await addD();
		serveGroup(mlsGroup);
		vi.mocked(fetchGroupInfo).mockResolvedValue({ group_info: null, epoch: 1 });

		const result = await settle(alreadyAMember());

		expect(result).toMatchObject({
			outcome: MlsMembershipOutcome.Failed,
			failure: { step: MlsEstablishStep.SeatRetake },
		});
		expect(loadMlsState(joiner.dir, D_ID, GROUP_ID)).toBeNull();
	});

	it("test_already_a_member_when_the_group_has_no_ratchet_tree_then_the_not_mls_result_comes_back", async () => {
		await addD();
		serveGroup({ id: GROUP_ID });

		expect(await settle(alreadyAMember())).toEqual({ outcome: MlsMembershipOutcome.NotMls });
	});

	it("test_already_a_member_when_the_seat_was_stranded_then_the_reseated_result_comes_back", async () => {
		await strandD();
		await reclaimC();
		serveGroup(mlsGroup);

		const result = await settle(alreadyAMember());

		expect(result).toEqual({ outcome: MlsMembershipOutcome.Reseated });
		expect(loadMlsState(joiner.dir, D_ID, GROUP_ID)).not.toBeNull();
	});

	it("test_already_a_member_when_the_tree_holds_a_member_the_agent_cannot_verify_then_the_refusal_is_raised", async () => {
		await addD();
		scene.cKeys = "absent";
		scene.roster = [A_ID, B_ID, D_ID];
		serveGroup(mlsGroup);
		serveWelcome();

		await expect(settle(alreadyAMember())).rejects.toMatchObject({
			code: WELCOME_REFUSED_CODE,
			groupId: GROUP_ID,
			reason: "peer_not_admitted",
		});
	});
});
