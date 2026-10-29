/**
 * The downgrade guard's memo, across a state change in ONE process.
 *
 * A test that only ever exercises a fresh process cannot catch a memo that is
 * never invalidated: every answer it takes is the first one. These drive the
 * REAL establishers and the REAL retirement instead — a founding, a Welcome, an
 * external commit, a leave — ask the guard on either side of each, and assert
 * the answer changed.
 *
 * Only the network is mocked (`crypto/mls-api.js`), exactly as in
 * `test/mls-ops.test.ts`: the commit, welcome and GroupInfo blobs relayed
 * between the agents are the genuine ones the native core produced.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/mls-escrow-key.js", async () =>
	(await import("../mls-escrow-harness.js")).escrowKeyModule(),
);

vi.mock("../../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<
		typeof import("../../src/crypto/mls-api.js")
	>("../../src/crypto/mls-api.js");
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
		fetchWelcomes: vi.fn(async () => ({ welcomes: [] })),
		fetchGroupInfo: vi.fn(async () => ({ group_info: null, epoch: null })),
	};
});

import { MlsDowngradeError } from "../../src/crypto/downgrade-error.js";
import type { MlsCommitBody } from "../../src/crypto/mls-api.js";
import {
	claimKeyPackages,
	claimKeyPackagesBatch,
	fetchGroupInfo,
	fetchWelcomes,
	mlsCommit,
	mlsInit,
	mlsToBase64,
	uploadKeyPackages,
} from "../../src/crypto/mls-api.js";
import { assertNoMlsDowngrade } from "../../src/crypto/mls-downgrade.js";
import { deleteMlsState } from "../../src/crypto/mls-state.js";
import {
	mlsGroupIdBytes,
	mlsStoreRoot,
	openMlsClient,
} from "../../src/crypto/mls.js";
import {
	externalJoinMlsGroup,
	initMlsGroup,
	processMlsWelcomes,
} from "../../src/mls-ops.js";
import { withPeerReads } from "../mls-escrow-harness.js";
import { World } from "./world.js";

const SELF_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const MEMBER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const THIRD_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

let client: never;
let dir: string;
let posted: MlsCommitBody[];
let world: World;

function agent(agentId: string): void {
	world.save(dir, world.addAgent({ id: agentId }));
}

/** One claimable key package for `agentId`, minted by that agent's own client. */
function offerKeyPackage(agentId: string): void {
	const pkg = mlsToBase64(openMlsClient(dir, agentId).generateKeyPackage());
	// Founding claims in batches, adding a member claims one at a time.
	vi.mocked(claimKeyPackages).mockResolvedValue({
		packages: [pkg],
		agent_id: agentId,
	});
	vi.mocked(claimKeyPackagesBatch).mockResolvedValue({
		claims: [{ agent_id: agentId, packages: [pkg] }],
	});
}

/** SELF founds GROUP_ID with MEMBER welcomed into it. */
async function foundGroup(): Promise<void> {
	offerKeyPackage(MEMBER_ID);
	vi.mocked(mlsInit).mockResolvedValue({
		mls_pending: true,
		members: [
			{ agent_id: SELF_ID, has_key_package: true },
			{ agent_id: MEMBER_ID, has_key_package: true },
		],
	});
	await initMlsGroup(dir, SELF_ID, GROUP_ID, client);
}

/** MEMBER processes the Welcome the founding commit carried. */
async function deliverWelcome(): Promise<void> {
	const welcome = posted[0]?.welcomes?.[0]?.welcome;
	if (!welcome) throw new Error("founding commit carried no welcome");
	vi.mocked(fetchWelcomes).mockResolvedValue({
		welcomes: [
			{
				id: "w1",
				group_id: GROUP_ID,
				blob: welcome,
				created_at: "2026-01-01T00:00:00Z",
			},
		],
	});
	await processMlsWelcomes(dir, MEMBER_ID, client);
	vi.mocked(fetchWelcomes).mockResolvedValue({ welcomes: [] });
}

/** A sender-key row is the server claiming "this group is not MLS". */
function askGuard(agentId: string): () => void {
	return () => assertNoMlsDowngrade(dir, agentId, GROUP_ID, false);
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-memo-"));
	posted = [];
	world = new World();
	client = withPeerReads(world, {
		get: async (path: string) => {
			if (path === `/groups/${GROUP_ID}/requests`) return { items: [] };
			throw new Error(`unexpected GET ${path}`);
		},
	}) as never;
	vi.clearAllMocks();
	vi.mocked(uploadKeyPackages).mockImplementation(async (_c, _a, p) => ({
		stored: p.length,
	}));
	vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => {
		posted.push(body);
		return { epoch: body.epoch ?? null, delivered_to: 1 };
	});
	vi.mocked(fetchWelcomes).mockResolvedValue({ welcomes: [] });
	vi.mocked(fetchGroupInfo).mockResolvedValue({
		group_info: null,
		epoch: null,
	});
	agent(SELF_ID);
	agent(MEMBER_ID);
	agent(THIRD_ID);
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("the downgrade memo across an MLS state change in one process", () => {
	it("test_guard_refuses_a_sender_key_row_after_the_agent_joins_mls_in_the_same_process", async () => {
		// The read that remembers "this agent holds none" — before the join.
		expect(askGuard(MEMBER_ID)).not.toThrow();

		await foundGroup();
		await deliverWelcome();

		expect(askGuard(MEMBER_ID)).toThrow(MlsDowngradeError);
	});

	it("test_guard_refuses_a_sender_key_row_after_founding_the_group_in_the_same_process", async () => {
		expect(askGuard(SELF_ID)).not.toThrow();

		await foundGroup();

		expect(askGuard(SELF_ID)).toThrow(MlsDowngradeError);
	});

	it("test_guard_refuses_a_sender_key_row_after_an_external_join_in_the_same_process", async () => {
		await foundGroup();
		expect(askGuard(THIRD_ID)).not.toThrow();
		const group = openMlsClient(dir, SELF_ID).loadGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: mlsToBase64(group.groupInfo()),
			epoch: 1,
		});

		await externalJoinMlsGroup(dir, THIRD_ID, GROUP_ID, client);

		expect(askGuard(THIRD_ID)).toThrow(MlsDowngradeError);
	});

	it("test_guard_allows_a_billboard_read_after_the_agent_leaves_in_the_same_process", async () => {
		await foundGroup();
		await deliverWelcome();
		// The read that remembers "this agent holds state" — before the leave.
		expect(askGuard(MEMBER_ID)).toThrow(MlsDowngradeError);

		deleteMlsState(dir, MEMBER_ID, GROUP_ID);

		expect(askGuard(MEMBER_ID)).not.toThrow();
	});
});

/**
 * Establish real state the way ANOTHER PROCESS would — without invalidating.
 *
 * `noteMlsStateChanged` is an in-process call, so a join taken with `rine` on
 * the command line while a long-running `rine-mcp` holds the same config dir
 * reaches that server only through the store on disk.
 */
function plantStateUnnoticed(agentId: string): void {
	openMlsClient(dir, agentId).createGroup(mlsGroupIdBytes(GROUP_ID)).save();
}

/** The converse: another process left the group and retired its state. */
function retireStateUnnoticed(agentId: string): void {
	fs.rmSync(join(mlsStoreRoot(dir, agentId), "groups"), {
		recursive: true,
		force: true,
	});
}

describe("the downgrade memo across an MLS state change in ANOTHER process", () => {
	it("test_guard_refuses_a_sender_key_row_after_another_process_establishes_state", () => {
		// The read that remembers "this agent holds none" — before the other
		// process joins. Nothing here ever calls the invalidator.
		expect(askGuard(THIRD_ID)).not.toThrow();

		plantStateUnnoticed(THIRD_ID);

		expect(askGuard(THIRD_ID)).toThrow(MlsDowngradeError);
	});

	it("test_guard_allows_a_billboard_read_after_another_process_retires_state", async () => {
		await foundGroup();
		await deliverWelcome();
		expect(askGuard(MEMBER_ID)).toThrow(MlsDowngradeError);

		retireStateUnnoticed(MEMBER_ID);

		expect(askGuard(MEMBER_ID)).not.toThrow();
	});
});
