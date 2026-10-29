/**
 * The escrow drain and the peer admission, wired into the join, sync and
 * external-join paths, driven against the REAL native core.
 *
 * The founder lives in its own config dir, so the member under test knows it
 * only through the chain-verified roster: a test here fails when an installed
 * epoch uploads no escrow, when an idle sync pays for roster reads, or when a
 * Welcome whose peers could not be admitted is thrown away.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-escrow-key.js", async () =>
	(await import("./mls-escrow-harness.js")).escrowKeyModule(),
);

vi.mock("../src/mls-escrow-settle.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/mls-escrow-settle.js")
	>("../src/mls-escrow-settle.js");
	return { ...actual, settleAfterJoin: vi.fn(actual.settleAfterJoin) };
});

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/crypto/mls-api.js")
	>("../src/crypto/mls-api.js");
	return {
		...actual,
		uploadKeyPackages: vi.fn(async (_c: unknown, _a: unknown, p: string[]) => ({
			stored: p.length,
		})),
		mlsCommit: vi.fn(async () => ({ epoch: null, delivered_to: 1 })),
		mlsAck: vi.fn(async () => ({ confirmed: true, acks: 1, needed: 1 })),
		fetchHandshakes: vi.fn(async () => ({ handshakes: [] })),
		fetchWelcomes: vi.fn(async () => ({ welcomes: [] })),
		fetchGroupInfo: vi.fn(async () => ({ group_info: null, epoch: null })),
	};
});

import { settleAfterJoin } from "../src/mls-escrow-settle.js";
import { noteUnreported } from "../src/mls-escrow-handoff.js";
import {
	fetchGroupInfo,
	fetchHandshakes,
	fetchWelcomes,
	mlsCommit,
	mlsToBase64,
} from "../src/crypto/mls-api.js";
import { mlsGroupIdBytes, openMlsClient } from "../src/crypto/mls.js";
import {
	externalJoinMlsGroup,
	processMlsWelcomes,
	syncMlsGroup,
} from "../src/mls-ops.js";
import { WelcomeSpool } from "../src/mls-welcome-spool.js";
import { World } from "./crypto/world.js";
import { type PeerReads, withPeerReads } from "./mls-escrow-harness.js";

const FOUNDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const MEMBER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const THIRD_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";
const FOURTH_ID = "e5f6a7b8-c9d0-1234-ef12-345678901234";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

/** The member under test's config dir; it holds no key of the founder's. */
let dir: string;
/** The founder's config dir; it holds every key the founder commits with. */
let founderDir: string;
let world: World;
/** The roster the fake server serves; a test widens it as the founder adds. */
let members: string[];
let rosterReads: number;
let rosterFails: boolean;
let client: PeerReads;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-wirejoin-"));
	founderDir = fs.mkdtempSync(join(tmpdir(), "rine-wirejoin-founder-"));
	world = new World();
	members = [FOUNDER_ID, MEMBER_ID];
	rosterReads = 0;
	rosterFails = false;
	vi.clearAllMocks();
	vi.mocked(fetchHandshakes).mockResolvedValue({ handshakes: [] });
	vi.mocked(fetchWelcomes).mockResolvedValue({ welcomes: [] });
	vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => ({
		epoch: body.epoch ?? null,
		delivered_to: 1,
	}));
	client = withPeerReads(
		world,
		{
			get: async (path: string) => {
				if (path === `/groups/${GROUP_ID}/requests`) return { items: [] };
				throw new Error(`unexpected GET ${path}`);
			},
		},
		() => {
			rosterReads += 1;
			if (rosterFails) throw new Error("roster unavailable");
			return members;
		},
	);
	const member = world.addAgent({ id: MEMBER_ID });
	world.save(dir, member);
	world.save(founderDir, member);
	world.save(founderDir, world.addAgent({ id: FOUNDER_ID }));
	const third = world.addAgent({ id: THIRD_ID });
	world.save(dir, third);
	world.save(founderDir, third);
	world.save(founderDir, world.addAgent({ id: FOURTH_ID }));
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
	fs.rmSync(founderDir, { recursive: true, force: true });
});

/** The escrow uploads so far, as the epochs their paths name. */
function uploadedEpochs(): string[] {
	return client.puts.map(([path]) => path.split("/").pop() ?? "");
}

/** The founder founds the group with the member and hands the Welcome to the server. */
function founderInvitesMember() {
	const pkg = openMlsClient(dir, MEMBER_ID).generateKeyPackage();
	const founder = openMlsClient(founderDir, FOUNDER_ID).createGroupWithMembers(
		mlsGroupIdBytes(GROUP_ID),
		[pkg],
	);
	const welcome = founder.lastCommit()?.welcomes[0];
	if (!welcome) throw new Error("founding commit carried no welcome");
	founder.save();
	vi.mocked(fetchWelcomes).mockResolvedValue({
		welcomes: [
			{
				id: "w1",
				group_id: GROUP_ID,
				blob: mlsToBase64(welcome),
				created_at: "2026-01-01T00:00:00Z",
			},
		],
	});
	return founder;
}

describe("processMlsWelcomes", () => {
	it("test_process_welcomes_when_welcome_installed_uploads_escrow_for_the_joined_epoch", async () => {
		founderInvitesMember();

		const result = await processMlsWelcomes(dir, MEMBER_ID, client as never);

		expect(result.groupIds).toEqual([GROUP_ID]);
		expect(client.puts.map(([path]) => path)).toContain(
			`/groups/${GROUP_ID}/mls/escrow/1`,
		);
	});

	it("test_process_welcomes_when_a_welcome_is_installed_then_the_old_state_is_settled_for_that_group_first", async () => {
		founderInvitesMember();

		await processMlsWelcomes(dir, MEMBER_ID, client as never);

		expect(settleAfterJoin).toHaveBeenCalledTimes(1);
		expect(settleAfterJoin).toHaveBeenCalledWith(
			expect.objectContaining({ agentId: MEMBER_ID }),
			GROUP_ID,
			expect.anything(),
		);
	});

	it("test_process_welcomes_when_admission_read_fails_keeps_the_welcome_spooled", async () => {
		founderInvitesMember();
		rosterFails = true;

		const result = await processMlsWelcomes(dir, MEMBER_ID, client as never);

		expect(result.processed).toBe(0);
		expect(new WelcomeSpool(dir, MEMBER_ID).pending()).toHaveLength(1);
		expect(client.puts).toEqual([]);
	});
});

describe("syncMlsGroup", () => {
	/** The member installed the group; the founder then commits `ids` one by one. */
	async function memberFollowsFounderAdding(ids: string[]) {
		const founder = founderInvitesMember();
		await processMlsWelcomes(dir, MEMBER_ID, client as never);
		members = [FOUNDER_ID, MEMBER_ID, ...ids];
		const handshakes = ids.map((id, index) => {
			const pkg = openMlsClient(founderDir, id).generateKeyPackage();
			const bundle = founder.addMember(pkg);
			founder.save();
			return {
				id: `h${index}`,
				epoch: index + 2,
				blob: mlsToBase64(bundle.commit),
				created_at: "2026-01-01T00:00:00Z",
			};
		});
		return handshakes;
	}

	it("test_sync_when_peer_commit_applied_uploads_escrow_for_each_applied_epoch", async () => {
		const handshakes = await memberFollowsFounderAdding([THIRD_ID, FOURTH_ID]);
		client.puts.length = 0;
		vi.mocked(fetchHandshakes).mockResolvedValue({ handshakes });

		const result = await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client as never);

		expect(result.processed).toBe(2);
		expect(uploadedEpochs()).toEqual(["2", "3"]);
	});

	it("test_sync_when_no_handshakes_makes_no_group_reads", async () => {
		await memberFollowsFounderAdding([]);
		rosterReads = 0;

		await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client as never);

		expect(rosterReads).toBe(0);
	});

	it("test_sync_when_a_background_sweep_lost_epochs_then_a_reporting_idle_sync_reports_them_once", async () => {
		await memberFollowsFounderAdding([]);
		const carried = [
			{ epoch: 5, reason: "refused" as const },
			{ epoch: 6, reason: "branch_revoked" as const },
		];
		noteUnreported(dir, MEMBER_ID, carried.map((gap) => ({ groupId: GROUP_ID, gap })));

		const result = await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client as never, undefined, {
			carryUnreported: true,
		});

		expect(result.escrow.gaps).toEqual(carried);

		const again = await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client as never, undefined, {
			carryUnreported: true,
		});
		expect(again.escrow.gaps).toEqual([]);
	});

	it("test_sync_when_a_sweep_lost_epochs_then_a_sync_run_for_its_effect_leaves_them_for_the_next_reported_one", async () => {
		await memberFollowsFounderAdding([]);
		const carried = [{ epoch: 5, reason: "refused" as const }];
		noteUnreported(dir, MEMBER_ID, carried.map((gap) => ({ groupId: GROUP_ID, gap })));

		const silent = await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client as never);
		const reported = await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client as never, undefined, {
			carryUnreported: true,
		});

		expect(silent.escrow.gaps).toEqual([]);
		expect(reported.escrow.gaps).toEqual(carried);
	});

	it("test_sync_when_a_sweep_lost_epochs_of_another_group_then_this_groups_sync_does_not_report_them", async () => {
		await memberFollowsFounderAdding([]);
		noteUnreported(dir, MEMBER_ID, [
			{ groupId: "d4e5f6a7-b8c9-0123-def0-234567890123", gap: { epoch: 5, reason: "refused" } },
		]);

		const result = await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client as never, undefined, {
			carryUnreported: true,
		});

		expect(result.escrow.gaps).toEqual([]);
	});
});

describe("externalJoinMlsGroup", () => {
	it("test_external_join_when_commit_accepted_uploads_escrow", async () => {
		const founder = founderInvitesMember();
		members = [FOUNDER_ID, MEMBER_ID, THIRD_ID];
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: mlsToBase64(founder.groupInfo()),
			epoch: 1,
		});

		const { epoch } = await externalJoinMlsGroup(
			dir,
			THIRD_ID,
			GROUP_ID,
			client as never,
		);

		expect(epoch).toBe(2);
		expect(client.puts.map(([path]) => path)).toContain(
			`/groups/${GROUP_ID}/mls/escrow/2`,
		);
	});

	it("test_external_join_when_commit_accepted_then_the_old_state_is_settled_for_that_group_first", async () => {
		const founder = founderInvitesMember();
		members = [FOUNDER_ID, MEMBER_ID, THIRD_ID];
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: mlsToBase64(founder.groupInfo()),
			epoch: 1,
		});

		await externalJoinMlsGroup(dir, THIRD_ID, GROUP_ID, client as never);

		expect(settleAfterJoin).toHaveBeenCalledTimes(1);
		expect(settleAfterJoin).toHaveBeenCalledWith(
			expect.objectContaining({ agentId: THIRD_ID }),
			GROUP_ID,
			expect.anything(),
		);
	});
});
