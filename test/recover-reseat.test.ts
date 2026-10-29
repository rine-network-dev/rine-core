/**
 * Recovery's closed-group reseat, driven against the REAL
 * native core: a restored agent holds no MLS state and re-enters the group from
 * the published GroupInfo alone. A test here fails when the reseat posts
 * nothing, adopts state the server refused, or retries a group it cannot reseat.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-escrow-key.js", async () =>
	(await import("./mls-escrow-harness.js")).escrowKeyModule(),
);

import { mlsToBase64 } from "../src/crypto/mls-api.js";
import {
	loadMlsGroup,
	mlsGroupIdBytes,
	mlsStoreRoot,
	openMlsClient,
} from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import { ReseatStatus, reseatClosedGroups } from "../src/recover-reseat.js";
import { World } from "./crypto/world.js";
import { type PeerReads, withPeerReads } from "./mls-escrow-harness.js";

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const PEER = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

let dir: string;
let world: World;
let groupInfo: string | null;
let listed: Record<string, unknown>[];
let posts: string[];
let refusePost: boolean;
let conflictsLeft: number;
let listError: Error | undefined;
let client: PeerReads;

/** The escrow upload call of the fake client, which a test may replace. */
interface Uploads {
	put: (path: string, body: unknown) => Promise<unknown>;
}

/**
 * PEER founds the group with AGENT in it; AGENT then loses its local MLS state
 * unless `keepState`, in which case its joined snapshot still holds the
 * epoch-1 exports no drain has taken.
 */
function foundGroupThenLoseState(keepState = false): void {
	const pkg = openMlsClient(dir, AGENT).generateKeyPackage();
	const founder = openMlsClient(dir, PEER).createGroupWithMembers(
		mlsGroupIdBytes(GROUP_ID),
		[pkg],
	);
	const welcome = founder.lastCommit()?.welcomes[0];
	if (!welcome) throw new Error("founding commit carried no welcome");
	openMlsClient(dir, AGENT).joinFromWelcome(welcome).save();
	founder.save();
	groupInfo = mlsToBase64(founder.groupInfo());
	if (!keepState) {
		fs.rmSync(mlsStoreRoot(dir, AGENT), { recursive: true, force: true });
	}
}

/** The epochs escrowed through `PUT /groups/{id}/mls/escrow/{epoch}`. */
function escrowedEpochs(): number[] {
	return client.puts.map(([path]) => Number(path.split("/").at(-1)));
}

function seatedMlsGroup(): Record<string, unknown> {
	return { id: GROUP_ID, mls_group_id: GROUP_ID, member_agent_ids: [AGENT] };
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-reseat-"));
	world = new World();
	world.save(dir, world.addAgent({ id: AGENT }));
	world.save(dir, world.addAgent({ id: PEER }));
	groupInfo = null;
	listed = [seatedMlsGroup()];
	posts = [];
	refusePost = false;
	conflictsLeft = 0;
	listError = undefined;
	client = withPeerReads(world, {
		get: async (path: string) => {
			if (path === "/groups") {
				if (listError) throw listError;
				return { items: listed };
			}
			if (path === `/groups/${GROUP_ID}/mls/group-info`) {
				return { group_info: groupInfo, epoch: 1 };
			}
			if (path === `/groups/${GROUP_ID}/requests`) return { items: [] };
			throw new Error(`unexpected GET ${path}`);
		},
		post: async (path: string) => {
			if (refusePost) throw new Error("stale epoch");
			if (conflictsLeft-- > 0) {
				throw new RineApiError(409, "stale", undefined, "epoch_conflict");
			}
			posts.push(path);
			return { epoch: 2, delivered_to: 1 };
		},
	});
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("reseatClosedGroups", () => {
	it("test_reseat_when_state_is_gone_then_posts_one_commit_and_escrows_the_epoch", async () => {
		foundGroupThenLoseState();

		const result = await reseatClosedGroups(client as never, dir, [AGENT]);

		expect(result).toEqual([
			{
				agent_id: AGENT,
				group_id: GROUP_ID,
				status: ReseatStatus.Reseated,
				escrow_pending: false,
				escrow: { gaps: [], queued: 0, dropped: 0, backlogged: 0 },
			},
		]);
		expect(posts.filter((path) => path.endsWith("/mls/commit"))).toEqual([
			`/groups/${GROUP_ID}/mls/commit`,
		]);
		expect(client.puts.length).toBeGreaterThan(0);
		const reseated = loadMlsGroup(openMlsClient(dir, AGENT), GROUP_ID);
		expect(reseated?.epoch()).toBe(2);
	});

	it("test_reseat_when_a_stale_snapshot_holds_untaken_exports_then_they_are_escrowed_before_it_is_replaced", async () => {
		foundGroupThenLoseState(true);

		await reseatClosedGroups(client as never, dir, [AGENT]);

		expect(escrowedEpochs()).toContain(1);
		expect(escrowedEpochs()).toContain(2);
	});

	it("test_reseat_when_only_an_older_epochs_upload_fails_then_the_resync_epoch_is_reported_stored", async () => {
		foundGroupThenLoseState(true);
		const uploads = client as unknown as Uploads;
		const stored = uploads.put;
		uploads.put = async (path, body) => {
			if (path.endsWith("/mls/escrow/1")) {
				throw new RineApiError(403, "no seat", undefined, "escrow_no_seat");
			}
			return stored(path, body);
		};

		const result = await reseatClosedGroups(client as never, dir, [AGENT]);

		expect(result[0]).toMatchObject({ status: ReseatStatus.Reseated, escrow_pending: false });
	});

	it("test_reseat_when_the_resync_epochs_upload_fails_then_escrow_is_reported_pending", async () => {
		foundGroupThenLoseState();
		(client as unknown as Uploads).put = async () => {
			throw new RineApiError(503, "unavailable");
		};

		const result = await reseatClosedGroups(client as never, dir, [AGENT]);

		expect(result[0]).toMatchObject({ status: ReseatStatus.Reseated, escrow_pending: true });
	});

	it("test_reseat_when_group_info_is_missing_then_reports_it_and_posts_nothing", async () => {
		const result = await reseatClosedGroups(client as never, dir, [AGENT]);

		expect(result.map((row) => row.status)).toEqual([ReseatStatus.NoGroupInfo]);
		expect(posts).toEqual([]);
	});

	it("test_reseat_when_roster_lacks_the_agent_then_reports_not_seated", async () => {
		const founder = openMlsClient(dir, PEER).createGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		founder.save();
		groupInfo = mlsToBase64(founder.groupInfo());

		const result = await reseatClosedGroups(client as never, dir, [AGENT]);

		expect(result.map((row) => row.status)).toEqual([ReseatStatus.NotSeated]);
		expect(posts).toEqual([]);
	});

	it("test_reseat_when_commit_is_refused_then_reports_failed_and_keeps_no_state", async () => {
		foundGroupThenLoseState();
		refusePost = true;

		const result = await reseatClosedGroups(client as never, dir, [AGENT]);

		expect(result[0]).toMatchObject({
			status: ReseatStatus.Failed,
			reason: "stale epoch",
		});
		expect(loadMlsGroup(openMlsClient(dir, AGENT), GROUP_ID)).toBeNull();
	});

	it("test_reseat_when_group_is_open_or_agent_unseated_then_skips_it", async () => {
		listed = [
			{ id: GROUP_ID, mls_group_id: null, member_agent_ids: [AGENT] },
			{ id: PEER, mls_group_id: PEER, member_agent_ids: [PEER] },
		];

		const result = await reseatClosedGroups(client as never, dir, [AGENT]);

		expect(result).toEqual([]);
	});

	it("test_reseat_when_the_commit_loses_the_epoch_race_once_then_it_is_rebuilt_and_reseated", async () => {
		foundGroupThenLoseState();
		conflictsLeft = 1;

		const result = await reseatClosedGroups(client as never, dir, [AGENT]);

		expect(result.map((row) => row.status)).toEqual([ReseatStatus.Reseated]);
	});

	it("test_reseat_when_the_commit_loses_the_epoch_race_twice_then_it_is_reported_failed", async () => {
		foundGroupThenLoseState();
		conflictsLeft = 2;

		const result = await reseatClosedGroups(client as never, dir, [AGENT]);

		expect(result.map((row) => row.status)).toEqual([ReseatStatus.Failed]);
	});

	it("test_reseat_when_every_commit_loses_the_epoch_race_then_two_posts_and_the_raw_conflict_is_the_reason", async () => {
		foundGroupThenLoseState();
		conflictsLeft = 5;

		const result = await reseatClosedGroups(client as never, dir, [AGENT]);

		// One rebuild and one retry: two commit posts, and the second conflict is
		// reported as it came off the wire.
		expect(conflictsLeft).toBe(3);
		expect(posts).toEqual([]);
		expect(result).toMatchObject([
			{ status: ReseatStatus.Failed, reason: "409: stale" },
		]);
	});

	it("test_reseat_when_one_agents_group_list_fails_then_it_is_reported_and_the_next_agent_runs", async () => {
		foundGroupThenLoseState();
		listError = new Error("groups unavailable");

		const result = await reseatClosedGroups(client as never, dir, [PEER, AGENT]);

		expect(result.map((row) => [row.agent_id, row.group_id, row.status])).toEqual([
			[PEER, null, ReseatStatus.Failed],
			[AGENT, null, ReseatStatus.Failed],
		]);
	});
});
