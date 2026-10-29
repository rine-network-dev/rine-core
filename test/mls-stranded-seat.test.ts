/**
 * A seated member with no local state, against the REAL native core.
 *
 * D is seated by A's Add, but C was revoked before D opened the Welcome, so the
 * Welcome was refused and D holds no state. Once a member reclaims C's leaf, D
 * takes its own leaf back on its next group sync. Until then the sync raises the
 * refusal that names the remedy, and a member that holds state, never had a leaf,
 * or has a Welcome waiting for it is never re-seated.
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
import { loadMlsGroup, openMlsClient } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import { isMlsResyncUnavailable, recoverMlsGroup } from "../src/mls-ops-resync.js";
import { processMlsWelcomes, resumeMlsGroupAdmission } from "../src/mls-ops.js";
import { WELCOME_REFUSED_CODE } from "../src/mls-welcome-guard.js";
import {
	A_ID,
	B_ID,
	C_ID,
	GROUP_ID,
	scene,
	setUpScene,
	tearDownScene,
} from "./mls-admission-scene.js";
import { D_ID, addD, joiner, serveWelcome } from "./mls-welcome-catchup-scene.js";

beforeEach(async () => {
	await setUpScene({ removeC: false });
});
afterEach(tearDownScene);

const decode = (identity: Uint8Array) => new TextDecoder().decode(identity);

/** The agent ids holding a leaf in the group as `dir`'s agent sees it. */
function leaves(dir: string, id: string): string[] {
	const group = loadMlsGroup(openMlsClient(dir, id), GROUP_ID);
	return group === null ? [] : group.memberIdentities().map((l) => decode(l.identity));
}

/** C is revoked and D's Welcome is refused for it: D is seated and holds no state. */
async function strandD(): Promise<void> {
	await addD();
	scene.cKeys = "absent";
	scene.roster = [A_ID, B_ID, D_ID];
	serveWelcome();
	await expect(
		processMlsWelcomes(joiner.dir, D_ID, scene.client, { forGroup: GROUP_ID }),
	).rejects.toMatchObject({ reason: "peer_not_admitted" });
	expect(leaves(joiner.dir, D_ID)).toEqual([]);
}

/** A member reclaims C's leaf, then the group's latest GroupInfo is what a joiner reads. */
async function reclaimC(): Promise<void> {
	await resumeMlsGroupAdmission(scene.dirA, A_ID, GROUP_ID, scene.client, undefined, {
		reclaim: true,
	});
	publishLatestGroupInfo();
}

function publishLatestGroupInfo(): void {
	const withInfo = scene.posted.filter((body) => body.group_info);
	const info = withInfo[withInfo.length - 1]!.group_info!;
	vi.mocked(fetchGroupInfo).mockResolvedValue({ group_info: info, epoch: 1 });
}

describe("a seated member with no local state", () => {
	it("test_sync_when_the_welcome_was_refused_and_the_seat_is_reclaimed_then_the_member_takes_its_leaf_back", async () => {
		await strandD();
		await reclaimC();
		const before = scene.posted.length;

		const result = await recoverMlsGroup(joiner.dir, D_ID, GROUP_ID, scene.client);

		expect(result).toMatchObject({ regime: "mls", rung: "resync", evicted: false });
		const mine = leaves(joiner.dir, D_ID);
		expect(mine.filter((id) => id === D_ID)).toHaveLength(1);
		expect(mine).not.toContain(C_ID);
		expect(scene.posted.length).toBe(before + 1);
		expect(scene.posted.at(-1)!.welcomes).toEqual([]);
	});

	it("test_sync_when_the_tree_still_holds_the_revoked_leaf_then_the_refusal_is_raised_and_nothing_is_posted", async () => {
		await strandD();
		publishLatestGroupInfo();
		const before = scene.posted.length;

		const outcome = recoverMlsGroup(joiner.dir, D_ID, GROUP_ID, scene.client);

		await expect(outcome).rejects.toMatchObject({
			code: WELCOME_REFUSED_CODE,
			groupId: GROUP_ID,
			reason: "peer_not_admitted",
			message:
				`Cannot join the MLS group ${GROUP_ID} yet: its ratchet tree holds a member ` +
				"this agent cannot verify, because the server no longer vouches for that " +
				"agent. The group's seat for it must be reclaimed first: any other member " +
				"that holds a leaf in the group can run " +
				"`rine group resume-admission --reclaim` (an admin is not required); then " +
				"the join can be repeated.",
		});
		expect(scene.posted.length).toBe(before);
		expect(leaves(joiner.dir, D_ID)).toEqual([]);
	});

	it("test_sync_when_the_member_was_never_seated_then_nothing_is_posted", async () => {
		await strandD();
		await reclaimC();
		const stranger = join(scene.root, "e");
		fs.mkdirSync(stranger);
		const E_ID = "f2e3d4c5-b6a7-4890-9123-456789abcdef";
		scene.world.save(stranger, scene.world.addAgent({ id: E_ID }));
		const before = scene.posted.length;

		const outcome = recoverMlsGroup(stranger, E_ID, GROUP_ID, scene.client);

		await expect(outcome).rejects.toSatisfy(isMlsResyncUnavailable);
		expect(scene.posted.length).toBe(before);
	});

	it("test_sync_when_the_welcome_is_kept_on_the_spool_then_the_member_does_not_reseat", async () => {
		await addD();
		serveWelcome();
		const client = scene.client as unknown as {
			get: (path: string, ...rest: unknown[]) => Promise<unknown>;
		};
		const real = client.get;
		client.get = async (path, ...rest) => {
			if (path === `/groups/${GROUP_ID}/members`) throw new RineApiError(503, "roster down");
			return real(path, ...rest);
		};
		publishLatestGroupInfo();
		const before = scene.posted.length;

		const outcome = recoverMlsGroup(joiner.dir, D_ID, GROUP_ID, scene.client);

		await expect(outcome).rejects.toSatisfy(isMlsResyncUnavailable);
		expect(scene.posted.length).toBe(before);
		expect(leaves(joiner.dir, D_ID)).toEqual([]);
	});

	it("test_sync_when_a_welcome_waits_on_the_server_then_it_installs_and_nothing_is_posted", async () => {
		await addD();
		serveWelcome();
		publishLatestGroupInfo();
		const before = scene.posted.length;

		const result = await recoverMlsGroup(joiner.dir, D_ID, GROUP_ID, scene.client);

		expect(leaves(joiner.dir, D_ID)).toContain(D_ID);
		expect(result.rung).toBe("replay");
		expect(scene.posted.length).toBe(before);
	});

	it("test_sync_when_the_group_info_read_fails_then_the_failure_propagates_unchanged", async () => {
		await strandD();
		await reclaimC();
		vi.mocked(fetchGroupInfo).mockRejectedValue(new RineApiError(503, "upstream down"));
		const before = scene.posted.length;

		const outcome = recoverMlsGroup(joiner.dir, D_ID, GROUP_ID, scene.client);

		await expect(outcome).rejects.toMatchObject({ status: 503, detail: "upstream down" });
		expect(scene.posted.length).toBe(before);
	});

	it("test_sync_when_the_member_holds_state_then_it_takes_the_ordinary_path", async () => {
		await addD();
		serveWelcome();
		await processMlsWelcomes(joiner.dir, D_ID, scene.client, { forGroup: GROUP_ID });
		expect(leaves(joiner.dir, D_ID)).toContain(D_ID);
		publishLatestGroupInfo();
		const before = scene.posted.length;

		const result = await recoverMlsGroup(joiner.dir, D_ID, GROUP_ID, scene.client);

		expect(result.rung).toBe("replay");
		expect(scene.posted.length).toBe(before);
	});
});
