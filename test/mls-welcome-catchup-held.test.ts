/**
 * What the welcome pass does when a Welcome is neither simply installed nor
 * simply discarded, against the REAL native core.
 *
 * A re-invited agent holding old state, whose new Welcome names a member that
 * does not verify: the final refusal is not an install and the old state
 * survives. A verification read that fails transiently: the Welcome stays
 * spooled and the next pass installs the SAME bytes. An ordinary pass reads
 * nothing extra. A roster read answering 403: the Welcome is never opened, kept
 * marked refused, its key package half still there.
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

import { MlsClient } from "@rine-network/mls";
import { fetchWelcomes, mlsFromBase64 } from "../src/crypto/mls-api.js";
import { mlsStoreRoot, openMlsClient } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
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
	DELIVERY_ID,
	OTHER_GROUP_ID,
	X_ID,
	addD,
	delivery,
	joiner,
	readsNaming,
	serveWelcome,
	spoolEntry,
	wrapGet,
} from "./mls-welcome-catchup-scene.js";
import { mintHonestWelcome } from "./mls-welcome-harness.js";

beforeEach(async () => {
	await setUpScene({ removeC: false });
	await addD();
});
afterEach(tearDownScene);

/** Every file of D's group state on disk, as relative path -> bytes in hex. */
function groupStateOnDisk(): Record<string, string> {
	const root = mlsStoreRoot(joiner.dir, D_ID);
	const out: Record<string, string> = {};
	for (const rel of fs.readdirSync(root, { recursive: true }) as string[]) {
		if (!rel.includes("groups")) continue;
		const full = join(root, rel);
		if (!fs.statSync(full).isFile()) continue;
		out[rel] = fs.readFileSync(full).toString("hex");
	}
	return out;
}

describe("a Welcome the pass does not simply install or discard", () => {
	it("test_welcome_when_the_agent_holds_old_state_and_the_member_does_not_verify_then_the_group_is_not_reported_installed", async () => {
		const xDir = join(scene.root, "x");
		fs.mkdirSync(xDir);
		agent(xDir, X_ID);
		// addD consumed D's first key package for the real Welcome, so the old
		// Welcome needs a fresh half D still holds.
		offerKeyPackage(D_ID, joiner.dir);
		scene.roster = [X_ID, D_ID];
		const oldBlob = await mintHonestWelcome({
			founderDir: xDir,
			founder: X_ID,
			victim: D_ID,
			groupId: GROUP_ID,
			client: scene.client,
			posted: scene.posted,
		});
		vi.mocked(fetchWelcomes).mockResolvedValueOnce({
			welcomes: [delivery("w-old", GROUP_ID, oldBlob)],
		});
		const old = await processMlsWelcomes(joiner.dir, D_ID, scene.client);
		expect(old.groupIds).toEqual([GROUP_ID]);
		const before = groupStateOnDisk();
		expect(Object.keys(before).length).toBeGreaterThan(0);

		scene.cKeys = "tampered";
		scene.roster = [A_ID, B_ID, D_ID];
		scene.keyReads.length = 0;
		serveWelcome();

		const outcome = await processMlsWelcomes(joiner.dir, D_ID, scene.client);

		expect(outcome.groupIds).toEqual([]);
		expect(outcome.discarded).toBe(1);
		expect(
			openMlsClient(joiner.dir, D_ID).discardWelcomeKeyPackage(
				mlsFromBase64(joiner.blob),
			),
		).toBe(false);
		expect(groupStateOnDisk()).toEqual(before);
	});

	it("test_welcome_when_the_member_key_read_has_an_outage_then_it_stays_spooled_and_the_next_pass_installs_it", async () => {
		offerKeyPackage(D_ID, joiner.dir);
		scene.roster = [A_ID, B_ID, C_ID, D_ID];
		const g2Blob = await mintHonestWelcome({
			founderDir: scene.dirA,
			founder: A_ID,
			victim: D_ID,
			groupId: OTHER_GROUP_ID,
			client: scene.client,
			posted: scene.posted,
		});
		scene.roster = [A_ID, B_ID, D_ID];
		scene.keyReads.length = 0;
		// The outage belongs to the pass under test, not to the invitation.
		scene.cKeys = "outage";
		vi.mocked(fetchWelcomes).mockResolvedValueOnce({
			welcomes: [
				delivery(DELIVERY_ID, GROUP_ID, joiner.blob),
				delivery("w-g2", OTHER_GROUP_ID, g2Blob),
			],
		});
		const paths: string[] = [];
		wrapGet((path) => paths.push(path));

		const first = await processMlsWelcomes(joiner.dir, D_ID, scene.client);

		expect(first.groupIds).toEqual([OTHER_GROUP_ID]);
		expect(first.discarded).toBe(0);
		const pending = new WelcomeSpool(joiner.dir, D_ID).pending();
		expect(pending).toHaveLength(1);
		expect(pending[0]!.delivery.group_id).toBe(GROUP_ID);
		expect(spoolEntry().refused).toBe(false);
		expect(paths.some((p) => p.endsWith("/mls/key-packages/count"))).toBe(false);

		scene.cKeys = "served";
		const second = await processMlsWelcomes(joiner.dir, D_ID, scene.client);

		expect(second.groupIds).toEqual([GROUP_ID]);
		expect(new WelcomeSpool(joiner.dir, D_ID).pending()).toHaveLength(0);
	});

	it("test_welcome_when_every_tree_member_is_on_the_roster_then_no_refusal_is_read_and_no_extra_key_read_is_made", async () => {
		scene.roster = [A_ID, B_ID, C_ID, D_ID];
		const spy = vi.spyOn(MlsClient.prototype, "refusedPeer");
		serveWelcome();

		const outcome = await processMlsWelcomes(joiner.dir, D_ID, scene.client);

		expect(outcome.groupIds).toEqual([GROUP_ID]);
		expect(spy).not.toHaveBeenCalled();
		expect(scene.keyReads).toHaveLength(2);
		spy.mockRestore();
	});

	it("test_welcome_when_the_roster_read_is_forbidden_then_the_welcome_is_never_opened_and_is_kept_marked_refused", async () => {
		wrapGet((path) => {
			if (/^\/groups\/[^/]+\/members$/.test(path)) {
				throw new RineApiError(403, "forbidden");
			}
		});
		serveWelcome();

		const outcome = await processMlsWelcomes(joiner.dir, D_ID, scene.client);

		expect(outcome.groupIds).toEqual([]);
		expect(outcome.discarded).toBe(0);
		expect(readsNaming(C_ID)).toHaveLength(0);
		expect(spoolEntry().refused).toBe(true);
		expect(
			openMlsClient(joiner.dir, D_ID).discardWelcomeKeyPackage(
				mlsFromBase64(joiner.blob),
			),
		).toBe(true);
	});
});
