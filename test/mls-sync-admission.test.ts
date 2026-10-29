/**
 * A member that was offline while a peer was added and removed catches up
 * through both commits, against the REAL native core.
 *
 * The Add of C is applied by B before C's removal, so B's allowed set must hold
 * C's leaf at that moment even though C is no longer in the roster B reads. The
 * sync therefore admits the peer a refusal names, once, and retries; every
 * other outcome (unverifiable chain, wrong key, gone agent, outage) must reach
 * the caller as itself, with exactly the NACKs the ruling allows.
 *
 * Three config dirs keep the three agents on separate devices, so B can only
 * learn C's leaf key through the chain-verified key read.
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

import { mlsAck, mlsNack } from "../src/crypto/mls-api.js";
import { MLS_ERR_PEER_NOT_ADMITTED } from "../src/crypto/mls-errors.js";
import { syncMlsGroup } from "../src/mls-ops.js";
import {
	A_ID,
	B_ID,
	C_ID,
	type CKeys,
	GROUP_ID,
	groupOf,
	scene,
	setUpScene,
	tearDownScene,
} from "./mls-admission-scene.js";

beforeEach(() => setUpScene({ removeC: true }));
afterEach(tearDownScene);

describe("a member that missed an Add and the Remove behind it", () => {
	it("test_sync_when_two_epochs_were_missed_then_it_catches_up_without_a_nack_and_reads_the_next_message", async () => {
		const result = await syncMlsGroup(scene.dirB, B_ID, GROUP_ID, scene.client);

		expect(result).toMatchObject({ epoch: 3, processed: 2, evicted: false });
		expect(mlsNack).not.toHaveBeenCalled();
		expect(mlsAck).toHaveBeenCalledTimes(2);
		const envelope = new TextEncoder().encode("after the churn");
		const sealed = groupOf(scene.dirA, A_ID).encryptApplicationMessage(envelope);
		expect(groupOf(scene.dirB, B_ID).decryptApplicationMessage(sealed).envelope).toEqual(envelope);
	});

	it("test_sync_when_the_added_peer_is_still_on_the_roster_then_it_makes_no_extra_key_read", async () => {
		scene.roster = [A_ID, B_ID, C_ID];
		await syncMlsGroup(scene.dirB, B_ID, GROUP_ID, scene.client);

		expect(scene.keyReads).toHaveLength(1);
		expect(mlsNack).not.toHaveBeenCalled();
	});

	it.each<[string, CKeys]>([
		["its_chain_does_not_verify", "tampered"],
		["its_published_key_is_not_the_leaf_key", "foreign"],
		["the_agent_is_gone", "absent"],
	])("test_sync_when_%s_then_it_is_nacked_once_and_the_typed_refusal_reaches_the_caller", async (_name, mode) => {
		scene.cKeys = mode;

		await expect(syncMlsGroup(scene.dirB, B_ID, GROUP_ID, scene.client)).rejects.toMatchObject({
			code: MLS_ERR_PEER_NOT_ADMITTED,
		});

		expect(mlsNack).toHaveBeenCalledTimes(1);
		expect(mlsAck).not.toHaveBeenCalled();
		// The retry is bounded: one read for the roster, one for the named peer.
		expect(scene.keyReads.filter((ids) => ids.includes(C_ID))).toHaveLength(1);
		expect(groupOf(scene.dirB, B_ID).epoch()).toBe(1);
	});

	it("test_sync_when_the_key_read_has_an_outage_then_the_outage_surfaces_and_nothing_is_nacked", async () => {
		scene.cKeys = "outage";

		await expect(syncMlsGroup(scene.dirB, B_ID, GROUP_ID, scene.client)).rejects.toMatchObject({
			status: 503,
		});

		expect(mlsNack).not.toHaveBeenCalled();
		expect(groupOf(scene.dirB, B_ID).epoch()).toBe(1);
	});
});
