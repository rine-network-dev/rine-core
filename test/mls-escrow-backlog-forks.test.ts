/**
 * Giving up a parked snapshot: the gap markers it files, one per fork.
 *
 * A snapshot that cannot be reopened is known only by the range recorded when it
 * was parked, so its markers name no fork. A snapshot that reopens yields its
 * exports, each with the fork it belongs to, so each lost epoch is filed under
 * that fork's name. A marker is written once: a later give-up for the same epoch
 * leaves the first reason in place.
 */
import { hexToBytes } from "@noble/curves/utils.js";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { saveAgentKeys } from "../src/crypto/keys.js";
import { generateAgentKeys } from "./helpers/keys.js";
import { mlsGroupIdBytes, openMlsClient } from "../src/crypto/mls.js";
import { giveUpSnapshots } from "../src/mls-escrow-backlog.js";
import { EscrowLoss } from "../src/mls-escrow-gap.js";
import { readGap } from "../src/mls-escrow-markers.js";
import { groupPendingDir } from "../src/mls-escrow-pending.js";
import { writeQueued } from "../src/mls-escrow-queued.js";
import {
	backlogRoot,
	listSnapshots,
	parkSnapshot,
} from "../src/mls-escrow-snapshots.js";

/** A fingerprint no marker is filed under, so a read sees only fork-less markers. */
const NO_FORK_FP = new Uint8Array(16);

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const PEER = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

let dir: string;
let actor: { configDir: string; agentId: string; client: never };

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-backlog-forks-"));
	saveAgentKeys(dir, AGENT, generateAgentKeys());
	saveAgentKeys(dir, PEER, generateAgentKeys());
	actor = { configDir: dir, agentId: AGENT, client: {} as never };
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

/** A parked snapshot whose bytes the native core cannot read, with a sidecar naming its range. */
function unreadableSnapshot(
	name: string,
	epoch: number,
	queued: number,
	groupId = GROUP_ID,
	forks: ReadonlyMap<number, Uint8Array> = new Map(),
): string {
	const group = join(backlogRoot(dir, AGENT), groupId);
	fs.mkdirSync(group, { recursive: true });
	const path = join(group, name);
	fs.writeFileSync(path, "not a group state");
	writeQueued(path, epoch, queued, 0, forks);
	return path;
}

/** The marker file names of the group's pending dir, sorted. */
function markerNames(): string[] {
	return fs.readdirSync(groupPendingDir(dir, AGENT, GROUP_ID)).sort();
}

describe("giveUpSnapshots", () => {
	it("test_give_up_when_a_snapshot_cannot_be_reopened_then_a_fork_less_marker_is_filed_for_every_epoch_it_held", () => {
		const path = unreadableSnapshot("41.snapshot", 41, 3);

		const result = giveUpSnapshots(actor, EscrowLoss.Unreadable);

		expect(result.gaps).toEqual(
			[39, 40, 41].map((epoch) => ({
				groupId: GROUP_ID,
				gap: { epoch, reason: EscrowLoss.Unreadable },
			})),
		);
		expect(markerNames()).toEqual(["39.gap", "40.gap", "41.gap"]);
		for (const epoch of [39, 40, 41]) {
			expect(readGap(dir, AGENT, GROUP_ID, epoch, NO_FORK_FP)).toBe(EscrowLoss.Unreadable);
		}
		expect(fs.existsSync(path)).toBe(false);
		expect(fs.existsSync(path.replace(/\.snapshot$/, ".queued"))).toBe(false);
		expect(listSnapshots(dir, AGENT)).toEqual([]);
	});

	it("test_give_up_when_an_unreadable_snapshot_recorded_its_forks_then_each_marker_names_its_fork", () => {
		const fpA = new Uint8Array(16).fill(7);
		const fpB = new Uint8Array(16).fill(9);
		unreadableSnapshot("41.snapshot", 41, 3, GROUP_ID, new Map([[39, fpA], [40, fpB]]));

		const result = giveUpSnapshots(actor, EscrowLoss.Unreadable);

		expect(markerNames()).toEqual([`39-${"07".repeat(16)}.gap`, `40-${"09".repeat(16)}.gap`, "41.gap"]);
		expect(result.gaps.map(({ gap }) => [gap.epoch, gap.fp])).toEqual([
			[39, fpA],
			[40, fpB],
			[41, undefined],
		]);
		// A fork the snapshot never held is not blocked at those epochs.
		expect(readGap(dir, AGENT, GROUP_ID, 39, fpB)).toBeUndefined();
		expect(readGap(dir, AGENT, GROUP_ID, 39, fpA)).toBe(EscrowLoss.Unreadable);
	});

	it("test_give_up_when_a_snapshot_reopens_then_each_export_files_a_marker_naming_its_fork", () => {
		const pkg = openMlsClient(dir, PEER).generateKeyPackage();
		openMlsClient(dir, AGENT)
			.createGroupWithMembers(mlsGroupIdBytes(GROUP_ID), [pkg])
			.save();
		parkSnapshot(dir, AGENT, GROUP_ID, 1, 2, 0);

		const result = giveUpSnapshots(actor, EscrowLoss.BranchRevoked);

		expect(result.gaps.map(({ gap }) => gap.epoch)).toEqual([0, 1]);
		expect(
			result.gaps.every(({ groupId, gap }) => {
				return groupId === GROUP_ID && gap.reason === EscrowLoss.BranchRevoked;
			}),
		).toBe(true);
		const names = markerNames();
		expect(names).toHaveLength(2);
		expect(names[0]).toMatch(/^0-[0-9a-f]{32}\.gap$/);
		expect(names[1]).toMatch(/^1-[0-9a-f]{32}\.gap$/);
		for (const [epoch, name] of names.entries()) {
			const fp = hexToBytes(name.slice(`${epoch}-`.length, -".gap".length));
			expect(readGap(dir, AGENT, GROUP_ID, epoch, fp)).toBe(EscrowLoss.BranchRevoked);
		}
		expect(listSnapshots(dir, AGENT)).toEqual([]);
	});

	it("test_give_up_when_a_marker_already_exists_then_a_later_loss_leaves_the_first_reason", () => {
		unreadableSnapshot("41.snapshot", 41, 3);
		giveUpSnapshots(actor, EscrowLoss.Unreadable);
		unreadableSnapshot("41-abcd1234.snapshot", 41, 3);

		giveUpSnapshots(actor, EscrowLoss.BranchRevoked);

		expect(readGap(dir, AGENT, GROUP_ID, 41, NO_FORK_FP)).toBe(EscrowLoss.Unreadable);
		expect(markerNames()).toEqual(["39.gap", "40.gap", "41.gap"]);
	});

	it("test_give_up_when_two_groups_lost_the_same_epoch_then_each_group_reports_it", () => {
		const other = "d4e5f6a7-b8c9-0123-def0-234567890123";
		unreadableSnapshot("7.snapshot", 7, 0);
		unreadableSnapshot("7.snapshot", 7, 0, other);

		const result = giveUpSnapshots(actor, EscrowLoss.BranchRevoked);

		expect(result.gaps.map(({ groupId }) => groupId).sort()).toEqual([GROUP_ID, other].sort());
	});
});
