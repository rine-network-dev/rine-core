/**
 * The parked-snapshot store's own rules, with no MLS core and no mocks.
 *
 * A group's stored state is just a file at `groupStatePath(...)`, so these tests
 * write small distinct byte strings there and drive the store through its public
 * exports. What is load-bearing:
 *
 * 1. A second state parked at an epoch that already has a snapshot is a
 *    DIFFERENT state (a resync and a rejoin can land on the same epoch number),
 *    so it takes a distinct name rather than replace the first.
 * 2. A parked snapshot has the protection a live one has: a 0600 file in a 0700
 *    dir, with no staged copy left behind.
 * 3. Deleting the last snapshot of a group removes the group dir; a sibling
 *    keeps it.
 * 4. A snapshot that cannot be processed is renamed out of the listing.
 * 5. Only scratch entries older than the stale window are cleared.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { groupStatePath } from "../src/crypto/mls-store-probe.js";
import {
	backlogRoot,
	clearScratch,
	deleteSnapshot,
	listSnapshots,
	parkSnapshot,
} from "../src/mls-escrow-snapshots.js";

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP_A = "c3d4e5f6-a7b8-9012-cdef-123456789012";

let root: string;
let dir: string;

beforeEach(() => {
	root = fs.mkdtempSync(join(tmpdir(), "rine-escrow-snapshots-"));
	dir = join(root, "config");
	fs.mkdirSync(dir);
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

/** Write the group's stored state — the file `parkSnapshot` copies from. */
function writeState(groupId: string, bytes: string): void {
	const path = groupStatePath(dir, AGENT, groupId);
	fs.mkdirSync(dirname(path), { recursive: true });
	fs.writeFileSync(path, bytes);
}

/** The dir one group's parked snapshots live in. */
function groupDir(groupId: string): string {
	return join(backlogRoot(dir, AGENT), groupId);
}

/** The bytes of every parked snapshot of one group, sorted by content. */
function parkedBytes(groupId: string): string[] {
	return fs
		.readdirSync(groupDir(groupId))
		.filter((name) => name.endsWith(".snapshot"))
		.map((name) => fs.readFileSync(join(groupDir(groupId), name), "utf-8"))
		.sort();
}

describe("the parked-snapshot store", () => {
	it("test_park_when_the_epoch_name_is_taken_then_the_second_state_gets_a_distinct_name_and_both_are_kept", () => {
		writeState(GROUP_A, "state-A");
		parkSnapshot(dir, AGENT, GROUP_A, 3, 0, 0);
		writeState(GROUP_A, "state-B");
		parkSnapshot(dir, AGENT, GROUP_A, 3, 0, 0);

		const listed = listSnapshots(dir, AGENT);

		expect(listed).toHaveLength(2);
		expect(listed.map((s) => s.epoch)).toEqual([3, 3]);
		expect(listed[0]?.path).not.toBe(listed[1]?.path);
		expect(parkedBytes(GROUP_A)).toEqual(["state-A", "state-B"]);
	});

	it("test_park_when_it_succeeds_then_the_snapshot_is_0600_in_a_0700_dir_and_no_staged_copy_remains", () => {
		writeState(GROUP_A, "state-A");
		parkSnapshot(dir, AGENT, GROUP_A, 3, 0, 0);

		const [snapshot] = listSnapshots(dir, AGENT);
		expect(snapshot).toBeDefined();
		expect(fs.statSync(snapshot!.path).mode & 0o777).toBe(0o600);
		expect(fs.statSync(groupDir(GROUP_A)).mode & 0o777).toBe(0o700);
		const names = fs.readdirSync(groupDir(GROUP_A));
		expect(names).toEqual(["3.queued", "3.snapshot"]);
		expect(names.some((name) => name.startsWith(".stage-"))).toBe(false);
	});

	it("test_park_when_exports_were_dropped_then_the_sidecar_records_the_dropped_count", () => {
		writeState(GROUP_A, "state-A");
		parkSnapshot(dir, AGENT, GROUP_A, 40, 32, 8);

		const sidecar = join(groupDir(GROUP_A), "40.queued");

		expect(JSON.parse(fs.readFileSync(sidecar, "utf-8"))).toEqual({
			epoch: 40,
			queued: 32,
			dropped: 8,
		});
	});

	it("test_list_when_a_group_dir_is_a_link_then_it_is_not_listed", () => {
		writeState(GROUP_A, "state-A");
		parkSnapshot(dir, AGENT, GROUP_A, 3, 0, 0);
		const moved = join(root, "moved");
		fs.renameSync(groupDir(GROUP_A), moved);
		fs.symlinkSync(moved, groupDir(GROUP_A));

		expect(listSnapshots(dir, AGENT)).toEqual([]);
	});

	it("test_park_when_the_stored_state_is_missing_then_it_throws_and_leaves_no_staged_copy", () => {
		expect(() => parkSnapshot(dir, AGENT, GROUP_A, 3, 0, 0)).toThrow();

		const names = fs.existsSync(groupDir(GROUP_A))
			? fs.readdirSync(groupDir(GROUP_A))
			: [];
		expect(names.some((name) => name.startsWith(".stage-"))).toBe(false);
		expect(listSnapshots(dir, AGENT)).toEqual([]);
	});

	it("test_delete_when_the_group_dir_is_then_empty_then_the_dir_is_removed_but_a_sibling_snapshot_keeps_it", () => {
		writeState(GROUP_A, "state-A");
		parkSnapshot(dir, AGENT, GROUP_A, 3, 0, 0);
		writeState(GROUP_A, "state-B");
		parkSnapshot(dir, AGENT, GROUP_A, 4, 0, 0);
		const [first, second] = listSnapshots(dir, AGENT);
		expect(first).toBeDefined();
		expect(second).toBeDefined();

		deleteSnapshot(first!);

		expect(fs.existsSync(groupDir(GROUP_A))).toBe(true);
		expect(listSnapshots(dir, AGENT).map((s) => s.path)).toEqual([second!.path]);

		deleteSnapshot(second!);

		expect(fs.existsSync(groupDir(GROUP_A))).toBe(false);
		expect(listSnapshots(dir, AGENT)).toEqual([]);
	});

	it("test_clear_scratch_when_entries_are_stale_then_only_the_stale_ones_are_removed", () => {
		const rootDir = backlogRoot(dir, AGENT);
		const group = groupDir(GROUP_A);
		fs.mkdirSync(group, { recursive: true });
		const old = Date.now() / 1000 - 2 * 60 * 60;
		const stale = [
			join(rootDir, ".open-old"),
			join(rootDir, ".stage-old"),
			join(group, ".open-old"),
			join(group, ".stage-old"),
		];
		const fresh = [
			join(rootDir, ".open-fresh"),
			join(rootDir, ".stage-fresh"),
			join(group, ".open-fresh"),
			join(group, ".stage-fresh"),
		];
		for (const path of [...stale, ...fresh]) {
			if (path.includes(".open-")) fs.mkdirSync(path);
			else fs.writeFileSync(path, "scratch");
		}
		for (const path of stale) fs.utimesSync(path, old, old);
		const snapshot = join(group, "3.snapshot");
		fs.writeFileSync(snapshot, "state-A");

		clearScratch(dir, AGENT, Date.now() / 1000);

		for (const path of stale) expect(fs.existsSync(path)).toBe(false);
		for (const path of fresh) expect(fs.existsSync(path)).toBe(true);
		expect(fs.readFileSync(snapshot, "utf-8")).toBe("state-A");
	});
});
