/**
 * The queued-range sidecar: the epochs a parked snapshot was holding, recorded
 * beside it so a snapshot that can never be reopened still names them.
 *
 * A snapshot's own epoch is only the last of the epochs it held, so the sidecar
 * carries the count and the range is derived from it. The sidecar is advisory:
 * when it is absent or malformed, the lost epochs fall back to every epoch after
 * the group's escrow head, through the snapshot's epoch. These tests drive the
 * sidecar through its public exports, writing the snapshot file by hand because
 * parking one needs a real group state file.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { writeHead } from "../src/mls-escrow-head.js";
import {
	lostEpochs,
	MAX_DROPPED_EPOCHS,
	MAX_QUEUED_EXPORTS,
	recordedForks,
	writeQueued,
} from "../src/mls-escrow-queued.js";
import { backlogRoot, deleteSnapshot } from "../src/mls-escrow-snapshots.js";

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const FP = new Uint8Array(16).fill(7);

let dir: string;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-queued-"));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

/** The path of a parked snapshot of the group, with the file written by hand. */
function snapshot(name: string): string {
	const group = join(backlogRoot(dir, AGENT), GROUP);
	fs.mkdirSync(group, { recursive: true });
	const path = join(group, name);
	fs.writeFileSync(path, "state");
	return path;
}

/** The sidecar path beside a snapshot path. */
function sidecar(path: string): string {
	return `${path.replace(/\.snapshot$/, "")}.queued`;
}

describe("the native queue's caps", () => {
	it("test_caps_when_read_then_they_equal_the_native_cores", () => {
		// The vendored mls-rs `MAX_QUEUED_EPOCH_READ_EXPORTS` and
		// `MAX_DROPPED_EPOCH_READ_EPOCHS`; the Python twin carries the same two.
		expect(MAX_QUEUED_EXPORTS).toBe(32);
		expect(MAX_DROPPED_EPOCHS).toBe(1024);
	});
});

describe("lostEpochs", () => {
	it("test_lost_epochs_when_a_sidecar_records_the_range_then_the_whole_range_is_named", () => {
		const path = snapshot("41.snapshot");
		writeQueued(path, 41, 3, 0);

		expect(lostEpochs(dir, AGENT, GROUP, path, 41)).toEqual([39, 40, 41]);
	});

	it("test_lost_epochs_when_the_sidecar_records_no_queued_exports_then_the_snapshot_epoch_is_named", () => {
		const path = snapshot("41.snapshot");
		writeQueued(path, 41, 0, 0);

		expect(lostEpochs(dir, AGENT, GROUP, path, 41)).toEqual([41]);
	});

	it("test_lost_epochs_when_the_range_would_start_below_zero_then_it_is_clamped", () => {
		const path = snapshot("1.snapshot");
		writeQueued(path, 1, 5, 0);

		expect(lostEpochs(dir, AGENT, GROUP, path, 1)).toEqual([0, 1]);
	});

	it("test_lost_epochs_when_there_is_no_sidecar_and_no_head_then_the_snapshot_epoch_is_named", () => {
		const path = snapshot("41.snapshot");

		expect(lostEpochs(dir, AGENT, GROUP, path, 41)).toEqual([41]);
	});

	it("test_lost_epochs_when_there_is_no_sidecar_and_a_head_before_the_snapshot_then_the_epochs_after_it_are_named", () => {
		const path = snapshot("41.snapshot");
		writeHead(dir, AGENT, GROUP, { epoch: 38, fp: FP });

		expect(lostEpochs(dir, AGENT, GROUP, path, 41)).toEqual([39, 40, 41]);
	});

	it("test_lost_epochs_when_there_is_no_sidecar_and_a_head_past_the_snapshot_then_the_last_export_queue_is_named", () => {
		const path = snapshot("41.snapshot");
		writeHead(dir, AGENT, GROUP, { epoch: 45, fp: FP });

		const epochs = lostEpochs(dir, AGENT, GROUP, path, 41);

		expect(epochs).toHaveLength(MAX_QUEUED_EXPORTS);
		expect(epochs[0]).toBe(41 - MAX_QUEUED_EXPORTS + 1);
		expect(epochs.at(-1)).toBe(41);
	});

	it("test_lost_epochs_when_there_is_no_sidecar_and_a_head_far_behind_then_the_range_is_capped", () => {
		const path = snapshot("5000.snapshot");
		writeHead(dir, AGENT, GROUP, { epoch: 2, fp: FP });

		const epochs = lostEpochs(dir, AGENT, GROUP, path, 5000);

		expect(epochs).toHaveLength(MAX_QUEUED_EXPORTS + MAX_DROPPED_EPOCHS);
		expect(epochs.at(-1)).toBe(5000);
	});

	it("test_lost_epochs_when_the_queue_had_dropped_epochs_then_the_dropped_run_is_named_below_the_queued_ones", () => {
		const path = snapshot("100.snapshot");
		writeQueued(path, 100, MAX_QUEUED_EXPORTS, 8);

		const epochs = lostEpochs(dir, AGENT, GROUP, path, 100);

		expect(epochs).toHaveLength(MAX_QUEUED_EXPORTS + 8);
		expect(epochs[0]).toBe(100 - MAX_QUEUED_EXPORTS - 8 + 1);
		expect(epochs.at(-1)).toBe(100);
	});

	it("test_lost_epochs_when_the_sidecar_belongs_to_another_epoch_then_it_is_ignored", () => {
		const path = snapshot("41.snapshot");
		writeQueued(path, 40, 3, 0);

		expect(lostEpochs(dir, AGENT, GROUP, path, 41)).toEqual([41]);
	});

	it.each([
		["queued above the native cap", { epoch: 41, queued: MAX_QUEUED_EXPORTS + 1, dropped: 0 }],
		["dropped above the native cap", { epoch: 41, queued: 3, dropped: MAX_DROPPED_EPOCHS + 1 }],
		["an astronomic range", { epoch: 41, queued: 1e9, dropped: 1e9 }],
	])("test_lost_epochs_when_the_sidecar_has_%s_then_it_is_ignored", (_label, body) => {
		const path = snapshot("41.snapshot");
		fs.writeFileSync(sidecar(path), JSON.stringify(body));

		expect(lostEpochs(dir, AGENT, GROUP, path, 41)).toEqual([41]);
	});

	it("test_lost_epochs_when_the_sidecar_predates_the_dropped_count_then_none_were_dropped", () => {
		const path = snapshot("41.snapshot");
		fs.writeFileSync(sidecar(path), '{"epoch": 41, "queued": 3}');

		expect(lostEpochs(dir, AGENT, GROUP, path, 41)).toEqual([39, 40, 41]);
	});

	it.each([
		["not JSON", "not json at all"],
		["a JSON array", "[]"],
		["a negative epoch", '{"epoch": -1, "queued": 2}'],
		["a string epoch", '{"epoch": "41", "queued": 2}'],
		["a boolean queued", '{"epoch": 41, "queued": true}'],
	])("test_lost_epochs_when_the_sidecar_is_%s_then_it_falls_back_like_no_sidecar", (_label, body) => {
		const path = snapshot("41.snapshot");
		fs.writeFileSync(sidecar(path), body);

		expect(lostEpochs(dir, AGENT, GROUP, path, 41)).toEqual([41]);
	});
});

describe("the sidecar on disk", () => {
	it("test_delete_snapshot_when_it_has_a_sidecar_then_the_sidecar_goes_too", () => {
		const path = snapshot("41.snapshot");
		writeQueued(path, 41, 3, 0);

		deleteSnapshot({ groupId: GROUP, epoch: 41, path });

		expect(fs.existsSync(path)).toBe(false);
		expect(fs.existsSync(sidecar(path))).toBe(false);
	});

	it("test_write_queued_when_it_records_a_range_then_the_body_and_name_are_pinned", () => {
		const plain = snapshot("41.snapshot");
		const named = snapshot("41-ab12cd34.snapshot");

		writeQueued(plain, 41, 3, 0);
		writeQueued(named, 41, 3, 0);

		expect(JSON.parse(fs.readFileSync(sidecar(plain), "utf-8"))).toEqual({
			epoch: 41,
			queued: 3,
			dropped: 0,
		});
		expect(fs.existsSync(join(backlogRoot(dir, AGENT), GROUP, "41.queued"))).toBe(true);
		expect(fs.existsSync(join(backlogRoot(dir, AGENT), GROUP, "41-ab12cd34.queued"))).toBe(
			true,
		);
	});
});

describe("the forks a sidecar records", () => {
	const FP_B = new Uint8Array(16).fill(9);

	it("test_recorded_forks_when_forks_were_written_then_they_round_trip_by_epoch", () => {
		const path = snapshot("41.snapshot");
		writeQueued(path, 41, 3, 0, new Map([[40, FP_B], [39, FP]]));

		expect(recordedForks(path, 41)).toEqual(new Map([[39, FP], [40, FP_B]]));
	});

	it("test_write_queued_when_forks_are_given_then_the_keys_ascend_and_the_values_are_hex", () => {
		const path = snapshot("41.snapshot");
		writeQueued(path, 41, 3, 0, new Map([[41, FP_B], [39, FP]]));

		expect(fs.readFileSync(sidecar(path), "utf-8")).toBe(
			`{"epoch":41,"queued":3,"dropped":0,"fps":{"39":"${"07".repeat(16)}","41":"${"09".repeat(16)}"}}`,
		);
	});

	it("test_write_queued_when_no_fork_is_given_then_the_sidecar_has_no_fps_key", () => {
		const path = snapshot("41.snapshot");
		writeQueued(path, 41, 3, 8);

		expect(fs.readFileSync(sidecar(path), "utf-8")).toBe('{"epoch":41,"queued":3,"dropped":8}');
		expect(recordedForks(path, 41).size).toBe(0);
	});

	it("test_recorded_forks_when_an_entry_is_malformed_or_out_of_range_then_only_that_entry_is_ignored", () => {
		const path = snapshot("41.snapshot");
		const good = "07".repeat(16);
		fs.writeFileSync(
			sidecar(path),
			JSON.stringify({
				epoch: 41,
				queued: 3,
				dropped: 0,
				fps: { "40": good, "42": good, "-1": good, x: good, "39": "zz", "38": "AB".repeat(16), "37": "07" },
			}),
		);

		expect(recordedForks(path, 41)).toEqual(new Map([[40, FP]]));
	});

	it("test_recorded_forks_when_the_sidecar_is_for_another_epoch_then_none_are_trusted", () => {
		const path = snapshot("41.snapshot");
		writeQueued(path, 40, 3, 0, new Map([[39, FP]]));

		expect(recordedForks(path, 41).size).toBe(0);
	});
});
