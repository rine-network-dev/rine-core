/**
 * The escrow files on disk, pinned to golden bytes shared with the Python SDK:
 * every gap marker reason, a fork-less and a fork-named marker, a second group,
 * the files that sit beside markers without being one, the queued-range sidecar
 * beside a parked snapshot and a corrupt one, and a sidecar that records the fork
 * of each queued epoch. The Python suite reads
 * this same directory and asserts the same two things, so a drift in either
 * stack's writer or reader shows in that stack's own suite: each golden must
 * parse to what `manifest.json` says, and writing it back must reproduce the
 * golden's name and bytes.
 */
import * as mls from "@rine-network/mls";
import { hexToBytes } from "@noble/curves/utils.js";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listGapMarkers } from "../src/mls-escrow-gap-list.js";
import { EscrowLoss, type GapReason, writeGap } from "../src/mls-escrow-gap.js";
import { readGap } from "../src/mls-escrow-markers.js";
import { groupPendingDir } from "../src/mls-escrow-pending.js";
import { lostEpochs, recordedForks, writeQueued } from "../src/mls-escrow-queued.js";
import { backlogRoot } from "../src/mls-escrow-snapshots.js";

/** A fingerprint no marker is filed under, so a read sees only fork-less markers. */
const NO_FORK_FP = new Uint8Array(16);

const GOLDEN = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "escrow-disk");
const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP = "c3d4e5f6-a7b8-9012-cdef-123456789012";

interface MarkerGolden {
	name: string;
	epoch: number;
	fork?: string;
	reason: GapReason;
}
interface SidecarGolden {
	snapshot: string;
	sidecar: string;
	epoch: number;
	queued?: number;
	dropped?: number;
	corrupt?: boolean;
	firstLost: number;
	lastLost: number;
}
const manifest = JSON.parse(
	fs.readFileSync(join(GOLDEN, "manifest.json"), "utf-8"),
) as {
	markers: MarkerGolden[];
	otherGroup: { id: string; markers: MarkerGolden[] };
	stray: string[];
	sidecars: SidecarGolden[];
	forkSidecars: (SidecarGolden & { fps: Record<string, string> })[];
};

let dir: string;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-golden-"));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

/** Copy a golden directory into the place the stack keeps those files. */
function install(from: string, to: string): void {
	fs.mkdirSync(to, { recursive: true });
	for (const name of fs.readdirSync(join(GOLDEN, from))) {
		fs.copyFileSync(join(GOLDEN, from, name), join(to, name));
	}
}

const range = (first: number, last: number): number[] =>
	Array.from({ length: last - first + 1 }, (_, index) => first + index);

/** The stray files, which share the group's dir with the markers and are not markers. */
function installStray(): void {
	install("pending", groupPendingDir(dir, AGENT, GROUP));
	install("stray", groupPendingDir(dir, AGENT, GROUP));
}

describe("the gap markers", () => {
	it("test_manifest_when_read_then_it_names_exactly_the_golden_marker_files", () => {
		expect(manifest.markers.map((marker) => marker.name)).toEqual(
			fs.readdirSync(join(GOLDEN, "pending")).sort(),
		);
	});

	it("test_list_gap_markers_when_the_golden_markers_are_installed_then_each_parses_as_the_manifest_says", () => {
		install("pending", groupPendingDir(dir, AGENT, GROUP));

		expect(listGapMarkers(dir, AGENT)).toEqual(
			manifest.markers.map(({ epoch, fork, reason }) => ({
				agent_id: AGENT,
				group_id: GROUP,
				epoch,
				...(fork === undefined ? {} : { fork }),
				reason,
			})),
		);
	});

	it("test_manifest_when_read_then_it_names_exactly_the_stray_files_and_every_gap_reason", () => {
		expect([...manifest.stray].sort()).toEqual(fs.readdirSync(join(GOLDEN, "stray")).sort());
		const binding = (mls as unknown as { EscrowGapReason: Record<string, string> })
			.EscrowGapReason;
		const bindingReasons = Object.getOwnPropertyNames(binding).map((name) =>
			String(binding[name]),
		);

		expect(new Set(manifest.markers.map((marker) => marker.reason))).toEqual(
			new Set([...bindingReasons, ...Object.values(EscrowLoss)]),
		);
	});

	it("test_list_gap_markers_when_stray_files_and_a_second_group_are_installed_then_only_markers_are_listed_in_group_order", () => {
		installStray();
		install("pending-other", groupPendingDir(dir, AGENT, manifest.otherGroup.id));

		const listed = listGapMarkers(dir, AGENT).map(({ group_id, epoch, fork, reason }) => ({
			group_id,
			epoch,
			...(fork === undefined ? {} : { fork }),
			reason,
		}));

		expect(listed).toEqual([
			...manifest.otherGroup.markers.map(({ epoch, reason }) => ({
				group_id: manifest.otherGroup.id,
				epoch,
				reason,
			})),
			...manifest.markers.map(({ epoch, fork, reason }) => ({
				group_id: GROUP,
				epoch,
				...(fork === undefined ? {} : { fork }),
				reason,
			})),
		]);
	});

	it("test_read_gap_when_the_goldens_and_stray_files_are_installed_then_each_epoch_reads_its_manifest_reason", () => {
		installStray();

		for (const { epoch, fork, reason } of manifest.markers) {
			const fp = fork === undefined ? NO_FORK_FP : hexToBytes(fork);
			expect(readGap(dir, AGENT, GROUP, epoch, fp)).toBe(reason);
		}
		for (const epoch of [12, 13, 14, 15, 16, 1234567890123456]) {
			expect(readGap(dir, AGENT, GROUP, epoch, NO_FORK_FP)).toBeUndefined();
		}
	});

	it("test_read_gap_when_the_goldens_are_installed_then_a_fork_reads_only_its_own_and_fork_less_markers", () => {
		installStray();
		const foreign = new Uint8Array(16).fill(0x0c);

		for (const { epoch, fork, reason } of manifest.markers) {
			if (fork === undefined) {
				expect(readGap(dir, AGENT, GROUP, epoch, foreign)).toBe(reason);
			} else {
				expect(readGap(dir, AGENT, GROUP, epoch, foreign)).toBeUndefined();
				expect(readGap(dir, AGENT, GROUP, epoch, NO_FORK_FP)).toBeUndefined();
			}
		}
	});

	it("test_list_gap_markers_when_links_pipes_and_misnamed_dirs_are_planted_then_none_is_listed_or_followed", () => {
		installStray();
		const group = groupPendingDir(dir, AGENT, GROUP);
		const outside = join(dir, "outside.txt");
		fs.writeFileSync(outside, "refused");
		fs.symlinkSync(outside, join(group, "21.gap"));
		execFileSync("mkfifo", [join(group, "22.gap")]);
		fs.writeFileSync(join(group, "23.gap"), "refused".padEnd(4096, "x"));
		const root = join(group, "..");
		fs.mkdirSync(join(dir, "real"));
		fs.writeFileSync(join(dir, "real", "3.gap"), "refused");
		fs.symlinkSync(join(dir, "real"), join(root, manifest.otherGroup.id));
		for (const name of ["ABCDEFAB-0000-4000-8000-000000000000", "not-a-group"]) {
			install("pending-other", join(root, name));
		}

		const listed = listGapMarkers(dir, AGENT);

		expect(listed.map(({ group_id, epoch }) => `${group_id}:${epoch}`)).toEqual(
			manifest.markers.map(({ epoch }) => `${GROUP}:${epoch}`),
		);
	});

	it("test_write_gap_when_each_golden_marker_is_written_back_then_name_and_bytes_are_identical", () => {
		for (const { epoch, fork, reason } of manifest.markers) {
			writeGap(dir, AGENT, GROUP, { epoch, reason }, fork === undefined ? undefined : hexToBytes(fork));
		}

		const written = groupPendingDir(dir, AGENT, GROUP);

		expect(fs.readdirSync(written).sort()).toEqual(fs.readdirSync(join(GOLDEN, "pending")).sort());
		for (const name of fs.readdirSync(written)) {
			expect(fs.readFileSync(join(written, name))).toEqual(
				fs.readFileSync(join(GOLDEN, "pending", name)),
			);
		}
	});
});

describe("the queued-range sidecar", () => {
	it("test_manifest_when_read_then_it_names_exactly_the_golden_backlog_files", () => {
		const named = manifest.sidecars.flatMap((entry) => [entry.snapshot, entry.sidecar]);

		expect(named.sort()).toEqual(fs.readdirSync(join(GOLDEN, "backlog")).sort());
	});

	it("test_lost_epochs_when_the_golden_sidecars_are_installed_then_each_names_the_manifest_range", () => {
		const group = join(backlogRoot(dir, AGENT), GROUP);
		install("backlog", group);

		for (const entry of manifest.sidecars) {
			expect(lostEpochs(dir, AGENT, GROUP, join(group, entry.snapshot), entry.epoch)).toEqual(
				range(entry.firstLost, entry.lastLost),
			);
		}
	});

	it("test_write_queued_when_each_readable_golden_is_written_back_then_name_and_bytes_are_identical", () => {
		const group = join(backlogRoot(dir, AGENT), GROUP);
		fs.mkdirSync(group, { recursive: true });

		for (const entry of manifest.sidecars.filter((candidate) => !candidate.corrupt)) {
			writeQueued(join(group, entry.snapshot), entry.epoch, entry.queued ?? 0, entry.dropped ?? 0);

			expect(fs.readFileSync(join(group, entry.sidecar))).toEqual(
				fs.readFileSync(join(GOLDEN, "backlog", entry.sidecar)),
			);
		}
	});
});

describe("the queued-range sidecar with forks", () => {
	const forks = (fps: Record<string, string>) =>
		new Map(Object.entries(fps).map(([epoch, hex]) => [Number(epoch), hexToBytes(hex)]));

	it("test_manifest_when_read_then_it_names_exactly_the_golden_fork_backlog_files", () => {
		const named = manifest.forkSidecars.flatMap((entry) => [entry.snapshot, entry.sidecar]);

		expect(named.sort()).toEqual(fs.readdirSync(join(GOLDEN, "backlog-forks")).sort());
	});

	it("test_recorded_forks_when_the_golden_is_installed_then_it_names_the_manifest_forks_and_range", () => {
		const group = join(backlogRoot(dir, AGENT), GROUP);
		install("backlog-forks", group);

		for (const entry of manifest.forkSidecars) {
			const path = join(group, entry.snapshot);
			expect(recordedForks(path, entry.epoch)).toEqual(forks(entry.fps));
			expect(lostEpochs(dir, AGENT, GROUP, path, entry.epoch)).toEqual(
				range(entry.firstLost, entry.lastLost),
			);
		}
	});

	it("test_write_queued_when_the_fork_golden_is_written_back_then_name_and_bytes_are_identical", () => {
		const group = join(backlogRoot(dir, AGENT), GROUP);
		fs.mkdirSync(group, { recursive: true });

		for (const entry of manifest.forkSidecars) {
			writeQueued(
				join(group, entry.snapshot),
				entry.epoch,
				entry.queued ?? 0,
				entry.dropped ?? 0,
				forks(entry.fps),
			);

			expect(fs.readFileSync(join(group, entry.sidecar))).toEqual(
				fs.readFileSync(join(GOLDEN, "backlog-forks", entry.sidecar)),
			);
		}
	});
});
