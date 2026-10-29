/**
 * The per-fork gap marker: a marker names the epoch alone when the loss is the
 * epoch's, or the epoch and the fork whose bytes were dropped. A marker is only
 * ever written once, and reading an epoch accepts any of its markers.
 */
import { bytesToHex } from "@noble/curves/utils.js";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	EscrowLoss,
	clearGap,
	giveUpPending,
	writeGap,
} from "../src/mls-escrow-gap.js";
import { readGap } from "../src/mls-escrow-markers.js";
import { groupPendingDir, writePending } from "../src/mls-escrow-pending.js";

/** A fingerprint no marker is filed under, so a read sees only fork-less markers. */
const NO_FORK_FP = new Uint8Array(16);

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP = "c3d4e5f6-a7b8-9012-cdef-123456789012";

const fpA = new Uint8Array(16).fill(7);
const fpB = new Uint8Array(16).fill(9);

let dir: string;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-fork-gaps-"));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

function markerPath(epoch: number, fp?: Uint8Array): string {
	const name = fp === undefined ? `${epoch}.gap` : `${epoch}-${bytesToHex(fp)}.gap`;
	return join(groupPendingDir(dir, AGENT, GROUP), name);
}

describe("writeGap", () => {
	it("test_write_gap_when_a_fork_is_given_then_the_marker_is_named_for_the_epoch_and_the_fork", () => {
		writeGap(dir, AGENT, GROUP, { epoch: 4, reason: EscrowLoss.Refused }, fpA);

		expect(fs.existsSync(markerPath(4, fpA))).toBe(true);
		expect(fs.existsSync(markerPath(4))).toBe(false);
	});

	it("test_write_gap_when_the_same_marker_is_written_twice_then_the_first_reason_stays", () => {
		writeGap(dir, AGENT, GROUP, { epoch: 4, reason: EscrowLoss.Refused }, fpA);
		writeGap(dir, AGENT, GROUP, { epoch: 4, reason: EscrowLoss.Unreadable }, fpA);

		expect(readGap(dir, AGENT, GROUP, 4, fpA)).toBe(EscrowLoss.Refused);
	});
});

describe("readGap", () => {
	it("test_read_gap_when_only_another_fork_has_a_marker_at_the_epoch_then_the_epoch_reads_no_gap", () => {
		writeGap(dir, AGENT, GROUP, { epoch: 4, reason: EscrowLoss.BranchRevoked }, fpB);

		expect(readGap(dir, AGENT, GROUP, 4, fpA)).toBeUndefined();
		expect(readGap(dir, AGENT, GROUP, 4, fpB)).toBe(EscrowLoss.BranchRevoked);
		expect(readGap(dir, AGENT, GROUP, 4, NO_FORK_FP)).toBeUndefined();
	});

	it("test_write_gap_when_a_marker_exists_with_the_old_fork_less_name_then_read_gap_still_reads_it", () => {
		fs.mkdirSync(groupPendingDir(dir, AGENT, GROUP), { recursive: true });
		fs.writeFileSync(markerPath(4), EscrowLoss.Refused);

		expect(readGap(dir, AGENT, GROUP, 4, NO_FORK_FP)).toBe(EscrowLoss.Refused);
	});
});

describe("clearGap", () => {
	it("test_clear_gap_when_a_fork_is_stored_then_only_its_marker_goes", () => {
		writeGap(dir, AGENT, GROUP, { epoch: 4, reason: EscrowLoss.Refused }, fpA);
		writeGap(dir, AGENT, GROUP, { epoch: 4, reason: EscrowLoss.Unreadable }, fpB);

		clearGap(dir, AGENT, GROUP, 4, fpA);

		expect(fs.existsSync(markerPath(4, fpA))).toBe(false);
		expect(fs.existsSync(markerPath(4, fpB))).toBe(true);
		expect(readGap(dir, AGENT, GROUP, 4, fpB)).toBe(EscrowLoss.Unreadable);
	});
});

describe("giveUpPending", () => {
	it("test_give_up_pending_when_a_fork_is_lost_then_the_marker_carries_that_forks_name", () => {
		const pending = {
			groupId: GROUP,
			epoch: 4,
			fp: fpA,
			sealed: new Uint8Array([1, 2, 3]),
		};
		writePending(dir, AGENT, pending);

		giveUpPending(dir, AGENT, pending, EscrowLoss.Refused);

		expect(fs.existsSync(markerPath(4, fpA))).toBe(true);
		expect(readGap(dir, AGENT, GROUP, 4, fpA)).toBe(EscrowLoss.Refused);
	});

	it("test_give_up_pending_when_the_marker_already_holds_a_reason_then_the_gap_reports_that_reason", () => {
		const pending = {
			groupId: GROUP,
			epoch: 4,
			fp: fpA,
			sealed: new Uint8Array([1, 2, 3]),
		};
		writePending(dir, AGENT, pending);
		giveUpPending(dir, AGENT, pending, EscrowLoss.Refused);
		writePending(dir, AGENT, pending);

		const gap = giveUpPending(dir, AGENT, pending, EscrowLoss.BranchRevoked);

		expect(gap).toEqual({ epoch: 4, reason: EscrowLoss.Refused });
		expect(readGap(dir, AGENT, GROUP, 4, fpA)).toBe(EscrowLoss.Refused);
	});
});
