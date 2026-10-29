/**
 * The gap marker: the reason an installed epoch has no escrow, kept on disk
 * beside the group's pending files. A marker holding text that is not a reason
 * must read as no marker rather than reach a typed error.
 */
import * as mls from "@rine-network/mls";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { EscrowLoss, giveUpPending, writeGap } from "../src/mls-escrow-gap.js";
import { readGap } from "../src/mls-escrow-markers.js";
import { readHead, writeHead } from "../src/mls-escrow-head.js";
import { groupPendingDir, listPending, writePending } from "../src/mls-escrow-pending.js";

/** A fingerprint no marker is filed under, so a read sees only fork-less markers. */
const NO_FORK_FP = new Uint8Array(16);

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP = "c3d4e5f6-a7b8-9012-cdef-123456789012";

/** The binding's own runtime enum: its members are non-enumerable, so read them by name. */
const BINDING = (mls as unknown as { EscrowGapReason: Record<string, string> })
	.EscrowGapReason;

let dir: string;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-gap-"));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("readGap", () => {
	const reasons = Object.getOwnPropertyNames(BINDING).map((name) => BINDING[name] as string);

	it("test_read_gap_when_the_binding_defines_reasons_then_there_are_some", () => {
		expect(reasons.length).toBeGreaterThan(0);
	});

	it.each(reasons)("test_read_gap_when_the_marker_holds_%s_then_it_reads_it_back", (reason) => {
		writeGap(dir, AGENT, GROUP, { epoch: 4, reason: reason as mls.EscrowGapReason });

		expect(readGap(dir, AGENT, GROUP, 4, NO_FORK_FP)).toBe(reason);
	});

	it("test_read_gap_when_the_marker_holds_text_that_is_not_a_reason_then_it_reads_as_no_gap", () => {
		fs.mkdirSync(groupPendingDir(dir, AGENT, GROUP), { recursive: true });
		fs.writeFileSync(join(groupPendingDir(dir, AGENT, GROUP), "4.gap"), "totally_made_up");

		expect(readGap(dir, AGENT, GROUP, 4, NO_FORK_FP)).toBeUndefined();
	});

	it("test_read_gap_when_no_marker_exists_then_it_is_undefined", () => {
		expect(readGap(dir, AGENT, GROUP, 9, NO_FORK_FP)).toBeUndefined();
	});
});

describe("giveUpPending", () => {
	const fp = new Uint8Array(16).fill(7);
	const otherFp = new Uint8Array(16).fill(9);
	const pending = (forkFp: Uint8Array) => ({
		groupId: GROUP,
		epoch: 4,
		fp: forkFp,
		sealed: new Uint8Array([1, 2, 3]),
	});

	it("test_give_up_pending_when_the_head_names_the_escrow_then_the_head_is_forgotten", () => {
		writePending(dir, AGENT, pending(fp));
		writeHead(dir, AGENT, GROUP, { epoch: 4, fp });

		giveUpPending(dir, AGENT, pending(fp), EscrowLoss.Refused);

		expect(readHead(dir, AGENT, GROUP)).toBeUndefined();
		expect(readGap(dir, AGENT, GROUP, 4, fp)).toBe(EscrowLoss.Refused);
		expect(listPending(dir, AGENT, GROUP)).toEqual([]);
	});

	it("test_give_up_pending_when_the_head_names_another_fork_then_the_head_stays", () => {
		writePending(dir, AGENT, pending(fp));
		writeHead(dir, AGENT, GROUP, { epoch: 4, fp: otherFp });

		giveUpPending(dir, AGENT, pending(fp), EscrowLoss.Refused);

		expect(readHead(dir, AGENT, GROUP)?.fp).toEqual(otherFp);
	});
});
