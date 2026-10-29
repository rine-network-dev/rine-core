/**
 * The pending-escrow store's own rules.
 *
 * Three of them are load-bearing and none is about MLS:
 *
 * 1. The file holds the sealed bytes ALONE. The uploader signature is not
 *    stored, because the server answers 422 for a `key_gen` that is not the
 *    uploader's current one — a signature kept across a rotation would make the
 *    file permanently unuploadable.
 * 2. A write is idempotent: the bytes are the only copy of that epoch's
 *    secrets, so re-writing an identical file must not move its mtime.
 * 3. The head never moves to a lower epoch, because a stale drain finishing
 *    after a newer one must not rewind the fp a sender reads.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mlsStoreRoot } from "../src/crypto/mls.js";
import { readHead, writeHead } from "../src/mls-escrow-head.js";
import {
	type PendingEscrow,
	deletePending,
	listPending,
	pendingGroupIds,
	writePending,
} from "../src/mls-escrow-pending.js";

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP_A = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const GROUP_B = "d4e5f6a7-b8c9-0123-def1-234567890123";

let root: string;
let dir: string;

beforeEach(() => {
	root = fs.mkdtempSync(join(tmpdir(), "rine-escrow-pending-"));
	dir = join(root, "config");
	fs.mkdirSync(dir);
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

/** A 16-byte fork fingerprint whose bytes are all `byte`. */
function fp(byte: number): Uint8Array {
	return new Uint8Array(16).fill(byte);
}

/** A pending escrow for `groupId` at `epoch`, with distinguishable bytes. */
function pending(
	groupId: string,
	epoch: number,
	byte: number,
): PendingEscrow {
	return {
		groupId,
		epoch,
		fp: fp(byte),
		sealed: new Uint8Array([byte, byte + 1, byte + 2]),
	};
}

/** The dir one group's pending escrows live in. */
function groupDir(groupId: string): string {
	return join(mlsStoreRoot(dir, AGENT), "escrow-pending", groupId);
}

/** The head record path for one group. */
function headFile(groupId: string): string {
	return join(mlsStoreRoot(dir, AGENT), "escrow-head", `${groupId}.json`);
}

describe("the pending-escrow store", () => {
	it("test_write_pending_then_list_returns_sealed_bytes_sorted_by_epoch", () => {
		// Written out of order, across two groups, to prove the sort is the
		// store's and not the filesystem's.
		writePending(dir, AGENT, pending(GROUP_B, 1, 0x30));
		writePending(dir, AGENT, pending(GROUP_A, 7, 0x10));
		writePending(dir, AGENT, pending(GROUP_A, 3, 0x20));

		const listed = listPending(dir, AGENT);

		expect(listed.map((p) => [p.groupId, p.epoch])).toEqual([
			[GROUP_A, 3],
			[GROUP_A, 7],
			[GROUP_B, 1],
		]);
		expect(listed[0]?.sealed).toEqual(new Uint8Array([0x20, 0x21, 0x22]));
		expect(listed[0]?.fp).toEqual(fp(0x20));
		// The file holds the sealed bytes alone — no signature, no wrapper.
		expect(
			fs.readFileSync(join(groupDir(GROUP_A), `3-${"20".repeat(16)}.bin`)),
		).toEqual(Buffer.from([0x20, 0x21, 0x22]));
	});

	it("test_write_pending_when_file_exists_is_idempotent", () => {
		const one = pending(GROUP_A, 5, 0x40);
		writePending(dir, AGENT, one);
		const path = join(groupDir(GROUP_A), `5-${"40".repeat(16)}.bin`);
		const before = fs.statSync(path).mtimeMs;

		writePending(dir, AGENT, one);

		expect(fs.statSync(path).mtimeMs).toBe(before);
		expect(listPending(dir, AGENT)).toHaveLength(1);
	});

	it("test_list_pending_when_a_group_is_given_then_only_that_groups_files_are_read", () => {
		writePending(dir, AGENT, pending(GROUP_A, 1, 0x01));
		writePending(dir, AGENT, pending(GROUP_B, 2, 0x02));

		expect(listPending(dir, AGENT, GROUP_B).map((p) => p.epoch)).toEqual([2]);
		expect(listPending(dir, AGENT, "e5f6a7b8-c9d0-1234-ef12-345678901234")).toEqual([]);
	});

	it("test_write_pending_when_the_slot_is_taken_with_other_bytes_then_the_first_sealing_wins", () => {
		const first = pending(GROUP_A, 5, 0x40);
		writePending(dir, AGENT, first);

		writePending(dir, AGENT, { ...first, sealed: new Uint8Array([9, 9, 9]) });

		expect(listPending(dir, AGENT)[0]?.sealed).toEqual(first.sealed);
		expect(fs.readdirSync(groupDir(GROUP_A))).toHaveLength(1);
	});

	it("test_pending_files_when_written_have_mode_0600", () => {
		writePending(dir, AGENT, pending(GROUP_A, 1, 0x50));

		const path = join(groupDir(GROUP_A), `1-${"50".repeat(16)}.bin`);
		expect(fs.statSync(path).mode & 0o777).toBe(0o600);
		expect(fs.statSync(groupDir(GROUP_A)).mode & 0o777).toBe(0o700);
	});

	it("test_list_pending_when_tmp_or_foreign_files_present_ignores_them", () => {
		writePending(dir, AGENT, pending(GROUP_A, 2, 0x60));
		const dirPath = groupDir(GROUP_A);
		// A write in flight, a name that is not this module's shape, and a
		// directory that happens to sit in the group dir.
		fs.writeFileSync(join(dirPath, "2-ffff.tmp"), "half");
		fs.writeFileSync(join(dirPath, "notes.txt"), "hello");
		fs.writeFileSync(join(dirPath, "2-nothex.bin"), "hello");
		fs.mkdirSync(join(dirPath, "subdir"));

		const listed = listPending(dir, AGENT);

		expect(listed).toHaveLength(1);
		expect(listed[0]?.epoch).toBe(2);
	});

	it("test_list_pending_when_an_epoch_has_a_leading_zero_then_the_file_is_not_read", () => {
		writePending(dir, AGENT, pending(GROUP_A, 0, 0x90));
		const hex = "ab".repeat(16);
		fs.mkdirSync(groupDir(GROUP_B), { recursive: true });
		// Epoch 1 written by hand: this module never names a file this way, and
		// deleting the entry it would list computes `1-<hex>.bin`, not this name.
		fs.writeFileSync(join(groupDir(GROUP_B), `01-${hex}.bin`), "hello");

		const listed = listPending(dir, AGENT);

		expect(listed.map((entry) => [entry.groupId, entry.epoch])).toEqual([
			[GROUP_A, 0],
		]);
		expect(pendingGroupIds(dir, AGENT)).toEqual([GROUP_A]);
	});

	it("test_list_pending_when_dir_is_missing_returns_empty", () => {
		expect(listPending(dir, AGENT)).toEqual([]);
	});

	it("test_delete_pending_when_missing_does_not_throw", () => {
		const one = pending(GROUP_A, 9, 0x70);
		writePending(dir, AGENT, one);
		deletePending(dir, AGENT, one);
		expect(listPending(dir, AGENT)).toEqual([]);

		// Deleting again, and deleting a slot that was never written, are both
		// the success case.
		expect(() => deletePending(dir, AGENT, one)).not.toThrow();
		expect(() => deletePending(dir, AGENT, pending(GROUP_B, 1, 0x80))).not.toThrow();
	});

	it("test_write_pending_when_group_id_is_not_a_uuid_then_it_is_refused", () => {
		expect(() =>
			writePending(dir, AGENT, pending("../../profiles", 1, 0x90)),
		).toThrow(/group ID/);
	});
});

describe("the escrow head record", () => {
	it("test_write_head_then_read_head_round_trips", () => {
		writeHead(dir, AGENT, GROUP_A, { epoch: 12, fp: fp(0xab) });

		expect(readHead(dir, AGENT, GROUP_A)).toEqual({
			epoch: 12,
			fp: fp(0xab),
		});
		expect(fs.statSync(headFile(GROUP_A)).mode & 0o777).toBe(0o600);
	});

	it("test_write_head_when_lower_epoch_keeps_existing", () => {
		writeHead(dir, AGENT, GROUP_A, { epoch: 12, fp: fp(0xab) });

		writeHead(dir, AGENT, GROUP_A, { epoch: 4, fp: fp(0xcd) });

		expect(readHead(dir, AGENT, GROUP_A)).toEqual({
			epoch: 12,
			fp: fp(0xab),
		});
	});

	it("test_write_head_when_the_write_is_live_then_a_lower_epoch_follows_the_fork_switch", () => {
		writeHead(dir, AGENT, GROUP_A, { epoch: 12, fp: fp(0xab) });

		writeHead(dir, AGENT, GROUP_A, { epoch: 4, fp: fp(0xcd) }, { live: true });

		expect(readHead(dir, AGENT, GROUP_A)).toEqual({
			epoch: 4,
			fp: fp(0xcd),
		});
	});

	it("test_write_head_when_higher_epoch_replaces_existing", () => {
		writeHead(dir, AGENT, GROUP_A, { epoch: 12, fp: fp(0xab) });

		writeHead(dir, AGENT, GROUP_A, { epoch: 13, fp: fp(0xcd) });

		expect(readHead(dir, AGENT, GROUP_A)).toEqual({
			epoch: 13,
			fp: fp(0xcd),
		});
	});

	it("test_read_head_when_corrupt_returns_undefined", () => {
		fs.mkdirSync(join(mlsStoreRoot(dir, AGENT), "escrow-head"), {
			recursive: true,
		});
		fs.writeFileSync(headFile(GROUP_A), "{not json");
		expect(readHead(dir, AGENT, GROUP_A)).toBeUndefined();

		fs.writeFileSync(headFile(GROUP_A), '{"epoch":"12","fp":"ab"}');
		expect(readHead(dir, AGENT, GROUP_A)).toBeUndefined();

		fs.writeFileSync(headFile(GROUP_A), '{"epoch":12,"fp":"zz"}');
		expect(readHead(dir, AGENT, GROUP_A)).toBeUndefined();
	});

	it("test_read_head_when_absent_returns_undefined", () => {
		expect(readHead(dir, AGENT, GROUP_A)).toBeUndefined();
	});
});
