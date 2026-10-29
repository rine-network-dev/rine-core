/**
 * The escrow store's durability points. The state a sealed export came from is
 * deleted right after it is written, so the bytes must be flushed before the
 * entry is published and the directory flushed once the entry exists.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const events = vi.hoisted(() => ({ log: [] as string[] }));

vi.mock("../src/fsync.js", async () => {
	const actual = await vi.importActual<typeof import("../src/fsync.js")>("../src/fsync.js");
	return {
		fsyncFile: vi.fn((path: string) => {
			events.log.push(`file:${fs.statSync(path).size}`);
			actual.fsyncFile(path);
		}),
		fsyncDir: vi.fn((path: string) => {
			events.log.push(`dir:${fs.readdirSync(path).join(",")}`);
			actual.fsyncDir(path);
		}),
	};
});

import { groupStatePath } from "../src/crypto/mls-store-probe.js";
import { groupPendingDir, writePending } from "../src/mls-escrow-pending.js";
import { parkSnapshot } from "../src/mls-escrow-snapshots.js";

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP = "c3d4e5f6-a7b8-9012-cdef-123456789012";

let dir: string;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-durable-"));
	events.log.length = 0;
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("durability points", () => {
	it("test_write_pending_when_it_publishes_then_the_bytes_are_flushed_before_the_dir_entry_is", () => {
		const sealed = new Uint8Array(37).fill(7);

		writePending(dir, AGENT, { groupId: GROUP, epoch: 2, fp: new Uint8Array(32).fill(1), sealed });

		expect(events.log).toHaveLength(2);
		expect(events.log[0]).toBe("file:37");
		const entry = fs.readdirSync(groupPendingDir(dir, AGENT, GROUP)).find((n) => n.endsWith(".bin"));
		expect(events.log[1]).toContain(`dir:${entry}`);
	});

	it("test_park_snapshot_when_it_publishes_then_the_copy_is_flushed_before_the_dir_entry_is", () => {
		const state = groupStatePath(dir, AGENT, GROUP);
		fs.mkdirSync(join(state, ".."), { recursive: true });
		fs.writeFileSync(state, new Uint8Array(21).fill(3));

		parkSnapshot(dir, AGENT, GROUP, 6, 0, 0);

		expect(events.log[0]).toBe("file:21");
		expect(events.log[1]).toMatch(/^dir:.*6\.snapshot/);
	});
});
