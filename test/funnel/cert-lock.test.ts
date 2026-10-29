// The per-agent issuance lock: one hook-relay of an agent issues at a time, the
// sibling that finds a live lock skips without waiting, a crashed holder's lock
// is taken over once stale, and the lock is released whatever `fn` does.

import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { withAgentIssuanceLock } from "../../src/funnel/cert-lock.js";

const CERT_KEY = "a1b2c3d4e5";
const NOW = 1_800_000_000_000;
const STALE_MS = 15 * 60_000;

let configDir: string;
const lockFile = () => join(configDir, "funnel", `${CERT_KEY}.lock`);
const args = () => ({ configDir, certKey: CERT_KEY, opts: {}, now: () => NOW });

function plantLock(acquiredAt: number): void {
	fs.mkdirSync(join(configDir, "funnel"), { recursive: true });
	fs.writeFileSync(lockFile(), `${JSON.stringify({ pid: 1, acquired_at: acquiredAt })}\n`);
}

beforeEach(() => {
	configDir = fs.mkdtempSync(join(tmpdir(), "rine-cert-lock-"));
});

afterEach(() => {
	fs.rmSync(configDir, { recursive: true, force: true });
});

describe("withAgentIssuanceLock", () => {
	it("test_issuanceLock_when_free_then_runs_fn_and_releases", async () => {
		const fn = vi.fn(async () => {
			expect(fs.existsSync(lockFile())).toBe(true);
			return "issued";
		});

		await expect(withAgentIssuanceLock(args(), fn)).resolves.toEqual({
			acquired: true,
			result: "issued",
		});
		expect(fs.existsSync(lockFile())).toBe(false);
	});

	it("test_issuanceLock_when_a_live_sibling_holds_it_then_skips_without_waiting", async () => {
		plantLock(NOW - STALE_MS + 60_000);
		const fn = vi.fn(async () => "issued");

		await expect(withAgentIssuanceLock(args(), fn)).resolves.toEqual({ acquired: false });
		expect(fn).not.toHaveBeenCalled();
		expect(fs.existsSync(lockFile())).toBe(true);
	});

	it("test_issuanceLock_when_the_holder_crashed_then_takes_the_stale_lock", async () => {
		plantLock(NOW - STALE_MS - 1);

		await expect(withAgentIssuanceLock(args(), async () => "issued")).resolves.toEqual({
			acquired: true,
			result: "issued",
		});
		expect(fs.existsSync(lockFile())).toBe(false);
	});

	it("test_issuanceLock_when_fn_throws_then_rethrows_and_releases", async () => {
		const boom = new Error("acme order failed");

		await expect(
			withAgentIssuanceLock(args(), async () => {
				throw boom;
			}),
		).rejects.toBe(boom);
		expect(fs.existsSync(lockFile())).toBe(false);
	});
});
