import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { X402Error, X402_ERROR } from "../../src/x402/errors.js";
import {
	ACQUIRE_TIMEOUT_MS,
	POLL_MS,
	STALE_MS,
	spendLockPath,
	withSpendLock,
} from "../../src/x402/spend-lock.js";

const AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function writeLock(path: string, acquiredAt: number, pid = 999_999): void {
	fs.mkdirSync(dirname(path), { recursive: true });
	fs.writeFileSync(
		path,
		`${JSON.stringify({ pid, acquired_at: acquiredAt })}\n`,
	);
}

describe("spend-lock constants", () => {
	it("match_the_S2_spec_verbatim", () => {
		// Cross-language interop pins these — the Python mirror must use the same values.
		expect(STALE_MS).toBe(5000);
		expect(ACQUIRE_TIMEOUT_MS).toBe(10000);
		expect(POLL_MS).toBe(50);
	});
});

describe("withSpendLock", () => {
	let dir: string;
	let path: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-lock-test-"));
		path = spendLockPath(dir, AGENT_ID);
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("acquires_a_free_lock_runs_fn_then_releases", async () => {
		const result = await withSpendLock(path, async () => "done");
		expect(result).toBe("done");
		expect(fs.existsSync(path)).toBe(false);
	});

	it("releases_the_lock_when_fn_throws", async () => {
		await expect(
			withSpendLock(path, async () => {
				throw new Error("boom");
			}),
		).rejects.toThrow("boom");
		expect(fs.existsSync(path)).toBe(false);
	});

	it("creates_the_lock_content_atomically_via_link_never_empty", async () => {
		// Regression: a plain O_EXCL create then a SEPARATE write leaves an EMPTY
		// lock for a moment that a racing acquirer (TS or Py) reads as unparseable and
		// rename-steals from a LIVE holder → two holders, a lost journal update. The
		// create must link a fully-written temp into place, so the lock is never empty.
		const linkSpy = vi.spyOn(fs, "linkSync");
		await withSpendLock(path, async () => {
			const raw = fs.readFileSync(path, "utf-8"); // while held: parseable, non-empty
			expect(raw.endsWith("\n")).toBe(true);
			expect((JSON.parse(raw) as { pid: number }).pid).toBe(process.pid);
		});
		expect(linkSpy).toHaveBeenCalledWith(expect.stringMatching(/\.tmp$/), path);
		linkSpy.mockRestore();
	});

	it("leaves_the_lock_of_a_holder_that_stole_it_while_fn_ran", async () => {
		await withSpendLock(path, async () => {
			// This holder overran the stale age: another process stole the lock and holds it now.
			writeLock(path, Date.now(), 4242);
		});
		expect(JSON.parse(fs.readFileSync(path, "utf-8")).pid).toBe(4242);
	});

	it("steals_a_stale_lock_and_runs_fn", async () => {
		writeLock(path, Date.now() - (STALE_MS + 60_000));
		const result = await withSpendLock(path, async () => "stolen");
		expect(result).toBe("stolen");
		expect(fs.existsSync(path)).toBe(false);
	});

	it("treats_an_unparseable_lock_as_stale", async () => {
		fs.mkdirSync(dirname(path), { recursive: true });
		fs.writeFileSync(path, "this is not json {{{");
		const result = await withSpendLock(path, async () => "recovered");
		expect(result).toBe("recovered");
	});

	it("fresh_lock_blocks_a_concurrent_acquirer_until_release", async () => {
		let releaseA: () => void = () => {};
		const gate = new Promise<void>((r) => {
			releaseA = r;
		});
		let bRan = false;
		const a = withSpendLock(path, async () => {
			await gate; // hold the lock while B tries
		});
		await sleep(10); // let A acquire
		const b = withSpendLock(path, async () => {
			bRan = true;
		});
		await sleep(POLL_MS * 2); // give B time to poll and be blocked by A's fresh lock
		expect(bRan).toBe(false);
		releaseA();
		await Promise.all([a, b]);
		expect(bRan).toBe(true); // B acquired only after A released
	});

	it("stale_lock_is_rename_stolen_exactly_once_by_two_concurrent_stealers", async () => {
		// Rename-steal (not overwrite-steal) guarantees a single winner: if BOTH
		// stealers took the stale lock, they would run concurrently (maxInside === 2).
		writeLock(path, Date.now() - (STALE_MS + 1_000_000));
		let inside = 0;
		let maxInside = 0;
		let completed = 0;
		const task = () =>
			withSpendLock(path, async () => {
				inside += 1;
				maxInside = Math.max(maxInside, inside);
				await sleep(20);
				inside -= 1;
				completed += 1;
			});
		await Promise.all([task(), task()]);
		expect(maxInside).toBe(1); // mutual exclusion held
		expect(completed).toBe(2); // both eventually acquired
		expect(fs.existsSync(path)).toBe(false);
	});

	it("times_out_with_wallet_busy_under_sustained_contention", async () => {
		// A live competitor keeps the lock perpetually fresh: the injected sleep both
		// advances the clock and re-stamps the lock, so it never ages to STALE and can
		// never be rename-stolen. The acquire budget drains to a typed WALLET_BUSY.
		let t = 1_000_000;
		const now = () => t;
		writeLock(path, t);
		const refreshingSleep = async () => {
			t += 1000;
			writeLock(path, t);
		};
		let ran = false;
		const promise = withSpendLock(
			path,
			async () => {
				ran = true;
			},
			{ now, sleep: refreshingSleep },
		);
		await expect(promise).rejects.toBeInstanceOf(X402Error);
		await promise.catch((e: X402Error) =>
			expect(e.code).toBe(X402_ERROR.WALLET_BUSY),
		);
		expect(ran).toBe(false);
	});

	describe("on a filesystem without hard links", () => {
		beforeEach(() => {
			vi.spyOn(fs, "linkSync").mockImplementation(() => {
				throw Object.assign(new Error("operation not permitted"), {
					code: "EPERM",
				});
			});
		});
		afterEach(() => {
			vi.restoreAllMocks();
		});

		it("test_spend_lock_when_the_link_is_refused_then_it_is_held_and_released", async () => {
			const result = await withSpendLock(path, async () => {
				const raw = fs.readFileSync(path, "utf-8");
				return (JSON.parse(raw) as { pid: number }).pid;
			});
			expect(result).toBe(process.pid);
			expect(fs.readdirSync(dirname(path))).toEqual([]);
		});

		it("test_spend_lock_when_the_link_is_refused_then_a_fresh_lock_still_excludes", async () => {
			let releaseA: () => void = () => {};
			const gate = new Promise<void>((r) => {
				releaseA = r;
			});
			let bRan = false;
			const a = withSpendLock(path, async () => {
				await gate;
			});
			await sleep(10);
			const b = withSpendLock(path, async () => {
				bRan = true;
			});
			await sleep(POLL_MS * 2);
			expect(bRan).toBe(false);
			releaseA();
			await Promise.all([a, b]);
			expect(bRan).toBe(true);
		});
	});

	it("test_spend_lock_when_the_lock_is_empty_and_young_then_it_waits_for_the_stale_age", async () => {
		// An empty lock is a holder between its exclusive create and its write, so it
		// is only taken over once its file age passes the stale age.
		fs.mkdirSync(dirname(path), { recursive: true });
		fs.writeFileSync(path, "");
		const start = Date.now();
		let t = start;
		const ranAt = await withSpendLock(path, async () => t, {
			now: () => t,
			sleep: async () => {
				t += 1000;
			},
		});
		expect(ranAt - start).toBeGreaterThanOrEqual(STALE_MS);
	});
});
