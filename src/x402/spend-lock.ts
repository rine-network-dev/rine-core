// Cross-process spend-journal lock (S2, S2_JOURNAL_DESIGN.md § Lock protocol).
// Modelled on funnel/cert-lock.ts but with the S2 constants and — critically —
// RENAME-STEAL rather than overwrite-in-place: at a 5 s TTL two processes can both
// judge a lock stale and both overwrite it; rename() is atomic so exactly one wins
// the steal. Held only across the tiny reserve critical section (read journal →
// enforce policy → write journal), never across network I/O.
//
// Constants MUST match the Python mirror (rine-sdk) exactly — a lock written by one
// language is read for staleness by the other, so both sides share this TTL/timeout.

import * as fs from "node:fs";
import { dirname, join } from "node:path";
import { validatePathId } from "../crypto/keys.js";
import { X402Error, X402_ERROR } from "./errors.js";

/** A lock older than this is stale (its holder crashed mid-section). */
export const STALE_MS = 5000;
/** Overall acquire budget. > STALE_MS so one call rides through a crashed holder. */
export const ACQUIRE_TIMEOUT_MS = 10000;
/** Poll interval while a fresh (live-holder) lock blocks us. */
export const POLL_MS = 50;

interface LockFile {
	pid: number;
	acquired_at: number;
}

export function spendLockPath(configDir: string, agentId: string): string {
	validatePathId(agentId, "agent ID");
	return join(configDir, "keys", agentId, "wallet-spend.lock");
}

// Lock states observed after a failed (EEXIST) create — mirrors the Python names.
// MISSING is deliberately NOT stealable: a lock that already vanished is a normal
// release, not a crashed holder, and stealing on ENOENT is a TOCTOU trap (a new
// holder could have re-created it fresh between our read and the steal → two holders).
type LockState = "missing" | "fresh" | "stale";

function lockState(path: string, nowMs: number): LockState {
	let raw: string;
	try {
		raw = fs.readFileSync(path, "utf-8");
	} catch (err) {
		return (err as NodeJS.ErrnoException).code === "ENOENT"
			? "missing"
			: "stale";
	}
	let acquiredAt: number;
	try {
		acquiredAt = Number((JSON.parse(raw) as LockFile).acquired_at);
	} catch {
		return "stale"; // exists but garbage — a crashed writer's leftovers
	}
	if (!Number.isFinite(acquiredAt)) return "stale";
	return nowMs - acquiredAt < STALE_MS ? "fresh" : "stale";
}

/**
 * Atomically create the lock with its body already present. Returns `true` on
 * success, `false` if it already exists (someone holds it). Content-atomic: a
 * plain `O_EXCL` create then a separate write leaves an EMPTY file for a moment,
 * and a racing acquirer would read that as unparseable → steal a LIVE holder →
 * two holders (a lost update). Writing the body to a per-pid temp first, then
 * `link()`-ing it into place, keeps the exclusive-create guarantee while making
 * the lock non-empty the instant it exists. Mirrors Python `_try_create`.
 */
function tryCreate(path: string, nowMs: number): boolean {
	const body = `${JSON.stringify({ pid: process.pid, acquired_at: nowMs })}\n`;
	const tmp = `${path}.${process.pid}.tmp`;
	const fd = fs.openSync(tmp, "w", 0o600); // w = O_CREAT|O_TRUNC|O_WRONLY
	try {
		fs.writeSync(fd, body);
	} finally {
		fs.closeSync(fd);
	}
	try {
		fs.linkSync(tmp, path); // atomic exclusive create — EEXIST if a holder exists
		return true;
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === "EEXIST") return false;
		throw err;
	} finally {
		fs.rmSync(tmp, { force: true }); // best-effort; force swallows ENOENT
	}
}

/**
 * Rename-steal a stale/unparseable lock. `rename()` is atomic: with N concurrent
 * stealers exactly one succeeds and drops the renamed file; the losers get ENOENT
 * and fall back to the retry loop. The target is keyed on pid so distinct processes
 * never collide on the transient `.stale-*` name (that name is never read across
 * languages, so it is not part of the interop contract).
 */
function renameSteal(path: string): void {
	const stalePath = `${path}.stale-${process.pid}`;
	try {
		fs.renameSync(path, stalePath);
		fs.rmSync(stalePath, { force: true });
	} catch {
		// Lost the rename race (ENOENT) — another stealer won; the loop retries.
	}
}

const realSleep = (ms: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

/** Injectable clock/sleep so contention and timeout are deterministically testable. */
export interface SpendLockClock {
	now?: () => number;
	sleep?: (ms: number) => Promise<void>;
}

async function acquire(
	path: string,
	now: () => number,
	sleep: (ms: number) => Promise<void>,
): Promise<void> {
	fs.mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const deadline = now() + ACQUIRE_TIMEOUT_MS;
	for (;;) {
		const nowMs = now();
		if (tryCreate(path, nowMs)) return;
		// Create failed (EEXIST). Classify the incumbent: a STALE/unparseable lock is
		// a crashed holder — rename-steal it and retry the create at once. A FRESH lock
		// is a live sibling — back off. MISSING (a release we raced) — retry immediately.
		const state = lockState(path, nowMs);
		if (state === "stale") {
			renameSteal(path);
			continue;
		}
		if (nowMs >= deadline) {
			throw new X402Error(
				X402_ERROR.WALLET_BUSY,
				"Could not acquire the spend lock — another payment is in flight",
			);
		}
		if (state === "fresh") await sleep(POLL_MS);
	}
}

function release(path: string): void {
	try {
		fs.rmSync(path, { force: true });
	} catch {
		// best-effort: a stranded lock self-heals once it ages past STALE_MS.
	}
}

/**
 * Run `fn` while holding the cross-process spend lock at `path`. Acquires with the
 * content-atomic link + rename-steal protocol, always releases in `finally`, and propagates a
 * typed {@link X402Error} `wallet-busy` when the acquire budget is exhausted.
 */
export async function withSpendLock<T>(
	path: string,
	fn: () => Promise<T>,
	clock: SpendLockClock = {},
): Promise<T> {
	const now = clock.now ?? Date.now;
	const sleep = clock.sleep ?? realSleep;
	await acquire(path, now, sleep);
	try {
		return await fn();
	} finally {
		release(path);
	}
}
