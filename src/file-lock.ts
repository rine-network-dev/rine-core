// Cross-process lock file, for a short read-modify-write of a shared file. It is
// acquired content-atomically (`createAtomicExclusive`: a temp file linked into
// place, so a racing acquirer never reads an empty lock) and a crashed
// holder's lock is taken over by RENAME-STEAL rather than overwrite-in-place: two
// processes can both judge a lock stale and both overwrite it, but rename() is
// atomic, so exactly one wins the steal. A lock others wait for is never held
// across network I/O.
//
// The spend lock (x402/spend-lock.ts), the profiles lock (profiles.ts) and the
// funnel issuance lock (funnel/cert-lock.ts) use this protocol. The issuance lock
// is held across an ACME order and no one waits for it: a run that finds it held
// skips. The Python SDK's spend and profiles locks run the same protocol
// (`rine._file_lock`), so a lock written by one language is read for staleness by
// the other. The body is `{"pid", "acquired_at", "token"}`: the token is this
// acquire's own, so a release removes the lock only while it is still the holder's.

import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { dirname } from "node:path";
import { createAtomicExclusive } from "./config.js";
import { sleep } from "./timing.js";

/** When a lock counts as stale, how long to try before giving up, and how often to retry. */
export interface FileLockTiming {
	staleMs: number;
	timeoutMs: number;
	pollMs: number;
}

/** Injectable clock/sleep so contention and timeout are deterministically testable. */
export interface FileLockClock {
	now?: () => number;
	sleep?: (ms: number) => Promise<void>;
}

/** The lock stayed held by a live process for the whole acquire budget. */
export class FileLockBusyError extends Error {
	constructor(readonly path: string) {
		super(`${path} is held by another process; retry when it finishes`);
		this.name = "FileLockBusyError";
	}
}

interface LockFile {
	pid: number;
	acquired_at: number;
	token?: string;
}

function lockBody(nowMs: number, token: string): string {
	const body: LockFile = { pid: process.pid, acquired_at: nowMs, token };
	return `${JSON.stringify(body)}\n`;
}

// Lock states observed after a failed (EEXIST) create — mirrors the Python names.
// MISSING is deliberately NOT stealable: a lock that already vanished is a normal
// release, not a crashed holder, and stealing on ENOENT is a TOCTOU trap (a new
// holder could have re-created it fresh between our read and the steal → two holders).
type LockState = "missing" | "fresh" | "stale";

function lockState(path: string, nowMs: number, staleMs: number): LockState {
	let raw: string;
	let acquiredAt: number;
	try {
		raw = fs.readFileSync(path, "utf-8");
		// An empty lock is a holder between its in-place create and its write (a
		// filesystem without hard links), so its age is the file's own.
		acquiredAt =
			raw === ""
				? fs.statSync(path).mtimeMs
				: Number((JSON.parse(raw) as LockFile).acquired_at);
	} catch (err) {
		return (err as NodeJS.ErrnoException).code === "ENOENT"
			? "missing"
			: "stale"; // unreadable or garbage — a crashed writer's leftovers
	}
	if (!Number.isFinite(acquiredAt)) return "stale";
	// A stamp from the future (a wall clock stepped back) reads as fresh: it may be a
	// live holder's, and stealing it would give the lock two holders.
	return nowMs - acquiredAt < staleMs ? "fresh" : "stale";
}

/**
 * Rename-steal a stale/unparseable lock. `rename()` is atomic: with N concurrent
 * stealers exactly one succeeds and drops the renamed file; the losers get ENOENT
 * and fall back to the retry loop. The target name uses `randomBytes` entropy (not
 * `pid`, which is not unique across pid namespaces on a shared volume) so distinct
 * processes never collide on the transient `.stale-*` name (that name is never read
 * across languages, so it is not part of the interop contract).
 */
function renameSteal(path: string): void {
	const stalePath = `${path}.stale-${randomBytes(8).toString("hex")}`;
	try {
		fs.renameSync(path, stalePath);
		fs.rmSync(stalePath, { force: true });
	} catch {
		// Lost the rename race (ENOENT) — another stealer won; the loop retries.
	}
}

/**
 * The acquire loop, yielding each wait (in ms) to its driver so the async and the
 * sync lock share it. Returns once the lock is held; throws `busy()` when the
 * budget runs out while a live holder keeps it.
 */
function* acquireWaits(
	path: string,
	timing: FileLockTiming,
	now: () => number,
	busy: () => Error,
	token: string,
): Generator<number, void, void> {
	fs.mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const deadline = now() + timing.timeoutMs;
	for (;;) {
		const nowMs = now();
		if (createAtomicExclusive(path, lockBody(nowMs, token))) return;
		// Create failed (EEXIST). Classify the incumbent: a STALE/unparseable lock is
		// a crashed holder — rename-steal it and retry the create at once. A FRESH lock
		// is a live sibling — back off. MISSING (a release we raced) — retry immediately.
		const state = lockState(path, nowMs, timing.staleMs);
		if (state === "stale") {
			renameSteal(path);
			continue;
		}
		if (nowMs >= deadline) throw busy();
		if (state === "fresh") yield timing.pollMs;
	}
}

/**
 * Remove the lock if it still carries `token`. A holder that overran the stale age
 * may have been stolen from; the lock it finds then is the new holder's, and stays.
 */
function release(path: string, token: string): void {
	try {
		const held = JSON.parse(fs.readFileSync(path, "utf-8")) as LockFile;
		if (held.token === token) fs.rmSync(path, { force: true });
	} catch {
		// best-effort: a stranded lock self-heals once it ages past its stale age.
	}
}

function newToken(): string {
	return randomBytes(8).toString("hex");
}

/**
 * Run `fn` while holding the lock at `path`, always releasing it. `busy` builds the
 * error thrown when the acquire budget runs out (default {@link FileLockBusyError}).
 */
export async function withFileLock<T>(
	path: string,
	timing: FileLockTiming,
	fn: () => Promise<T>,
	busy: () => Error = () => new FileLockBusyError(path),
	clock: FileLockClock = {},
): Promise<T> {
	const wait = clock.sleep ?? sleep;
	const token = newToken();
	for (const ms of acquireWaits(
		path,
		timing,
		clock.now ?? Date.now,
		busy,
		token,
	)) {
		await wait(ms);
	}
	try {
		return await fn();
	} finally {
		release(path, token);
	}
}

const sleepCell = new Int32Array(new SharedArrayBuffer(4));

/** {@link withFileLock} for a synchronous `fn`: the waits block the thread. */
export function withFileLockSync<T>(
	path: string,
	timing: FileLockTiming,
	fn: () => T,
): T {
	const busy = () => new FileLockBusyError(path);
	const token = newToken();
	for (const ms of acquireWaits(path, timing, Date.now, busy, token)) {
		Atomics.wait(sleepCell, 0, 0, ms);
	}
	try {
		return fn();
	} finally {
		release(path, token);
	}
}
