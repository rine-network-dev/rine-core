// rine Funnel per-agent issuance lock + wipe-surviving attempt-ledger
// (REQ-CERT-42, AUD-B2/SCALE-4). Because the per-agent wildcard collapses ALL of
// an agent's hook-relays onto ONE `funnel/{agentLabel}/` subtree and ONE
// `*.{agentLabel}.hook.rine.network` cert, two hook-relays of the SAME agent that
// cold-start together would otherwise fire TWO ACME orders for the IDENTICAL
// wildcard FQDN — burning the LE duplicate-certificate budget (5 / 7d). This
// module adds the cross-process guards that make the sharing safe:
//
//  - a cross-process OS file-lock held across newOrder->download so only one
//    hook-relay of an agent issues at a time (the other skips, reuses the cert);
//  - a separate attempt-ledger persisted at the funnel ROOT (NOT inside the
//    wiped per-agent subtree) so a cache wipe does NOT reset the crash-loop
//    backoff counter and re-burn the duplicate-cert budget.
//
// Both artifacts live at the funnel root keyed by certKey, OUTSIDE the subtree
// `wipeHandleCache` deletes — so a teardown never strands the lock or the ledger.

import * as fs from "node:fs";
import { join } from "node:path";
import { type AcmeOptions, funnelCacheDir } from "./cert-cache.js";

// A lock older than this is treated as stale (its holder crashed without
// releasing). Sized above the worst-case cold issuance (propagation grace +
// bounded poll + ACME round-trips, a few minutes) so a SLOW-but-live holder is
// never stolen from mid-order, but a dead holder never wedges an agent forever.
const LOCK_STALE_MS = 15 * 60_000; // 15 minutes

interface LockFile {
	pid: number;
	acquired_at: number;
}

/** Persisted across the wiped subtree so a cache wipe never resets backoff. */
export interface AttemptLedger {
	consecutive_failures: number;
	last_attempt_ts: number;
}

function lockPath(
	configDir: string,
	certKey: string,
	opts: AcmeOptions,
): string {
	return join(funnelCacheDir(configDir, opts), `${certKey}.lock`);
}

function ledgerPath(
	configDir: string,
	certKey: string,
	opts: AcmeOptions,
): string {
	return join(funnelCacheDir(configDir, opts), `${certKey}.attempts.json`);
}

function readLock(path: string): LockFile | null {
	try {
		return JSON.parse(fs.readFileSync(path, "utf-8")) as LockFile;
	} catch {
		return null;
	}
}

/**
 * Try to ATOMICALLY create the lock file (O_EXCL). Returns true on success. If it
 * already exists, returns true only after stealing a STALE lock (crashed holder),
 * false while a fresh lock is held by a (presumed-live) sibling.
 */
function tryAcquire(path: string, nowMs: number): boolean {
	fs.mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 });
	const body = `${JSON.stringify({ pid: process.pid, acquired_at: nowMs })}\n`;
	try {
		const fd = fs.openSync(path, "wx", 0o600); // wx = O_CREAT|O_EXCL — atomic
		fs.writeSync(fd, body);
		fs.closeSync(fd);
		return true;
	} catch {
		// Lock exists — steal it ONLY if it is stale (its holder crashed). A fresh
		// lock means a sibling is mid-issuance for the identical wildcard; back off.
		const existing = readLock(path);
		if (existing && nowMs - existing.acquired_at < LOCK_STALE_MS) return false;
		// Stale (or unparseable): overwrite in place and take ownership.
		try {
			fs.writeFileSync(path, body, { mode: 0o600 });
			return true;
		} catch {
			return false;
		}
	}
}

function release(path: string): void {
	try {
		fs.rmSync(path, { force: true });
	} catch {
		// best-effort: a stale lock self-heals after LOCK_STALE_MS.
	}
}

/**
 * Run `fn` under the per-agent cross-process issuance lock (AUD-B2/SCALE-4). The
 * lock is held for the WHOLE callback (newOrder->download) so two concurrent
 * hook-relays of the SAME agent cannot fire two ACME orders for the identical
 * `*.{agentLabel}.hook.rine.network`. If the lock is already held by a live
 * sibling, `fn` is SKIPPED and `{ acquired: false }` is returned — the caller
 * reuses whatever the sibling installs (no duplicate ACME order). The lock is
 * always released in `finally`. `now` is injectable for deterministic tests.
 */
export async function withAgentIssuanceLock<T>(
	args: {
		configDir: string;
		certKey: string;
		opts: AcmeOptions;
		now?: () => number;
	},
	fn: () => Promise<T>,
): Promise<{ acquired: true; result: T } | { acquired: false }> {
	const { configDir, certKey, opts } = args;
	const nowMs = (args.now ?? Date.now)();
	const path = lockPath(configDir, certKey, opts);
	if (!tryAcquire(path, nowMs)) return { acquired: false };
	try {
		return { acquired: true, result: await fn() };
	} finally {
		release(path);
	}
}

/**
 * Load the wipe-surviving attempt-ledger for a cert key. Returns a zeroed ledger
 * when none exists, so the FIRST failure starts the count at one (not undefined).
 */
export function loadAttemptLedger(
	configDir: string,
	certKey: string,
	opts: AcmeOptions,
): AttemptLedger {
	try {
		const raw = fs.readFileSync(ledgerPath(configDir, certKey, opts), "utf-8");
		const parsed = JSON.parse(raw) as AttemptLedger;
		return {
			consecutive_failures: parsed.consecutive_failures ?? 0,
			last_attempt_ts: parsed.last_attempt_ts ?? 0,
		};
	} catch {
		return { consecutive_failures: 0, last_attempt_ts: 0 };
	}
}

/** Atomically persist the attempt-ledger at the funnel root (0600). */
export function saveAttemptLedger(
	configDir: string,
	certKey: string,
	opts: AcmeOptions,
	ledger: AttemptLedger,
): void {
	const path = ledgerPath(configDir, certKey, opts);
	fs.mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 });
	const tmp = `${path}.tmp`;
	fs.writeFileSync(tmp, `${JSON.stringify(ledger)}\n`, { mode: 0o600 });
	fs.renameSync(tmp, path);
	fs.chmodSync(path, 0o600);
}
