// rine Funnel per-agent issuance lock + wipe-surviving attempt-ledger.
// Because the per-agent wildcard collapses ALL of
// an agent's hook-relays onto ONE `funnel/{agentLabel}/` subtree and ONE
// `*.{agentLabel}.hook.rine.network` cert, two hook-relays of the SAME agent that
// cold-start together would otherwise fire TWO ACME orders for the IDENTICAL
// wildcard FQDN — burning the LE duplicate-certificate budget (5 / 7d). This
// module adds the cross-process guards that make the sharing safe:
//
//  - a cross-process lock file (the `file-lock.ts` protocol) held across
//    newOrder->download so only one hook-relay of an agent issues at a time (the
//    other skips, reuses the cert);
//  - a separate attempt-ledger persisted at the funnel ROOT (NOT inside the
//    wiped per-agent subtree) so a cache wipe does NOT reset the crash-loop
//    backoff counter and re-burn the duplicate-cert budget.
//
// Both artifacts live at the funnel root keyed by certKey, OUTSIDE the subtree
// `wipeHandleCache` deletes — so a teardown never strands the lock or the ledger.

import * as fs from "node:fs";
import { join } from "node:path";
import { writeAtomic } from "../config.js";
import { type FileLockTiming, withFileLock } from "../file-lock.js";
import { type AcmeOptions, funnelCacheDir } from "./cert-cache.js";

// A lock older than this is treated as stale (its holder crashed without
// releasing). Sized above the worst-case cold issuance (propagation grace +
// bounded poll + ACME round-trips, a few minutes) so a SLOW-but-live holder is
// never stolen from mid-order, but a dead holder never wedges an agent forever.
// A held lock is never waited for: the run that finds a sibling mid-order skips.
const LOCK_TIMING: FileLockTiming = {
	staleMs: 15 * 60_000,
	timeoutMs: 0,
	pollMs: 0,
};

/** Acquiring found a live sibling's lock; private, so `fn` can never throw it. */
class HeldBySibling extends Error {}

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

/**
 * Run `fn` under the per-agent cross-process issuance lock. The
 * lock is held for the WHOLE callback (newOrder->download) so two concurrent
 * hook-relays of the SAME agent cannot fire two ACME orders for the identical
 * `*.{agentLabel}.hook.rine.network`. If the lock is already held by a live
 * sibling, `fn` is SKIPPED and `{ acquired: false }` is returned — the caller
 * reuses whatever the sibling installs (no duplicate ACME order). The lock is
 * always released in `finally`; a crashed holder's lock is taken over once
 * it is stale. The acquire budget is zero, so a lock that is released between
 * the failed create and the check also returns `{ acquired: false }`: the run
 * skips rather than racing a new holder, and the next pass takes the lock.
 * `now` is injectable for deterministic tests.
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
	const path = lockPath(configDir, certKey, opts);
	try {
		const result = await withFileLock(
			path,
			LOCK_TIMING,
			fn,
			() => new HeldBySibling(),
			{ now: args.now },
		);
		return { acquired: true, result };
	} catch (err) {
		if (err instanceof HeldBySibling) return { acquired: false };
		throw err;
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
	writeAtomic(path, `${JSON.stringify(ledger)}\n`);
}
