// Cross-process spend-journal lock: the shared lock-file protocol (file-lock.ts)
// with this journal's own constants. Held only across the tiny reserve critical
// section (read journal → enforce policy → write journal), never across network I/O.
//
// Constants MUST match the Python mirror (rine-sdk) exactly — a lock written by one
// language is read for staleness by the other, so both sides share this TTL/timeout.

import { join } from "node:path";
import { validatePathId } from "../crypto/keys.js";
import { type FileLockClock, withFileLock } from "../file-lock.js";
import { X402Error, X402_ERROR } from "./errors.js";

/** A lock older than this is stale (its holder crashed mid-section). */
export const STALE_MS = 5000;
/** Overall acquire budget. > STALE_MS so one call rides through a crashed holder. */
export const ACQUIRE_TIMEOUT_MS = 10000;
/** Poll interval while a fresh (live-holder) lock blocks us. */
export const POLL_MS = 50;

export function spendLockPath(configDir: string, agentId: string): string {
	validatePathId(agentId, "agent ID");
	return join(configDir, "keys", agentId, "wallet-spend.lock");
}

/** Injectable clock/sleep so contention and timeout are deterministically testable. */
export type SpendLockClock = FileLockClock;

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
	return withFileLock(
		path,
		{ staleMs: STALE_MS, timeoutMs: ACQUIRE_TIMEOUT_MS, pollMs: POLL_MS },
		fn,
		() =>
			new X402Error(
				X402_ERROR.WALLET_BUSY,
				"Could not acquire the spend lock — another payment is in flight",
			),
		clock,
	);
}
