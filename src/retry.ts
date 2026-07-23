// Shared rate-limit / retry primitives for the token and request paths.
// The Retry-After parser was
// previously duplicated in funnel/acme.ts and ts-sdk; this is the single canonical
// copy. Full-jitter backoff mirrors funnel/backoff.ts's formula but with
// token-appropriate constants (small base, bounded total wait) rather than the
// ACME-tuned 30s-base / 1h-cap schedule.
import type { RineApiError } from "./errors.js";

/** Max attempts for the OAuth token POST (initial + retries). */
export const TOKEN_RETRY_MAX_ATTEMPTS = 3;
/** Upper bound on cumulative token-retry wait, and the cap on a single normal-call 429 wait. */
export const MAX_RETRY_WAIT_MS = 30_000;
const BACKOFF_BASE_MS = 1_000;

/** Milliseconds to wait per a `Retry-After` header on `res`, or 0 if absent/non-positive. */
export function retryAfterMsFromResponse(res: Response): number {
	const header = res.headers?.get?.("retry-after");
	const secs = header ? Number(header) : Number.NaN;
	if (Number.isFinite(secs) && secs > 0) return secs * 1000;
	return 0;
}

/** Retry-After (ms) carried on a thrown `RineApiError.raw` Response, or 0. */
export function retryAfterMsFromError(err: RineApiError): number {
	return err.raw instanceof Response ? retryAfterMsFromResponse(err.raw) : 0;
}

/**
 * Full-jitter exponential backoff: a uniform random delay in `[0, ceiling]` where
 * `ceiling = base * 2^(attempt-1)`. Full jitter (not a jittered fixed delay) is
 * what de-correlates a fleet of co-located clients retrying the same 429.
 * `attempt` is 1-based.
 */
export function fullJitterBackoffMs(
	attempt: number,
	rng: () => number = Math.random,
): number {
	const n = Math.max(1, attempt);
	const ceiling = BACKOFF_BASE_MS * 2 ** (n - 1);
	return Math.floor(rng() * (ceiling + 1));
}

/**
 * Per-client-instance token refresh margin (seconds): `60 + uniform(0, 120)`,
 * drawn ONCE at client construction. Co-located clients that started
 * together then desynchronize permanently instead of clustering their refreshes
 * into the same minute. `rng` is injectable for deterministic tests.
 */
export function jitteredRefreshMargin(rng: () => number = Math.random): number {
	return 60 + rng() * 120;
}
