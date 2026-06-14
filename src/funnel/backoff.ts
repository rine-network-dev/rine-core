// rine Funnel ACME-storm backoff + renewal window + LE rate-limit classification
// (REQ-CERT-13/14). The token-storm precedent: never re-mint per boot, back off
// exponentially with FULL jitter, and treat the LE duplicate-cert / failed-
// validation ceilings as TERMINAL rather than hammering Let's Encrypt.

import type { CertMeta } from "./cert-cache.js";

const BACKOFF_BASE_MS = 30_000; // 30s
const BACKOFF_FACTOR = 2;
const BACKOFF_CAP_MS = 3_600_000; // 1h
const RENEWAL_WINDOW_MS = 30 * 86_400_000; // 30 days before not_after

/**
 * Full-jitter exponential backoff: a uniform random delay in `[0, ceiling]`
 * where `ceiling = base * factor^(n-1)`, capped at 1h. Full jitter (not just a
 * jittered fixed delay) is what de-correlates a fleet of crash-looping relays.
 * `n` is the 1-based consecutive-failure count (n<=0 is treated as the first).
 */
export function nextBackoffDelayMs(consecutiveFailures: number): number {
	const n = Math.max(1, consecutiveFailures);
	const ceiling = Math.min(
		BACKOFF_CAP_MS,
		BACKOFF_BASE_MS * BACKOFF_FACTOR ** (n - 1),
	);
	return Math.floor(Math.random() * (ceiling + 1));
}

/**
 * A cert is due for renewal when `not_after - now <= 30 days` (boundary
 * inclusive). An already-expired cert is due (and forces a cold issuance).
 */
export function isRenewalDue(meta: CertMeta, nowMs: number): boolean {
	const notAfterMs = Date.parse(meta.not_after);
	if (Number.isNaN(notAfterMs)) return true; // unparseable -> re-issue
	return notAfterMs - nowMs <= RENEWAL_WINDOW_MS;
}

/**
 * TERMINAL = an LE rate-limit ceiling that no amount of retrying can clear in
 * the near term (the duplicate-certificate limit: 5 identical FQDN sets / 7
 * days, and the per-account failed-validation limit). On a terminal error the
 * relay stops attempting and surfaces it rather than burning the LE budget.
 * Ordinary transient failures (timeouts, propagation, provider 502) are NOT
 * terminal — they retry on the backoff schedule.
 */
export function isTerminalAcmeError(err: unknown): boolean {
	if (typeof err !== "object" || err === null) return false;
	const tag = (err as { leRateLimit?: unknown }).leRateLimit;
	if (tag === "duplicate-certificate" || tag === "failed-validation") {
		return true;
	}
	const msg = err instanceof Error ? err.message.toLowerCase() : "";
	// Match the stable LE stem `too many certificates` so the modern
	// parenthetical-count wording (`too many certificates (5) already issued ...`)
	// is still classified TERMINAL — the count breaks any longer literal.
	return (
		msg.includes("too many certificates") ||
		msg.includes("too many failed authorizations")
	);
}
