// rine Funnel ACME-storm backoff + renewal window + LE rate-limit classification
// (REQ-CERT-13/14). The token-storm precedent: never re-mint per boot, back off
// exponentially with FULL jitter, and treat the LE duplicate-cert / failed-
// validation ceilings as TERMINAL rather than hammering Let's Encrypt.

import type { CertMeta } from "./cert-cache.js";

const BACKOFF_BASE_MS = 30_000; // 30s
const BACKOFF_FACTOR = 2;
const BACKOFF_CAP_MS = 3_600_000; // 1h
const RENEWAL_WINDOW_MS = 30 * 86_400_000; // 30 days before not_after
// PINNED (REQ-CERT-46/SCALE-2): the per-agent renewal trigger is spread across
// this window so a 1K-agent fleet whose certs were all minted in one migration
// burst de-correlates instead of all firing at `not_after - 30d`. Capped well
// under the 30-day window so `offset_max (20d) + worst-case backoff (1h) +
// propagation grace (45s)` still leaves head-room before expiry.
const RENEWAL_SPREAD_MS = 20 * 86_400_000; // 20 days

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
 * A stable, deterministic 32-bit hash (FNV-1a) of the agent label. NOT
 * `Math.random` — a relay that restarts repeatedly must compute the SAME renewal
 * offset every boot, never re-roll (which would thunder early or never settle).
 */
function stableHash(label: string): number {
	let h = 0x811c9dc5; // FNV offset basis
	for (let i = 0; i < label.length; i++) {
		h ^= label.charCodeAt(i);
		h = Math.imul(h, 0x01000193) >>> 0; // FNV prime, keep unsigned 32-bit
	}
	return h >>> 0;
}

/**
 * Per-agent jittered renewal trigger (REQ-CERT-46). Spreads the renewal firing
 * deterministically across `RENEWAL_SPREAD_MS` (20d, PINNED) so a fleet whose
 * certs were all minted in one window does NOT storm Let's Encrypt at
 * `not_after - 30d`. Fires when `now >= not_after - 30d + offset(agentLabel)`,
 * i.e. it shrinks the un-jittered 30-day window by a stable per-agent offset in
 * `[0, RENEWAL_SPREAD_MS]`. Wraps `isRenewalDue` (the un-jittered primitive,
 * which still governs already-expired / unparseable certs).
 */
export function renewalDueWithJitter(
	meta: CertMeta,
	agentLabel: string,
	nowMs: number,
): boolean {
	const notAfterMs = Date.parse(meta.not_after);
	if (Number.isNaN(notAfterMs)) return true; // unparseable -> re-issue
	const offset = stableHash(agentLabel) % RENEWAL_SPREAD_MS;
	return notAfterMs - nowMs <= RENEWAL_WINDOW_MS - offset;
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
