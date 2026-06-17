// rine Funnel relay-side webhook de-dup (T8). The relay's HMAC verify
// authenticates the BODY only — a captured signed webhook (leaked CI log,
// pre-TLS MITM at the source, shared transcript) replays forever, minting
// duplicate `rine.v1.webhook` inbox messages with no de-dup. This bounded
// in-memory store remembers recently-relayed delivery keys so a duplicate is
// dropped before it is encrypted/self-sent.
//
// Purely client-side: PROTOCOL.md already blesses Idempotency-Key + the
// messages.idempotency_key column exists, so this adds NO wire/protocol change.
// The store is per-process and best-effort (a relay restart clears it, which at
// worst re-admits an in-flight replay once) — it is a quota/duplicate-action
// shield, not a security boundary; HMAC verify remains the authenticator.

const DEFAULT_MAX_ENTRIES = 4096;
const DEFAULT_TTL_MS = 10 * 60_000; // 10 min — well past any legitimate retry.

/**
 * A bounded, TTL-evicting set of seen idempotency keys with LRU overflow.
 *
 * Insertion-ordered `Map<key, expiryMs>` gives both eviction policies cheaply:
 * - TTL: a key whose stored expiry is in the past is treated as absent (and
 *   purged on access), so stale entries never produce false-duplicate drops.
 * - LRU: when the live set exceeds `maxEntries`, the oldest insertion (the
 *   Map's first key) is deleted. Re-seeing a live key refreshes its position
 *   (delete+re-set) so hot keys survive overflow.
 *
 * No timers: eviction is lazy on `seen()`, so an idle relay holds no callbacks.
 */
export class IdempotencyStore {
	private readonly entries = new Map<string, number>();
	private readonly maxEntries: number;
	private readonly ttlMs: number;
	private readonly now: () => number;

	constructor(
		opts: { maxEntries?: number; ttlMs?: number; now?: () => number } = {},
	) {
		this.maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
		this.ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
		this.now = opts.now ?? Date.now;
	}

	/**
	 * Record `key` and report whether it was ALREADY present (and unexpired).
	 * Returns `true` for a duplicate (caller should drop), `false` for a first
	 * sighting (caller should relay). A re-seen live key has its TTL refreshed.
	 */
	seen(key: string): boolean {
		const nowMs = this.now();
		const expiry = this.entries.get(key);
		if (expiry !== undefined && expiry > nowMs) {
			// Live duplicate: refresh recency + TTL, report the hit.
			this.entries.delete(key);
			this.entries.set(key, nowMs + this.ttlMs);
			return true;
		}
		// Absent or expired: (re)admit as a first sighting.
		this.entries.delete(key);
		this.entries.set(key, nowMs + this.ttlMs);
		this.evictOverflow();
		return false;
	}

	/** Live entry count (expired-but-not-yet-purged keys may inflate this). */
	get size(): number {
		return this.entries.size;
	}

	/** Drop oldest insertions until the live set fits `maxEntries`. */
	private evictOverflow(): void {
		while (this.entries.size > this.maxEntries) {
			const oldest = this.entries.keys().next().value;
			if (oldest === undefined) break;
			this.entries.delete(oldest);
		}
	}
}
