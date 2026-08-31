// Bounded, TTL-evicting value cache with LRU overflow — the value-carrying
// sibling of funnel/idempotency-store.ts (which stores only membership/expiry).
// Used to cache per-agent key material (GET /agents/{id}/keys) on a persistent
// client instance so a multi-agent host stops re-fetching the same keys on every
// inbound-verify. The outbound seal never reads it: a key it sealed to is never
// reported wrong, so a stale entry there costs a permanently unreadable message
// (see fetchRecipientKeys in crypto/agent-keys.ts).
//
// Insertion-ordered `Map` gives both eviction policies cheaply:
// - TTL: an entry whose stored expiry is in the past is treated as absent (and
//   purged on access), so a rotated key never lingers past its TTL window.
// - LRU: when the live set exceeds `maxEntries`, the oldest insertion (the Map's
//   first key) is dropped. Re-setting a live key refreshes its position so hot
//   keys survive overflow.
//
// No timers: eviction is lazy on `get`/`set`, so an idle client holds no callbacks.

const DEFAULT_MAX_ENTRIES = 256;
const DEFAULT_TTL_MS = 600_000; // 10 min — bounds the key-rotation staleness window.

export class TtlCache<V> {
	private readonly entries = new Map<string, { value: V; expiry: number }>();
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

	/** The live value for `key`, or `undefined` if absent or expired (expired entries are purged). */
	get(key: string): V | undefined {
		const hit = this.entries.get(key);
		if (hit === undefined) return undefined;
		if (hit.expiry <= this.now()) {
			this.entries.delete(key);
			return undefined;
		}
		return hit.value;
	}

	/** Store `value` under `key`, refreshing its recency + TTL and evicting any overflow. */
	set(key: string, value: V): void {
		this.entries.delete(key);
		this.entries.set(key, { value, expiry: this.now() + this.ttlMs });
		while (this.entries.size > this.maxEntries) {
			const oldest = this.entries.keys().next().value;
			if (oldest === undefined) break;
			this.entries.delete(oldest);
		}
	}

	/** Drop `key` so the next `get` misses (forces a fresh fetch). */
	delete(key: string): void {
		this.entries.delete(key);
	}
}
