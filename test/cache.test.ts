import { describe, expect, it } from "vitest";
import { TtlCache } from "../src/cache.js";

describe("TtlCache", () => {
	it("returns a stored value before it expires", () => {
		let now = 1000;
		const cache = new TtlCache<string>({ ttlMs: 500, now: () => now });
		cache.set("a", "one");
		now = 1400; // still within TTL
		expect(cache.get("a")).toBe("one");
	});

	it("treats an entry as absent once its TTL elapses", () => {
		let now = 1000;
		const cache = new TtlCache<string>({ ttlMs: 500, now: () => now });
		cache.set("a", "one");
		now = 1600; // past 1000 + 500
		expect(cache.get("a")).toBeUndefined();
	});

	it("evicts the oldest entry when maxEntries is exceeded", () => {
		const cache = new TtlCache<number>({
			maxEntries: 2,
			ttlMs: 10_000,
			now: () => 0,
		});
		cache.set("a", 1);
		cache.set("b", 2);
		cache.set("c", 3); // overflow → "a" (oldest) evicted
		expect(cache.get("a")).toBeUndefined();
		expect(cache.get("b")).toBe(2);
		expect(cache.get("c")).toBe(3);
	});

	it("refreshes recency on re-set so a hot key survives overflow", () => {
		const cache = new TtlCache<number>({
			maxEntries: 2,
			ttlMs: 10_000,
			now: () => 0,
		});
		cache.set("a", 1);
		cache.set("b", 2);
		cache.set("a", 11); // re-set "a" → now newest, "b" oldest
		cache.set("c", 3); // overflow → "b" evicted, not "a"
		expect(cache.get("a")).toBe(11);
		expect(cache.get("b")).toBeUndefined();
		expect(cache.get("c")).toBe(3);
	});

	it("delete forces the next get to miss", () => {
		const cache = new TtlCache<string>({ now: () => 0 });
		cache.set("a", "one");
		cache.delete("a");
		expect(cache.get("a")).toBeUndefined();
	});
});
