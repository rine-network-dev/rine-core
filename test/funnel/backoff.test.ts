// B11 — REQ-CERT-46 / REQ-CERT-13 / SCALE-2: per-agent renewal JITTER + full-
// jitter failure backoff.
//
// `backoff.ts` had no dedicated test file (it was only exercised through
// cert.test.ts). The per-agent wildcard renews ONCE per agent, but a fleet of N
// agents whose certs were all minted in one migration burst MUST NOT renew in the
// same window — otherwise the whole fleet storms Let's Encrypt at `not_after-30d`.
// `renewalDueWithJitter` spreads each agent's renewal instant DETERMINISTICALLY
// (a stable hash of the agent label) across `RENEWAL_SPREAD_MS` (20d), capped so
// the renewal instant stays `<= not_after - 10d` — leaving head-room for the 1h
// failure backoff + the 45s propagation grace before expiry (SCALE-2). The
// existing full-jitter failure backoff (`nextBackoffDelayMs`) is unchanged.
//
// No network, no clock dependency, no filesystem — these are pure functions.

import { describe, expect, it } from "vitest";
import type { CertMeta } from "../../src/funnel/cert.js";
import {
	isRenewalDue,
	nextBackoffDelayMs,
	renewalDueWithJitter,
} from "../../src/funnel/cert.js";

const DAY_MS = 86_400_000;
const RENEWAL_WINDOW_MS = 30 * DAY_MS; // matches backoff.ts
const RENEWAL_SPREAD_MS = 20 * DAY_MS; // matches backoff.ts (PINNED)
const LE_PROD = "https://acme-v02.api.letsencrypt.org/directory";

// A fixed shared `not_after` so the ONLY variable is the per-agent label — this
// is the migration-burst shape (all certs minted together, expiring together).
const NOT_AFTER_MS = Date.UTC(2027, 0, 1);

function metaWithNotAfter(notAfterMs: number): CertMeta {
	return {
		directory_url: LE_PROD,
		not_after: new Date(notAfterMs).toISOString(),
		delegation_id: "x",
		last_attempt_ts: 0,
		consecutive_failures: 0,
	};
}

/**
 * The earliest `now` at which `renewalDueWithJitter` flips this agent to due,
 * for a fixed `not_after`. Found by a binary search over `now` (the predicate is
 * monotone in `now`: once due, always due as `now` advances). Returned RELATIVE
 * to `not_after` as a negative lead-time so it reads as "renews N days early".
 */
function renewalInstantMs(label: string, notAfterMs: number): number {
	const meta = metaWithNotAfter(notAfterMs);
	// Search the [not_after - 30d, not_after] window to 1ms resolution.
	let lo = notAfterMs - RENEWAL_WINDOW_MS - DAY_MS; // a touch before the window
	let hi = notAfterMs;
	while (hi - lo > 1) {
		const mid = Math.floor((lo + hi) / 2);
		if (renewalDueWithJitter(meta, label, mid)) hi = mid;
		else lo = mid;
	}
	return hi;
}

describe("nextBackoffDelayMs — full-jitter failure backoff is UNCHANGED (REQ-CERT-13)", () => {
	it("n=1 yields a delay within full-jitter of base 30s [0, 30000]", () => {
		for (let i = 0; i < 50; i++) {
			const d = nextBackoffDelayMs(1);
			expect(d).toBeGreaterThanOrEqual(0);
			expect(d).toBeLessThanOrEqual(30_000);
		}
	});

	it("doubles the ceiling each failure and caps at 1h", () => {
		for (let i = 0; i < 50; i++) {
			expect(nextBackoffDelayMs(2)).toBeLessThanOrEqual(60_000);
			expect(nextBackoffDelayMs(3)).toBeLessThanOrEqual(120_000);
			expect(nextBackoffDelayMs(99)).toBeLessThanOrEqual(3_600_000);
		}
	});

	it("applies FULL jitter — repeated calls at the same n are not all identical", () => {
		const samples = new Set<number>();
		for (let i = 0; i < 50; i++) samples.add(nextBackoffDelayMs(5));
		expect(samples.size).toBeGreaterThan(1);
	});
});

describe("renewalDueWithJitter — spreads a fleet's renewal instants (REQ-CERT-46, SCALE-2)", () => {
	// 64 distinct agent labels (base32-shaped) standing in for a migration-burst
	// fleet that shares one not_after.
	const labels = Array.from(
		{ length: 64 },
		(_, i) => `agent${i.toString(36)}xyz0123456789abcdef`,
	);

	it("spreads N agents' renewal instants — variance > 0 (NOT all firing at not_after-30d)", () => {
		const instants = labels.map((l) => renewalInstantMs(l, NOT_AFTER_MS));
		const unique = new Set(instants);
		// A real spread: many distinct firing instants, not one clustered moment.
		expect(unique.size).toBeGreaterThan(1);
		const mean = instants.reduce((a, b) => a + b, 0) / instants.length;
		const variance =
			instants.reduce((a, b) => a + (b - mean) ** 2, 0) / instants.length;
		expect(variance).toBeGreaterThan(0);
	});

	it("the offset upper bound is <= RENEWAL_SPREAD_MS (20d): every renewal instant is <= not_after - 10d", () => {
		// renewal instant = not_after - (30d - offset), offset in [0, 20d) ⇒
		// instant in [not_after-30d, not_after-10d]. The 10d floor leaves head-room
		// for the worst-case 1h backoff + 45s propagation grace before expiry.
		const earliest = NOT_AFTER_MS - RENEWAL_WINDOW_MS; // not_after - 30d
		const latest = NOT_AFTER_MS - (RENEWAL_WINDOW_MS - RENEWAL_SPREAD_MS); // - 10d
		for (const label of labels) {
			const instant = renewalInstantMs(label, NOT_AFTER_MS);
			expect(instant).toBeGreaterThanOrEqual(earliest);
			expect(instant).toBeLessThanOrEqual(latest);
		}
	});

	it("is DETERMINISTIC — the same agent label yields the SAME offset across restarts (no re-roll)", () => {
		// A relay that restarts repeatedly must compute the SAME renewal instant
		// every boot (the stable-hash precedent), never re-roll early or never settle.
		for (const label of labels.slice(0, 8)) {
			const first = renewalInstantMs(label, NOT_AFTER_MS);
			const second = renewalInstantMs(label, NOT_AFTER_MS);
			expect(second).toBe(first);
		}
	});

	it("different agent labels generally land on DIFFERENT offsets (de-correlation, not a constant)", () => {
		// Not every pair must differ (hash collisions exist), but the fleet must not
		// collapse to a single offset — assert a healthy fraction of distinct instants.
		const instants = labels.map((l) => renewalInstantMs(l, NOT_AFTER_MS));
		const distinct = new Set(instants).size;
		expect(distinct).toBeGreaterThan(labels.length / 2);
	});

	it("the jitter only DEFERS within the window — never past the 10-day floor (every agent due by not_after-10d)", () => {
		// The jitter SHRINKS the 30-day window by a non-negative offset (≤ 20d), so a
		// jittered relay renews no EARLIER than the plain 30-day boundary and no LATER
		// than not_after-10d. At the 10-day floor EVERY agent is unconditionally due,
		// so the jitter can never defer a renewal past the safety floor before expiry.
		const meta = metaWithNotAfter(NOT_AFTER_MS);
		const plainDue = NOT_AFTER_MS - RENEWAL_WINDOW_MS; // isRenewalDue flips here
		const floor = NOT_AFTER_MS - (RENEWAL_WINDOW_MS - RENEWAL_SPREAD_MS); // -10d
		expect(isRenewalDue(meta, plainDue)).toBe(true);
		for (const label of labels) {
			// Before the plain boundary nobody is due yet (jitter only ever defers).
			expect(renewalDueWithJitter(meta, label, plainDue - DAY_MS)).toBe(false);
			// At the 10-day floor every agent is due (the offset bound guarantees it).
			expect(renewalDueWithJitter(meta, label, floor)).toBe(true);
		}
	});

	it("an already-expired / unparseable not_after is due regardless of the jitter offset", () => {
		const label = "agent0xyz0123456789abcdef";
		const expired = metaWithNotAfter(NOT_AFTER_MS - 400 * DAY_MS);
		expect(renewalDueWithJitter(expired, label, NOT_AFTER_MS)).toBe(true);
		const bad: CertMeta = { ...metaWithNotAfter(NOT_AFTER_MS), not_after: "nope" };
		expect(renewalDueWithJitter(bad, label, NOT_AFTER_MS)).toBe(true);
	});
});
