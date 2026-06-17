// B13 (TS half) — REQ-CERT-47 / REQ-TIER-02 / AUD-F7: the FunnelTier values are a
// SHARED CONTRACT that MUST be byte-identical across the language boundary.
//
// The TS `api-types.ts` `termination` field is typed `FunnelTier`
// ("zero_trust" | "shared_edge"), with `FUNNEL_TIERS` as its exhaustive runtime
// witness. The authoritative source of the tier strings is the Python
// `funnel_naming.FunnelTier` StrEnum. This test reads the Python enum DIRECTLY
// from source and asserts the TS witness EXACTLY equals it (same values, same
// order, same count) — so a future third tier (or a renamed value) added on one
// side and forgotten on the other FAILS the build instead of silently drifting
// into a mis-tiered hostname / a DB CHECK violation at runtime.
//
// No network, no DB — a pure source-vs-source contract assertion.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FUNNEL_TIERS, type FunnelTier } from "../../src/api-types.js";

// `__dirname` is `rine-core/test/funnel`; the Python enum lives in the backend.
const PY_FUNNEL_NAMING = join(
	__dirname,
	"..",
	"..",
	"..",
	"src",
	"rine",
	"api",
	"funnel_naming.py",
);

/**
 * Extract the string VALUES assigned inside the Python `FunnelTier(StrEnum)`
 * block, in source order. Matches `NAME = "value"` lines between the class
 * declaration and the next top-level `def`/`class`. Deliberately strict (only the
 * enum body, not the whole file) so an unrelated string elsewhere never leaks in.
 */
function pythonFunnelTierValues(): string[] {
	const src = readFileSync(PY_FUNNEL_NAMING, "utf-8");
	const classIdx = src.indexOf("class FunnelTier(StrEnum):");
	expect(classIdx, "FunnelTier StrEnum must exist in funnel_naming.py").toBeGreaterThanOrEqual(
		0,
	);
	const after = src.slice(classIdx);
	// The enum body ends at the next top-level `def `/`class ` (col 0).
	const endMatch = after.slice(1).search(/\n(?:def |class )/);
	const body = endMatch >= 0 ? after.slice(0, endMatch + 1) : after;
	const values: string[] = [];
	const memberRe = /^\s+[A-Z_]+\s*=\s*"([^"]+)"/gm;
	let m: RegExpExecArray | null = memberRe.exec(body);
	while (m !== null) {
		const value = m[1];
		if (value !== undefined) values.push(value);
		m = memberRe.exec(body);
	}
	return values;
}

describe("B13 — FunnelTier contract lockstep across the TS/Python boundary (AUD-F7)", () => {
	it("the TS FUNNEL_TIERS witness EXACTLY equals the Python FunnelTier enum values (same set, same order)", () => {
		const pyValues = pythonFunnelTierValues();
		expect(pyValues.length).toBeGreaterThan(0);
		// Byte-identical, order-sensitive: catches an added/renamed/reordered tier.
		expect([...FUNNEL_TIERS]).toEqual(pyValues);
	});

	it("pins the exact two-tier contract — the only spellings anywhere are zero_trust and shared_edge", () => {
		// A literal pin (independent of the Python parse) so a regression that
		// changed BOTH sides in lockstep to a WRONG value still trips here.
		expect([...FUNNEL_TIERS]).toEqual(["zero_trust", "shared_edge"]);
	});

	it("FUNNEL_TIERS is the exhaustive witness of the FunnelTier union (no value outside the union)", () => {
		// Type-level: every entry is assignable to FunnelTier (compile-time), and the
		// runtime set has no duplicates (a duplicated value would mask a drift).
		const set = new Set<FunnelTier>(FUNNEL_TIERS);
		expect(set.size).toBe(FUNNEL_TIERS.length);
	});

	it("neither side uses the hyphenated CLI spelling as an enum value (zero-trust/shared-edge are flag aliases only)", () => {
		// The CLI flag accepts `zero-trust`/`shared-edge` but the wire/enum value is
		// always the underscore form — guard the underscore is what crosses the wire.
		for (const v of FUNNEL_TIERS) {
			expect(v).not.toContain("-");
			expect(v).toContain("_");
		}
	});
});
