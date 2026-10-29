// Each identity check keeps its own case rule: path and lookup checks accept
// either case, while the key-derivation check accepts only the lowercase
// canonical form the server issues.
import { describe, expect, it } from "vitest";
import { canonicalUuid } from "../src/crypto/derive.js";
import { isPathSafeId } from "../src/crypto/keys.js";
import { UUID_RE } from "../src/resolve-handle.js";

const LOWER = "abcdef01-2345-4789-8abc-def012345678";
const UPPER = "ABCDEF01-2345-4789-8ABC-DEF012345678";

describe("uuid case rules", () => {
	it("accepts the lowercase form everywhere", () => {
		expect(isPathSafeId(LOWER)).toBe(true);
		expect(UUID_RE.test(LOWER)).toBe(true);
		expect(canonicalUuid(LOWER, "agent id")).toBe(LOWER);
	});

	it("accepts the uppercase form for paths and lookups only", () => {
		expect(isPathSafeId(UPPER)).toBe(true);
		expect(UUID_RE.test(UPPER)).toBe(true);
		expect(() => canonicalUuid(UPPER, "agent id")).toThrow(
			"non-canonical agent id",
		);
	});
});
