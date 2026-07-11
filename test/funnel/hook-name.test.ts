// REQ-FSH-07 — hook names become the leading DNS label of the funnel hostname,
// and the relay appends a `--` separator to form the cert subject. A name that
// is un-certifiable (too short → `--` lands in the R-LDH-reserved positions 3–4,
// or charset/hyphen violations) must be rejected at create time, not cold at
// cert issuance. These tests pin `hookNameError`/`isValidHookName` behaviour
// through the public core surface.

import { describe, expect, it } from "vitest";
import {
	HOOK_NAME_MIN_LENGTH,
	hookNameError,
	isValidHookName,
} from "../../src/funnel/secret-store.js";

describe("REQ-FSH-07 — hook name validation", () => {
	describe("accepts certifiable names", () => {
		const valid = [
			"abc", // minimum length boundary (3)
			"default", // the CLI default
			"a-b", // 3 chars total with an interior hyphen
			"web1",
			"my-github-hook",
			"a".repeat(32), // max length boundary (32)
			"xna", // starts with x/n but not the `xn--` ACE prefix
			"xnab", // `xn` prefix without the reserved double-hyphen
		];
		for (const name of valid) {
			it(`accepts '${name}'`, () => {
				expect(hookNameError(name)).toBeNull();
				expect(isValidHookName(name)).toBe(true);
			});
		}
	});

	describe("rejects too-short names (min length rule)", () => {
		for (const name of ["", "a", "xx", "ab"]) {
			it(`rejects '${name}' with a min-length message`, () => {
				const err = hookNameError(name);
				expect(err).not.toBeNull();
				expect(err).toContain(String(HOOK_NAME_MIN_LENGTH));
				expect(isValidHookName(name)).toBe(false);
			});
		}
	});

	describe("rejects R-LDH / charset violations", () => {
		const invalid = [
			"xn--abc", // reserved ACE prefix: `--` in positions 3–4
			"ab--cd", // consecutive hyphens anywhere
			"-abc", // leading hyphen
			"abc-", // trailing hyphen
			"ABC", // uppercase
			"a_bc", // underscore not allowed
			"a bc", // space
			"a".repeat(33), // over max length
		];
		for (const name of invalid) {
			it(`rejects '${name}'`, () => {
				expect(hookNameError(name)).not.toBeNull();
				expect(isValidHookName(name)).toBe(false);
			});
		}
	});
});
