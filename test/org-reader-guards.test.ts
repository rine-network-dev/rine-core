import { describe, expect, it } from "vitest";
import { isCount, isCryptoFailure, isObject, isText } from "../src/org-reader/guards.js";

describe("org-reader guards", () => {
	it("isObject_rejects_null_arrays_and_primitives", () => {
		expect(isObject({})).toBe(true);
		for (const value of [null, [], "x", 1, undefined]) expect(isObject(value)).toBe(false);
	});

	it("isCount_accepts_only_non_negative_safe_integers", () => {
		expect(isCount(0)).toBe(true);
		for (const value of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, "1", null]) expect(isCount(value)).toBe(false);
	});

	it("isText_accepts_only_strings", () => {
		expect(isText("")).toBe(true);
		expect(isText(1)).toBe(false);
	});

	it("classifies_only_plain_errors_as_crypto_failures", () => {
		expect(isCryptoFailure(new Error("invalid tag"))).toBe(true);
		expect(isCryptoFailure(new TypeError("x"))).toBe(false);
		expect(isCryptoFailure(new RangeError("x"))).toBe(false);
		expect(isCryptoFailure("not an error")).toBe(false);
	});
});
