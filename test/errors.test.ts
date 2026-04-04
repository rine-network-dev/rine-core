import { describe, expect, it } from "vitest";
import { RineApiError, formatError } from "../src/errors.js";

describe("RineApiError", () => {
	it("stores status, detail, and raw response", () => {
		const raw = { some: "data" };
		const err = new RineApiError(404, "Not found", raw);
		expect(err.status).toBe(404);
		expect(err.detail).toBe("Not found");
		expect(err.raw).toBe(raw);
		expect(err.name).toBe("RineApiError");
		expect(err.message).toBe("404: Not found");
	});

	it("works without raw response", () => {
		const err = new RineApiError(500, "Server error");
		expect(err.raw).toBeUndefined();
	});

	it("is an instance of Error", () => {
		const err = new RineApiError(401, "Unauthorized");
		expect(err).toBeInstanceOf(Error);
		expect(err).toBeInstanceOf(RineApiError);
	});
});

describe("formatError", () => {
	it("extracts detail from RineApiError", () => {
		const err = new RineApiError(400, "Bad request");
		expect(formatError(err)).toBe("Bad request");
	});

	it("extracts message from generic Error", () => {
		expect(formatError(new Error("oops"))).toBe("oops");
	});

	it("converts non-Error to string", () => {
		expect(formatError("string error")).toBe("string error");
		expect(formatError(42)).toBe("42");
		expect(formatError(null)).toBe("null");
	});
});
