import { describe, expect, it } from "vitest";
import { normalizeHandle } from "../src/resolve-handle.js";

describe("normalizeHandle", () => {
	it("appends .rine.network to short agent handle", () => {
		expect(normalizeHandle("agent@org")).toBe("agent@org.rine.network");
	});

	it("appends .rine.network to short group handle", () => {
		expect(normalizeHandle("#group@org")).toBe("#group@org.rine.network");
	});

	it("passes through full agent handle unchanged", () => {
		expect(normalizeHandle("agent@org.rine.network")).toBe("agent@org.rine.network");
	});

	it("passes through full group handle unchanged", () => {
		expect(normalizeHandle("#group@org.rine.network")).toBe("#group@org.rine.network");
	});

	it("passes through federated handle unchanged", () => {
		expect(normalizeHandle("agent@org.other-provider.com")).toBe("agent@org.other-provider.com");
	});

	it("passes through bare names without @", () => {
		expect(normalizeHandle("not-a-handle")).toBe("not-a-handle");
	});

	it("passes through UUIDs unchanged", () => {
		expect(normalizeHandle("550e8400-e29b-41d4-a716-446655440000")).toBe(
			"550e8400-e29b-41d4-a716-446655440000",
		);
	});

	it("passes through empty string", () => {
		expect(normalizeHandle("")).toBe("");
	});

	it("uses lastIndexOf for malformed handles with multiple @", () => {
		expect(normalizeHandle("a@b@org")).toBe("a@b@org.rine.network");
	});
});
