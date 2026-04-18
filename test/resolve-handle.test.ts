import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock HttpClient.publicGet before importing the module
const mockPublicGet = vi.fn();
vi.mock("../src/http.js", () => ({
	HttpClient: {
		publicGet: (...args: unknown[]) => mockPublicGet(...args),
	},
}));

const { resolveHandleViaWebFinger } = await import("../src/resolve-handle.js");

describe("resolveHandleViaWebFinger", () => {
	beforeEach(() => {
		mockPublicGet.mockReset();
	});

	it("returns UUID when WebFinger has a matching alias", async () => {
		mockPublicGet.mockResolvedValue({
			aliases: [
				"https://rine.network/agents/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			],
		});
		const result = await resolveHandleViaWebFinger("https://rine.network", "bot@org.rine.network");
		expect(result).toBe("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
	});

	it("returns original string when WebFinger fails (network error)", async () => {
		mockPublicGet.mockRejectedValue(new Error("Network error"));
		const result = await resolveHandleViaWebFinger("https://rine.network", "bot@org.rine.network");
		expect(result).toBe("bot@org.rine.network");
	});

	it("returns original string when no UUID alias found", async () => {
		mockPublicGet.mockResolvedValue({
			aliases: ["https://example.com/some-other-link"],
		});
		const result = await resolveHandleViaWebFinger("https://rine.network", "bot@org.rine.network");
		expect(result).toBe("bot@org.rine.network");
	});

	it("normalizes short handle before WebFinger query", async () => {
		mockPublicGet.mockResolvedValue({
			aliases: [
				"https://rine.network/agents/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			],
		});
		const result = await resolveHandleViaWebFinger("https://rine.network", "bot@org");
		expect(result).toBe("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
		expect(mockPublicGet).toHaveBeenCalledWith(
			"https://rine.network",
			"/.well-known/webfinger",
			expect.objectContaining({})
		);
		const params = mockPublicGet.mock.calls[0]![2] as URLSearchParams;
		expect(params.get("resource")).toBe("acct:bot@org.rine.network");
	});
});
