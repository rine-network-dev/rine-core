import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpClient } from "../src/http.js";

function mockFetch(status: number, body: unknown): void {
	vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
		ok: status >= 200 && status < 300,
		status,
		statusText: status === 200 ? "OK" : "Error",
		json: () => Promise.resolve(body),
	}));
}

describe("HttpClient.markDelivered", () => {
	afterEach(() => vi.restoreAllMocks());

	it("calls POST with correct path and body", async () => {
		mockFetch(200, { marked: 3 });
		const client = new HttpClient({
			tokenFn: async () => "tok",
			apiUrl: "https://api.test",
		});

		await client.markDelivered("agent-123", ["msg-1", "msg-2", "msg-3"]);

		expect(fetch).toHaveBeenCalledWith(
			"https://api.test/agents/agent-123/messages/mark-delivered",
			expect.objectContaining({
				method: "POST",
				body: JSON.stringify({ message_ids: ["msg-1", "msg-2", "msg-3"] }),
			}),
		);
	});

	it("returns { marked: number } from response", async () => {
		mockFetch(200, { marked: 2 });
		const client = new HttpClient({
			tokenFn: async () => "tok",
			apiUrl: "https://api.test",
		});

		const result = await client.markDelivered("agent-1", ["msg-a"]);
		expect(result).toEqual({ marked: 2 });
	});

	it("passes extra headers through", async () => {
		mockFetch(200, { marked: 1 });
		const client = new HttpClient({
			tokenFn: async () => "tok",
			apiUrl: "https://api.test",
		});

		await client.markDelivered("agent-1", ["msg-a"], { "X-Rine-Agent": "agent-1" });

		expect(fetch).toHaveBeenCalledWith(
			expect.anything(),
			expect.objectContaining({
				headers: expect.objectContaining({ "X-Rine-Agent": "agent-1" }),
			}),
		);
	});
});
