import * as fs from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HttpClient, fetchOAuthToken, getOrRefreshToken } from "../src/http.js";
import { RineApiError } from "../src/errors.js";
import { cacheToken } from "../src/config.js";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-http-test-"));
}

function mockFetch(status: number, body: unknown, ok?: boolean): void {
	vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
		ok: ok ?? (status >= 200 && status < 300),
		status,
		statusText: status === 200 ? "OK" : "Error",
		json: () => Promise.resolve(body),
	}));
}

describe("HttpClient", () => {
	afterEach(() => vi.restoreAllMocks());

	it("sends GET with auth header", async () => {
		mockFetch(200, { result: "ok" });
		const client = new HttpClient({
			tokenFn: async () => "test-token",
			apiUrl: "https://api.test",
		});
		const result = await client.get("/agents");
		expect(result).toEqual({ result: "ok" });
		expect(fetch).toHaveBeenCalledWith(
			"https://api.test/agents",
			expect.objectContaining({
				method: "GET",
				headers: expect.objectContaining({ Authorization: "Bearer test-token" }),
			}),
		);
	});

	it("sends POST with JSON body", async () => {
		mockFetch(200, { id: "123" });
		const client = new HttpClient({
			tokenFn: async () => "tok",
			apiUrl: "https://api.test",
		});
		await client.post("/messages", { to: "agent-1" });
		expect(fetch).toHaveBeenCalledWith(
			"https://api.test/messages",
			expect.objectContaining({
				method: "POST",
				body: JSON.stringify({ to: "agent-1" }),
				headers: expect.objectContaining({ "Content-Type": "application/json" }),
			}),
		);
	});

	it("appends query params to GET", async () => {
		mockFetch(200, []);
		const client = new HttpClient({
			tokenFn: async () => "tok",
			apiUrl: "https://api.test",
		});
		await client.get("/agents", { limit: 10, active: true });
		expect(fetch).toHaveBeenCalledWith(
			expect.stringContaining("limit=10"),
			expect.anything(),
		);
	});

	it("retries on 401 when canRefresh is true", async () => {
		let callCount = 0;
		vi.stubGlobal("fetch", vi.fn().mockImplementation(() => {
			callCount++;
			if (callCount === 1) {
				return Promise.resolve({ ok: false, status: 401, statusText: "Unauthorized", json: () => Promise.resolve({ detail: "expired" }) });
			}
			return Promise.resolve({ ok: true, status: 200, statusText: "OK", json: () => Promise.resolve({ ok: true }) });
		}));

		const tokenFn = vi.fn()
			.mockResolvedValueOnce("old-token")
			.mockResolvedValueOnce("new-token");

		const client = new HttpClient({
			tokenFn,
			apiUrl: "https://api.test",
			canRefresh: true,
		});

		await client.get("/test");
		expect(tokenFn).toHaveBeenCalledTimes(2);
		expect(tokenFn).toHaveBeenLastCalledWith(true); // force refresh
	});

	it("throws RineApiError on non-ok response", async () => {
		mockFetch(403, { detail: "Forbidden" }, false);
		const client = new HttpClient({
			tokenFn: async () => "tok",
			apiUrl: "https://api.test",
			canRefresh: false,
		});
		await expect(client.get("/secret")).rejects.toThrow(RineApiError);
	});

	it("returns undefined for 204 No Content", async () => {
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
			ok: true,
			status: 204,
			statusText: "No Content",
		}));
		const client = new HttpClient({
			tokenFn: async () => "tok",
			apiUrl: "https://api.test",
		});
		const result = await client.delete("/resource");
		expect(result).toBeUndefined();
	});

	it("merges extra headers", async () => {
		mockFetch(200, {});
		const client = new HttpClient({
			tokenFn: async () => "tok",
			apiUrl: "https://api.test",
			defaultHeaders: { "X-Default": "yes" },
		});
		await client.get("/test", undefined, { "X-Extra": "hello" });
		expect(fetch).toHaveBeenCalledWith(
			expect.anything(),
			expect.objectContaining({
				headers: expect.objectContaining({
					"X-Default": "yes",
					"X-Extra": "hello",
				}),
			}),
		);
	});
});

describe("HttpClient.publicGet", () => {
	afterEach(() => vi.restoreAllMocks());

	it("sends unauthenticated GET", async () => {
		mockFetch(200, { items: [] });
		const result = await HttpClient.publicGet("https://api.test", "/directory/agents");
		expect(result).toEqual({ items: [] });
		expect(fetch).toHaveBeenCalledWith(
			"https://api.test/directory/agents",
			expect.objectContaining({
				headers: { Accept: "application/json" },
			}),
		);
	});

	it("appends URLSearchParams", async () => {
		mockFetch(200, []);
		const params = new URLSearchParams({ q: "test" });
		await HttpClient.publicGet("https://api.test", "/search", params);
		expect(fetch).toHaveBeenCalledWith(
			"https://api.test/search?q=test",
			expect.anything(),
		);
	});
});

describe("fetchOAuthToken", () => {
	afterEach(() => vi.restoreAllMocks());

	it("posts client credentials and returns token", async () => {
		mockFetch(200, { access_token: "tok", expires_in: 3600 });
		const result = await fetchOAuthToken("https://api.test", "client-id", "client-secret");
		expect(result.access_token).toBe("tok");
		expect(result.expires_in).toBe(3600);
	});

	it("throws RineApiError on failure", async () => {
		mockFetch(400, { detail: "invalid_client" }, false);
		await expect(fetchOAuthToken("https://api.test", "bad", "bad"))
			.rejects.toThrow(RineApiError);
	});
});

describe("getOrRefreshToken", () => {
	let dir: string;

	beforeEach(() => { dir = makeTmpDir(); });
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
		vi.restoreAllMocks();
	});

	it("returns envToken directly when provided", async () => {
		const result = await getOrRefreshToken(dir, "https://api", undefined, "default", {
			envToken: "env-tok",
		});
		expect(result).toBe("env-tok");
	});

	it("returns cached token when not expired", async () => {
		cacheToken(dir, "default", { access_token: "cached", expires_in: 7200 });
		const result = await getOrRefreshToken(
			dir, "https://api",
			{ client_id: "id", client_secret: "secret" },
			"default",
		);
		expect(result).toBe("cached");
	});

	it("fetches new token when cache is expired", async () => {
		// Write an expired cache entry
		cacheToken(dir, "default", { access_token: "old", expires_in: -100 });
		mockFetch(200, { access_token: "fresh", expires_in: 3600 });

		const result = await getOrRefreshToken(
			dir, "https://api",
			{ client_id: "id", client_secret: "secret" },
			"default",
		);
		expect(result).toBe("fresh");
	});

	it("throws when no credentials and no cache", async () => {
		await expect(getOrRefreshToken(dir, "https://api", undefined, "default"))
			.rejects.toThrow("No credentials found");
	});
});
