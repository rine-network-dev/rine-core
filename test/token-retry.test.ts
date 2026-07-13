import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cacheToken } from "../src/config.js";
import { RineApiError } from "../src/errors.js";
import { HttpClient, fetchOAuthToken, getOrRefreshToken } from "../src/http.js";

interface FakeResponseSpec {
	status: number;
	body?: unknown;
	retryAfter?: string;
}

function fakeResponse(spec: FakeResponseSpec) {
	return {
		ok: spec.status >= 200 && spec.status < 300,
		status: spec.status,
		statusText: "x",
		headers: {
			get: (k: string) =>
				k.toLowerCase() === "retry-after" ? (spec.retryAfter ?? null) : null,
		},
		json: () => Promise.resolve(spec.body ?? {}),
	};
}

function stubFetchSequence(specs: FakeResponseSpec[]) {
	const fn = vi.fn();
	for (const s of specs) fn.mockResolvedValueOnce(fakeResponse(s));
	vi.stubGlobal("fetch", fn);
	return fn;
}

const TOKEN_OK: FakeResponseSpec = {
	status: 200,
	body: { access_token: "fresh", expires_in: 3600 },
};

describe("fetchOAuthToken 429 retry (REQ-TS-01)", () => {
	afterEach(() => {
		vi.useRealTimers();
		vi.restoreAllMocks();
	});

	it("waits the Retry-After delay then retries once and succeeds", async () => {
		vi.useFakeTimers();
		const fetchFn = stubFetchSequence([
			{ status: 429, retryAfter: "5" },
			TOKEN_OK,
		]);
		const p = fetchOAuthToken("https://api", "id", "secret");
		await vi.advanceTimersByTimeAsync(0); // first fetch resolves → enters sleep(5s)
		expect(fetchFn).toHaveBeenCalledTimes(1);
		await vi.advanceTimersByTimeAsync(4999);
		expect(fetchFn).toHaveBeenCalledTimes(1); // still waiting
		await vi.advanceTimersByTimeAsync(1);
		expect(fetchFn).toHaveBeenCalledTimes(2);
		expect((await p).access_token).toBe("fresh");
	});

	it("falls back to full-jitter backoff when Retry-After is absent", async () => {
		vi.useFakeTimers();
		const fetchFn = stubFetchSequence([{ status: 429 }, TOKEN_OK]);
		// rng()=0.5, attempt 1 → ceiling 1000ms → 500ms backoff.
		const p = fetchOAuthToken("https://api", "id", "secret", {
			rng: () => 0.5,
		});
		await vi.advanceTimersByTimeAsync(499);
		expect(fetchFn).toHaveBeenCalledTimes(1);
		await vi.advanceTimersByTimeAsync(1);
		expect(fetchFn).toHaveBeenCalledTimes(2);
		expect((await p).access_token).toBe("fresh");
	});

	it("gives up after 3 attempts and throws RineApiError", async () => {
		vi.useFakeTimers();
		const fetchFn = stubFetchSequence([
			{ status: 429, retryAfter: "1", body: { detail: "rate limited" } },
			{ status: 429, retryAfter: "1", body: { detail: "rate limited" } },
			{ status: 429, retryAfter: "1", body: { detail: "rate limited" } },
		]);
		const p = fetchOAuthToken("https://api", "id", "secret");
		const assertion = expect(p).rejects.toThrow(RineApiError);
		await vi.runAllTimersAsync();
		await assertion;
		expect(fetchFn).toHaveBeenCalledTimes(3);
	});

	it("gives up without sleeping when a single Retry-After exceeds the 30s cumulative cap", async () => {
		vi.useFakeTimers();
		const fetchFn = stubFetchSequence([
			{ status: 429, retryAfter: "3600", body: { detail: "rate limited" } },
			TOKEN_OK,
		]);
		const p = fetchOAuthToken("https://api", "id", "secret");
		const assertion = expect(p).rejects.toThrow(RineApiError);
		await vi.runAllTimersAsync();
		await assertion;
		// A 3600s wait blows the 30s budget, so the client never sleeps and never
		// makes the second call. Deleting the cap guard would sleep an hour then
		// succeed with "fresh" and call fetch twice.
		expect(fetchFn).toHaveBeenCalledTimes(1);
	});

	it("gives up once the cumulative Retry-After wait would exceed the 30s cap", async () => {
		vi.useFakeTimers();
		const fetchFn = stubFetchSequence([
			{ status: 429, retryAfter: "20", body: { detail: "rate limited" } },
			{ status: 429, retryAfter: "20", body: { detail: "rate limited" } },
			TOKEN_OK,
		]);
		const p = fetchOAuthToken("https://api", "id", "secret");
		const assertion = expect(p).rejects.toThrow(RineApiError);
		await vi.runAllTimersAsync();
		await assertion;
		// First 20s wait fits (20 ≤ 30) and retries; the second would push the
		// cumulative wait to 40s > 30s, so the client stops at 2 calls rather than
		// riding the 3-attempt bound to a 3rd. Without cumulative tracking each 20s
		// wait passes the per-wait check and the third call would succeed.
		expect(fetchFn).toHaveBeenCalledTimes(2);
	});

	it("fails fast on a non-429 error without retrying", async () => {
		const fetchFn = stubFetchSequence([
			{ status: 400, body: { detail: "invalid_client" } },
		]);
		await expect(fetchOAuthToken("https://api", "bad", "bad")).rejects.toThrow(
			RineApiError,
		);
		expect(fetchFn).toHaveBeenCalledTimes(1);
	});
});

describe("HttpClient.request 429 retry (REQ-TS-03)", () => {
	afterEach(() => {
		vi.useRealTimers();
		vi.restoreAllMocks();
	});

	function makeClient() {
		return new HttpClient({
			tokenFn: async () => "tok",
			apiUrl: "https://api",
			canRefresh: false,
		});
	}

	it("retries once honoring Retry-After then returns the body", async () => {
		vi.useFakeTimers();
		const fetchFn = stubFetchSequence([
			{ status: 429, retryAfter: "2" },
			{ status: 200, body: { ok: true } },
		]);
		const client = makeClient();
		const p = client.get("/agents");
		await vi.advanceTimersByTimeAsync(2000);
		expect(await p).toEqual({ ok: true });
		expect(fetchFn).toHaveBeenCalledTimes(2);
	});

	it("retries only once — a second 429 surfaces as RineApiError", async () => {
		vi.useFakeTimers();
		const fetchFn = stubFetchSequence([
			{ status: 429, retryAfter: "1", body: { detail: "slow down" } },
			{ status: 429, retryAfter: "1", body: { detail: "slow down" } },
		]);
		const client = makeClient();
		const p = client.get("/agents");
		const assertion = expect(p).rejects.toThrow(RineApiError);
		await vi.runAllTimersAsync();
		await assertion;
		expect(fetchFn).toHaveBeenCalledTimes(2);
	});
});

describe("getOrRefreshToken jittered margin (REQ-TS-02, herd desync)", () => {
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-margin-test-"));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
		vi.restoreAllMocks();
	});

	it("a larger refresh margin refreshes a near-expiry token that a smaller margin still trusts", async () => {
		// Token has ~90s of life left. Margin 60 ⇒ still cached; margin 120 ⇒ refresh.
		cacheToken(dir, "default", { access_token: "cached", expires_in: 90 });
		stubFetchSequence([TOKEN_OK]);
		const entry = { client_id: "id", client_secret: "secret" };

		const small = await getOrRefreshToken(
			dir,
			"https://api",
			entry,
			"default",
			{
				refreshMargin: 60,
			},
		);
		expect(small).toBe("cached");

		const large = await getOrRefreshToken(
			dir,
			"https://api",
			entry,
			"default",
			{
				refreshMargin: 120,
			},
		);
		expect(large).toBe("fresh");
	});
});
