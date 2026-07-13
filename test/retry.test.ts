import { describe, expect, it } from "vitest";
import { RineApiError } from "../src/errors.js";
import {
	fullJitterBackoffMs,
	jitteredRefreshMargin,
	retryAfterMsFromError,
	retryAfterMsFromResponse,
} from "../src/retry.js";

function resWithRetryAfter(value: string | null): Response {
	return { headers: { get: () => value } } as unknown as Response;
}

describe("retryAfterMsFromResponse", () => {
	it("converts a numeric Retry-After header to milliseconds", () => {
		expect(retryAfterMsFromResponse(resWithRetryAfter("2"))).toBe(2000);
	});

	it("returns 0 when the header is absent", () => {
		expect(retryAfterMsFromResponse(resWithRetryAfter(null))).toBe(0);
	});

	it("returns 0 for a non-numeric or non-positive header", () => {
		expect(retryAfterMsFromResponse(resWithRetryAfter("soon"))).toBe(0);
		expect(retryAfterMsFromResponse(resWithRetryAfter("0"))).toBe(0);
	});
});

describe("retryAfterMsFromError", () => {
	it("reads Retry-After off a RineApiError carrying a Response", () => {
		// Real Response so the `raw instanceof Response` guard passes (mirrors the
		// funnel dns-post backstop path).
		const res = new Response(null, {
			status: 429,
			headers: { "retry-after": "3" },
		});
		const err = new RineApiError(429, "rate limited", res);
		expect(retryAfterMsFromError(err)).toBe(3000);
	});

	it("returns 0 when raw is not a Response", () => {
		expect(retryAfterMsFromError(new RineApiError(429, "x"))).toBe(0);
	});
});

describe("fullJitterBackoffMs", () => {
	it("stays within [0, base*2^(attempt-1)] using the injected rng", () => {
		// rng()=1 yields the ceiling (floor of ceiling*1 with +1 slack lands on ceiling).
		expect(fullJitterBackoffMs(1, () => 0)).toBe(0);
		expect(fullJitterBackoffMs(1, () => 0.999999)).toBeLessThanOrEqual(1000);
		// attempt 3 → ceiling 4000ms
		expect(fullJitterBackoffMs(3, () => 0.5)).toBeGreaterThan(0);
		expect(fullJitterBackoffMs(3, () => 0.999999)).toBeLessThanOrEqual(4000);
	});
});

describe("jitteredRefreshMargin", () => {
	it("maps rng into [60, 180) seconds, drawn from the injected rng", () => {
		expect(jitteredRefreshMargin(() => 0)).toBe(60);
		expect(jitteredRefreshMargin(() => 0.5)).toBe(120);
	});

	it("two clients with different rng seeds get distinct refresh margins", () => {
		const a = jitteredRefreshMargin(() => 0.1);
		const b = jitteredRefreshMargin(() => 0.9);
		expect(a).not.toBe(b);
	});
});
