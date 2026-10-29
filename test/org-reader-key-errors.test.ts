import { describe, expect, it } from "vitest";
import { KeyChainError } from "../src/crypto/key-chain.js";
import { RineApiError } from "../src/errors.js";
import {
	ReaderNetworkError,
	TokenBucket,
	createBudgetedFetch,
} from "../src/org-reader/fetch-budget.js";
import { isKeysUnavailable } from "../src/org-reader/key-errors.js";

const api = (status: number) => new RineApiError(status, "x");

describe("isKeysUnavailable", () => {
	it("is_true_when_the_network_failed", () => {
		expect(
			isKeysUnavailable(new ReaderNetworkError("the request failed")),
		).toBe(true);
	});

	it.each([429, 500, 502, 503])("is_true_for_a_%i_answer", (status) => {
		expect(isKeysUnavailable(api(status))).toBe(true);
	});

	it.each([400, 401, 403, 404, 410])("is_false_for_a_%i_answer", (status) => {
		expect(isKeysUnavailable(api(status))).toBe(false);
	});

	it("is_false_for_a_broken_key_chain_and_for_other_errors", () => {
		expect(isKeysUnavailable(new KeyChainError("agent_cert"))).toBe(false);
		expect(isKeysUnavailable(new Error("boom"))).toBe(false);
		expect(isKeysUnavailable(new TypeError("fetch failed"))).toBe(false);
		expect(isKeysUnavailable(undefined)).toBe(false);
	});
});

describe("the fetch wrapper", () => {
	it("turns_a_rejected_fetch_into_a_reader_network_error", async () => {
		const budgeted = createBudgetedFetch({
			apiUrl: "https://api.test",
			bucket: new TokenBucket(),
			fetch: () => Promise.reject(new TypeError("fetch failed")),
		});
		const err = await budgeted("https://api.test/agents/a/keys").catch(
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(ReaderNetworkError);
		expect(isKeysUnavailable(err)).toBe(true);
		expect((err as ReaderNetworkError).cause).toBeInstanceOf(TypeError);
	});

	it("leaves_an_abort_alone", async () => {
		const aborted = new DOMException("aborted", "AbortError");
		const budgeted = createBudgetedFetch({
			apiUrl: "https://api.test",
			bucket: new TokenBucket(),
			fetch: () => Promise.reject(aborted),
		});
		await expect(budgeted("https://api.test/x")).rejects.toBe(aborted);
	});
});
