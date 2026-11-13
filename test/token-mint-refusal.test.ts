import { afterEach, describe, expect, it, vi } from "vitest";
import { RineApiError } from "../src/errors.js";
import { fetchOAuthToken } from "../src/http.js";
import { TEST_SIGNER } from "./signer-fixture.js";

function stubRefusal(status: number, body: unknown): void {
	vi.stubGlobal(
		"fetch",
		vi.fn().mockResolvedValue({
			ok: false,
			status,
			statusText: "Bad Request",
			headers: { get: () => null },
			json: () => Promise.resolve(body),
		}),
	);
}

describe("fetchOAuthToken failed mint text", () => {
	afterEach(() => vi.restoreAllMocks());

	it("renders the RFC 6749 error_description of a hold refusal", async () => {
		stubRefusal(400, {
			error: "unauthorized_client",
			reason: "agent_suspended",
			error_description: "This agent is suspended by its organisation.",
		});
		const err = (await fetchOAuthToken("https://api", TEST_SIGNER).catch(
			(e) => e,
		)) as RineApiError;
		expect(err).toBeInstanceOf(RineApiError);
		expect(err.message).toContain("This agent is suspended by its organisation.");
		expect(err.code).toBe("unauthorized_client");
	});

	it("falls back to detail when the body carries no error_description", async () => {
		stubRefusal(401, { detail: "Invalid client assertion" });
		const err = (await fetchOAuthToken("https://api", TEST_SIGNER).catch(
			(e) => e,
		)) as RineApiError;
		expect(err.message).toContain("Invalid client assertion");
	});

	it("keeps the generic text when the body names neither", async () => {
		stubRefusal(500, {});
		const err = (await fetchOAuthToken("https://api", TEST_SIGNER).catch(
			(e) => e,
		)) as RineApiError;
		expect(err.message).toContain("Token request failed");
	});
});
