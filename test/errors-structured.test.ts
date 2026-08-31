// The 422 that refuses an MLS commit names every Welcome recipient it would not
// accept in a `rejected` array. A batched admission answers that refusal by
// dropping exactly those ids and retrying the batch once, so the array has to
// survive the trip from the wire into the thrown error — it used to be discarded,
// leaving a caller to pattern-match UUIDs out of the prose `detail`.
//
// Every test here drives the public surface (HttpClient / rineErrorFromResponse)
// against a stubbed global fetch and real `Response` objects, because the body
// being a one-shot stream is the whole reason the field went missing.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	RineApiError,
	formatError,
	rejectedAgents,
	rineErrorFromResponse,
} from "../src/errors.js";
import { HttpClient } from "../src/http.js";
import { retryAfterMsFromError } from "../src/retry.js";

function jsonResponse(
	status: number,
	body: unknown,
	statusText = "Error",
	headers: Record<string, string> = {},
): Response {
	return new Response(JSON.stringify(body), {
		status,
		statusText,
		headers: { "content-type": "application/json", ...headers },
	});
}

/** Fresh Response per call — a body stream can only be read once. */
function stubFetch(make: () => Response): void {
	vi.stubGlobal(
		"fetch",
		vi.fn().mockImplementation(() => Promise.resolve(make())),
	);
}

function client(): HttpClient {
	return new HttpClient({
		tokenFn: async () => "test-token",
		apiUrl: "https://api.test",
	});
}

/** The body `POST /groups/{id}/mls/commit` returns when it refuses recipients. */
const WELCOME_REJECTED = {
	error: "welcome_recipient_rejected",
	detail:
		"2 of this commit's Welcome recipients cannot be addressed: " +
		"11111111-1111-4111-8111-111111111111 is not a known agent, or has been revoked; " +
		"22222222-2222-4222-8222-222222222222 is not a member of this group and holds " +
		"no unresolved invitation to it. Post the commit again without them.",
	rejected: [
		{
			agent_id: "11111111-1111-4111-8111-111111111111",
			reason: "not_found_or_revoked",
		},
		{
			agent_id: "22222222-2222-4222-8222-222222222222",
			reason: "not_enrolled",
		},
	],
};

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("errors every shipped client already reads", () => {
	it("parses a typed refusal into the same status, detail and code as before", async () => {
		stubFetch(() =>
			jsonResponse(409, {
				error: "epoch_conflict",
				detail: "MLS epoch conflict",
			}),
		);
		const err = await client()
			.post("/groups/g1/mls/commit", {})
			.catch((e: unknown) => e);

		expect(err).toBeInstanceOf(RineApiError);
		const api = err as RineApiError;
		expect(api.status).toBe(409);
		expect(api.detail).toBe("MLS epoch conflict");
		expect(api.code).toBe("epoch_conflict");
		expect(api.name).toBe("RineApiError");
		expect(api.message).toBe("409: MLS epoch conflict");
		expect(formatError(api)).toBe("MLS epoch conflict");
		expect(api.raw).toBeInstanceOf(Response);
	});

	it("joins a pydantic validation array into one sentence, unchanged", async () => {
		stubFetch(() =>
			jsonResponse(422, {
				detail: [
					{
						loc: ["body", "visibility"],
						msg: "Field required",
						type: "missing",
					},
					{ loc: ["body", "handle"], msg: "too long", type: "string_too_long" },
				],
			}),
		);
		const err = (await client()
			.post("/groups", {})
			.catch((e: unknown) => e)) as RineApiError;

		expect(err.detail).toBe("Field required; too long");
		expect(err.code).toBeUndefined();
	});

	it("falls back to the status line when the body is not JSON", async () => {
		stubFetch(
			() =>
				new Response("<html>502</html>", {
					status: 502,
					statusText: "Bad Gateway",
				}),
		);
		const err = (await client()
			.get("/agents")
			.catch((e: unknown) => e)) as RineApiError;

		expect(err.detail).toBe("Bad Gateway");
		expect(err.code).toBeUndefined();
		expect(err.body).toBeUndefined();
	});

	it("still carries the Response as raw, so Retry-After resolves off it", async () => {
		const err = await rineErrorFromResponse(
			jsonResponse(
				429,
				{ error: "rate_limited", detail: "Slow down" },
				"Too Many Requests",
				{
					"retry-after": "3",
				},
			),
		);

		expect(retryAfterMsFromError(err)).toBe(3000);
	});
});

describe("structured error data", () => {
	it("carries the rejected recipients off a refused commit", async () => {
		stubFetch(() => jsonResponse(422, WELCOME_REJECTED));
		const err = (await client()
			.post("/groups/g1/mls/commit", {})
			.catch((e: unknown) => e)) as RineApiError;

		expect(err.code).toBe("welcome_recipient_rejected");
		expect(rejectedAgents(err)).toEqual([
			{
				agent_id: "11111111-1111-4111-8111-111111111111",
				reason: "not_found_or_revoked",
			},
			{
				agent_id: "22222222-2222-4222-8222-222222222222",
				reason: "not_enrolled",
			},
		]);
	});

	it("carries it on the unauthenticated path too", async () => {
		stubFetch(() =>
			jsonResponse(422, { error: "ssrf_blocked", detail: "no", rejected: [] }),
		);
		const err = (await HttpClient.publicGet(
			"https://api.test",
			"/directory/agents",
		).catch((e: unknown) => e)) as RineApiError;

		expect(err.code).toBe("ssrf_blocked");
		expect(err.body?.rejected).toEqual([]);
	});

	it("carries fields the client does not know about", async () => {
		stubFetch(() =>
			jsonResponse(409, {
				error: "group_full",
				detail: "This group is full",
				members: 430,
				outstanding: 70,
			}),
		);
		const err = (await client()
			.post("/groups/g1/invite", {})
			.catch((e: unknown) => e)) as RineApiError;

		expect(err.body).toMatchObject({ members: 430, outstanding: 70 });
	});

	it("reads nothing off raw, because the client already spent that body", async () => {
		stubFetch(() => jsonResponse(422, WELCOME_REJECTED));
		const err = (await client()
			.post("/groups/g1/mls/commit", {})
			.catch((e: unknown) => e)) as RineApiError;

		const raw = err.raw as Response;
		expect(raw.bodyUsed).toBe(true);
		await expect(raw.json()).rejects.toThrow();
	});
});

describe("rejectedAgents", () => {
	it("is empty for anything that is not a rine API error", () => {
		expect(rejectedAgents(new Error("boom"))).toEqual([]);
		expect(rejectedAgents(undefined)).toEqual([]);
		expect(rejectedAgents("welcome_recipient_rejected")).toEqual([]);
	});

	it("is empty for an error with no body and for one with no rejected array", () => {
		expect(rejectedAgents(new RineApiError(500, "boom"))).toEqual([]);
		expect(
			rejectedAgents(
				new RineApiError(409, "x", undefined, "epoch_conflict", {
					error: "epoch_conflict",
					detail: "x",
				}),
			),
		).toEqual([]);
	});

	it("is empty when rejected is not an array", async () => {
		const err = await rineErrorFromResponse(
			jsonResponse(422, { error: "e", detail: "d", rejected: "everyone" }),
		);
		expect(rejectedAgents(err)).toEqual([]);
	});

	it("keeps an entry whose reason is missing, and drops one that names nobody", async () => {
		const err = await rineErrorFromResponse(
			jsonResponse(422, {
				error: "welcome_recipient_rejected",
				detail: "d",
				rejected: [
					{ agent_id: "33333333-3333-4333-8333-333333333333" },
					{ reason: "not_enrolled" },
					{ agent_id: 42, reason: "not_enrolled" },
					null,
				],
			}),
		);

		expect(rejectedAgents(err)).toEqual([
			{ agent_id: "33333333-3333-4333-8333-333333333333" },
		]);
	});
});
