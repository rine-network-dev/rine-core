// A revoked principal is refused with a 401 that names which principal was
// revoked — the agent or the branch. Retrying cannot help and the credentials
// are not at fault, so the refusal is a typed error a caller can branch on
// rather than a status it has to re-derive from prose. The token mint names the
// scope only once the key assertion verified, so a plain bad assertion stays an
// ordinary RineApiError.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	PrincipalRevokedError,
	RineApiError,
	isPrincipalRevokedError,
	rineErrorFromResponse,
	scopeOfRevokedCode,
} from "../src/errors.js";
import { HttpClient, fetchOAuthToken } from "../src/http.js";
import { TEST_SIGNER } from "./signer-fixture.js";

function jsonResponse(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		statusText: "Error",
		headers: { "content-type": "application/json" },
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
		canRefresh: false,
	});
}

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("a bearer route refusing a revoked principal", () => {
	it("test_revoked_scope_when_bearer_401_names_agent_then_typed_error_carries_agent", async () => {
		const err = await rineErrorFromResponse(
			jsonResponse(401, {
				error: "agent_revoked",
				detail: "Agent is revoked",
			}),
		);

		expect(err).toBeInstanceOf(PrincipalRevokedError);
		expect(err).toBeInstanceOf(RineApiError);
		const revoked = err as PrincipalRevokedError;
		expect(revoked.scope).toBe("agent");
		expect(revoked.status).toBe(401);
		expect(revoked.code).toBe("agent_revoked");
		expect(revoked.detail).toBe("Agent is revoked");
		expect(revoked.name).toBe("PrincipalRevokedError");
	});

	it("test_revoked_scope_when_bearer_401_names_branch_then_typed_error_carries_branch", async () => {
		const err = await rineErrorFromResponse(
			jsonResponse(401, { error: "branch_revoked" }),
		);

		expect(err).toBeInstanceOf(PrincipalRevokedError);
		expect((err as PrincipalRevokedError).scope).toBe("branch");
	});

	it("test_revoked_scope_when_401_names_another_code_then_ordinary_api_error", async () => {
		const err = await rineErrorFromResponse(
			jsonResponse(401, { error: "AuthenticationError", detail: "x" }),
		);

		expect(err).toBeInstanceOf(RineApiError);
		expect(err).not.toBeInstanceOf(PrincipalRevokedError);
	});

	it("test_revoked_scope_when_status_is_not_401_then_ordinary_api_error", async () => {
		const unprocessable = await rineErrorFromResponse(
			jsonResponse(422, { error: "agent_revoked" }),
		);
		const forbidden = await rineErrorFromResponse(
			jsonResponse(403, { error: "branch_revoked" }),
		);

		expect(unprocessable).not.toBeInstanceOf(PrincipalRevokedError);
		expect(forbidden).not.toBeInstanceOf(PrincipalRevokedError);
	});

	it("test_revoked_scope_when_401_names_a_hostile_code_then_ordinary_api_error", async () => {
		const constructor = await rineErrorFromResponse(
			jsonResponse(401, { error: "constructor" }),
		);
		const proto = await rineErrorFromResponse(
			jsonResponse(401, { error: "__proto__" }),
		);

		expect(constructor).not.toBeInstanceOf(PrincipalRevokedError);
		expect(proto).not.toBeInstanceOf(PrincipalRevokedError);
	});

	it("test_revoked_scope_when_http_client_gets_a_bearer_401_then_rejects_typed_error", async () => {
		const fetchFn = vi.fn().mockImplementation(() =>
			Promise.resolve(
				jsonResponse(401, {
					error: "agent_revoked",
					detail: "Agent is revoked",
				}),
			),
		);
		vi.stubGlobal("fetch", fetchFn);

		const err = await client()
			.get("/agents")
			.catch((e: unknown) => e);

		expect(err).toBeInstanceOf(PrincipalRevokedError);
		expect((err as PrincipalRevokedError).scope).toBe("agent");
		expect(fetchFn).toHaveBeenCalledTimes(1);
	});
});

describe("the token mint refusing a revoked principal", () => {
	it("test_revoked_scope_when_token_mint_names_agent_then_typed_error_carries_agent", async () => {
		stubFetch(() =>
			jsonResponse(401, {
				error: "invalid_client",
				detail: "The principal is revoked",
				reason: "agent_revoked",
			}),
		);

		const err = await fetchOAuthToken("https://api", TEST_SIGNER).catch(
			(e: unknown) => e,
		);

		expect(err).toBeInstanceOf(PrincipalRevokedError);
		const revoked = err as PrincipalRevokedError;
		expect(revoked.scope).toBe("agent");
		expect(revoked.status).toBe(401);
		expect(revoked.code).toBe("invalid_client");
		expect(revoked.detail).toBe("The principal is revoked");
	});

	it("test_revoked_scope_when_token_mint_names_branch_then_typed_error_carries_branch", async () => {
		stubFetch(() =>
			jsonResponse(401, {
				error: "invalid_client",
				detail: "The principal is revoked",
				reason: "branch_revoked",
			}),
		);

		const err = await fetchOAuthToken("https://api", TEST_SIGNER).catch(
			(e: unknown) => e,
		);

		expect(err).toBeInstanceOf(PrincipalRevokedError);
		expect((err as PrincipalRevokedError).scope).toBe("branch");
	});

	it("test_revoked_scope_when_token_mint_names_no_reason_then_ordinary_api_error", async () => {
		stubFetch(() =>
			jsonResponse(401, {
				error: "invalid_client",
				detail: "Invalid client assertion",
			}),
		);

		const err = await fetchOAuthToken("https://api", TEST_SIGNER).catch(
			(e: unknown) => e,
		);

		expect(err).toBeInstanceOf(RineApiError);
		expect(err).not.toBeInstanceOf(PrincipalRevokedError);
		expect((err as RineApiError).detail).toBe("Invalid client assertion");
	});
});

describe("recognising a revoked principal", () => {
	it("test_is_principal_revoked_error_when_the_class_is_core_then_it_is_recognised", () => {
		expect(isPrincipalRevokedError(new PrincipalRevokedError("agent", "revoked"))).toBe(true);
	});

	it("test_is_principal_revoked_error_when_another_class_wears_the_name_and_scope_then_it_is_recognised", () => {
		const lookalike = Object.assign(new Error("revoked"), {
			name: "PrincipalRevokedError",
			scope: "branch",
		});

		expect(isPrincipalRevokedError(lookalike)).toBe(true);
	});

	it.each([
		["a plain api error", new RineApiError(401, "no")],
		["a name without a scope", Object.assign(new Error("x"), { name: "PrincipalRevokedError" })],
		["an unknown scope", Object.assign(new Error("x"), { name: "PrincipalRevokedError", scope: "org" })],
		["null", null],
	])("test_is_principal_revoked_error_when_given_%s_then_it_is_not_recognised", (_label, value) => {
		expect(isPrincipalRevokedError(value)).toBe(false);
	});

	it.each(["constructor", "__proto__", "revoked", undefined, 3])(
		"test_scope_of_revoked_code_when_the_code_is_%s_then_it_names_no_scope",
		(code) => {
			expect(scopeOfRevokedCode(code)).toBeUndefined();
		},
	);
});
