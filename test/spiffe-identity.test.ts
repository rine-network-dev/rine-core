import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	SpiffeVerificationError,
	hasSpiffeEndpoint,
	verifyIdentitySpiffe,
} from "../src/onboard.js";

// ---------------------------------------------------------------------------
// Helpers — a minimal ApiPoster spy and the two server responses the contract
// uses (challenge → audience, verify-svid → result).
// ---------------------------------------------------------------------------

const AGENT_ID = "00000000-0000-0000-0000-000000000010";
const AUDIENCE = "spiffe://challenge.rine.network/tok-123";

const CHALLENGE = { audience: AUDIENCE, expires_in: 300 };
const VERIFY_RESULT = {
	agent_id: AGENT_ID,
	spiffe_id: "spiffe://prod.acme.example/workload/web",
	trust_domain: "prod.acme.example",
	trust_tier: 2,
	verified_at: "2026-06-30T00:00:00Z",
};

function makePoster(verifyResponse: unknown = VERIFY_RESULT) {
	const post = vi.fn(async (path: string) => {
		if (path.endsWith("/verify-svid/challenge")) return CHALLENGE;
		if (path.endsWith("/verify-svid")) return verifyResponse;
		throw new Error(`Unexpected POST ${path}`);
	});
	return { post };
}

const SOCKET_ENV = "SPIFFE_ENDPOINT_SOCKET";

describe("verifyIdentitySpiffe", () => {
	afterEach(() => {
		delete process.env[SOCKET_ENV];
		vi.restoreAllMocks();
	});

	it("calls challenge then verify-svid in order with the supplied --svid", async () => {
		const client = makePoster();
		const result = await verifyIdentitySpiffe(client, AGENT_ID, {
			svid: "the.jwt.svid",
		});

		expect(client.post).toHaveBeenCalledTimes(2);
		expect(client.post).toHaveBeenNthCalledWith(
			1,
			`/agents/${AGENT_ID}/verify-svid/challenge`,
		);
		expect(client.post).toHaveBeenNthCalledWith(
			2,
			`/agents/${AGENT_ID}/verify-svid`,
			{ svid: "the.jwt.svid" },
		);
		expect(result).toEqual(VERIFY_RESULT);
	});

	it("returns the typed server result (trust tier 2)", async () => {
		const client = makePoster();
		const result = await verifyIdentitySpiffe(client, AGENT_ID, {
			svid: "jwt",
		});
		expect(result.trust_tier).toBe(2);
		expect(result.spiffe_id).toBe("spiffe://prod.acme.example/workload/web");
	});

	it("throws SpiffeVerificationError(no-svid) — never a silent no-op — when no SVID and no endpoint", async () => {
		const client = makePoster();
		await expect(verifyIdentitySpiffe(client, AGENT_ID)).rejects.toThrow(
			SpiffeVerificationError,
		);
		// The challenge was requested, but verify-svid was NOT — no partial success.
		expect(client.post).toHaveBeenCalledTimes(1);
		try {
			await verifyIdentitySpiffe(makePoster(), AGENT_ID);
		} catch (err) {
			expect((err as SpiffeVerificationError).reason).toBe("no-svid");
		}
	});

	it("with SPIFFE endpoint but no svid: logs auto-fetch unavailable and throws autofetch-unavailable", async () => {
		process.env[SOCKET_ENV] = "unix:///tmp/spire.sock";
		const client = makePoster();
		const log = vi.fn();

		await expect(
			verifyIdentitySpiffe(client, AGENT_ID, { log }),
		).rejects.toMatchObject({ reason: "autofetch-unavailable" });

		// The auto-fetch path was attempted and reported as unavailable (no silent no-op).
		expect(log).toHaveBeenCalledTimes(1);
		expect(log.mock.calls[0]?.[0]).toContain("not available");
		expect(log.mock.calls[0]?.[0]).toContain(AUDIENCE);
		// verify-svid is never reached without an SVID.
		expect(client.post).toHaveBeenCalledTimes(1);
	});

	it("propagates HTTP-layer errors from verify-svid (e.g. 422)", async () => {
		const client = {
			post: vi.fn(async (path: string) => {
				if (path.endsWith("/challenge")) return CHALLENGE;
				throw new Error("422: invalid SVID");
			}),
		};
		await expect(
			verifyIdentitySpiffe(client, AGENT_ID, { svid: "bad" }),
		).rejects.toThrow("422: invalid SVID");
	});
});

describe("hasSpiffeEndpoint", () => {
	beforeEach(() => {
		delete process.env[SOCKET_ENV];
	});
	afterEach(() => {
		delete process.env[SOCKET_ENV];
	});

	it("false when SPIFFE_ENDPOINT_SOCKET is unset", () => {
		expect(hasSpiffeEndpoint()).toBe(false);
	});

	it("true when SPIFFE_ENDPOINT_SOCKET is set", () => {
		process.env[SOCKET_ENV] = "unix:///run/spire/sockets/agent.sock";
		expect(hasSpiffeEndpoint()).toBe(true);
	});
});
