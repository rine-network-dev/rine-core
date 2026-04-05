import { describe, expect, it, vi, afterEach } from "vitest";
import { validateSlug, performRegistration, performAgentCreation } from "../src/onboard.js";

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock("../src/config.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../src/config.js")>();
	return {
		...actual,
		loadCredentials: vi.fn().mockReturnValue({}),
		saveCredentials: vi.fn(),
		cacheToken: vi.fn(),
	};
});

vi.mock("../src/http.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../src/http.js")>();
	return {
		...actual,
		fetchOAuthToken: vi.fn().mockResolvedValue({ access_token: "tok", expires_in: 3600 }),
	};
});

vi.mock("../src/timelock.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../src/timelock.js")>();
	return {
		...actual,
		solveTimeLockWithProgress: vi.fn().mockResolvedValue("solved-nonce"),
	};
});

vi.mock("../src/crypto/index.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../src/crypto/index.js")>();
	const fakeKeys = {
		signing: { privateKey: new Uint8Array(32), publicKey: new Uint8Array(32) },
		encryption: { privateKey: new Uint8Array(32), publicKey: new Uint8Array(32) },
	};
	return {
		...actual,
		generateAgentKeys: vi.fn(() => fakeKeys),
		saveAgentKeys: vi.fn(),
		signingPublicKeyToJWK: vi.fn(() => ({ kty: "OKP", crv: "Ed25519", x: "signing-pub" })),
		encryptionPublicKeyToJWK: vi.fn(() => ({ kty: "OKP", crv: "X25519", x: "enc-pub" })),
	};
});

// ---------------------------------------------------------------------------
// Helper imports (after mocks are registered)
// ---------------------------------------------------------------------------
import { loadCredentials, saveCredentials, cacheToken } from "../src/config.js";
import { fetchOAuthToken } from "../src/http.js";
import { solveTimeLockWithProgress } from "../src/timelock.js";
import { generateAgentKeys, saveAgentKeys, signingPublicKeyToJWK, encryptionPublicKeyToJWK } from "../src/crypto/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CHALLENGE = {
	challenge_id: "chal-1",
	prefix: "abc",
	modulus: "mod",
	difficulty: 10,
	algorithm: "rsa-timelock-v1",
	expires_in: 60,
};

const SOLVE_RESPONSE = {
	org_id: "00000000-0000-0000-0000-000000000001",
	client_id: "00000000-0000-0000-0000-000000000002",
	client_secret: "supersecret",
};

function makeFetchSequence(responses: Array<{ status: number; body: unknown }>): void {
	let call = 0;
	vi.stubGlobal("fetch", vi.fn().mockImplementation(() => {
		const r = responses[call++];
		if (!r) throw new Error("Unexpected fetch call");
		const ok = r.status >= 200 && r.status < 300;
		return Promise.resolve({
			ok,
			status: r.status,
			statusText: ok ? "OK" : "Error",
			json: () => Promise.resolve(r.body),
		});
	}));
}

function makeHappyFetch(): void {
	makeFetchSequence([
		{ status: 200, body: CHALLENGE },
		{ status: 200, body: SOLVE_RESPONSE },
	]);
}

const REG_PARAMS = { email: "test@example.com", slug: "my-org", name: "My Org" };
const API_URL = "https://api.test";
const CONFIG_DIR = "/tmp/fake-config";
const PROFILE = "default";

// ---------------------------------------------------------------------------
// validateSlug
// ---------------------------------------------------------------------------

describe("validateSlug", () => {
	describe("valid slugs", () => {
		it.each([
			["ab", "two char minimum"],
			["my-org", "hyphen in middle"],
			["acme", "plain lowercase"],
			["a".repeat(32), "32 chars (max)"],
			["org123", "ends with digit"],
			["123org", "starts with digit"],
		])("accepts %s (%s)", (slug) => {
			expect(validateSlug(slug)).toBe(true);
		});
	});

	describe("invalid slugs", () => {
		it.each([
			["a", "single char"],
			["-acme", "leading hyphen"],
			["acme-", "trailing hyphen"],
			["Acme", "uppercase letter"],
			["acme!", "special char"],
			["a".repeat(33), "33 chars (over max)"],
			["", "empty string"],
			["acme org", "space in slug"],
		])("rejects %s (%s)", (slug) => {
			expect(validateSlug(slug)).toBe(false);
		});
	});
});

// ---------------------------------------------------------------------------
// performRegistration
// ---------------------------------------------------------------------------

describe("performRegistration", () => {
	afterEach(() => {
		vi.restoreAllMocks();
		vi.mocked(loadCredentials).mockReturnValue({});
		vi.mocked(saveCredentials).mockReset();
		vi.mocked(cacheToken).mockReset();
		vi.mocked(fetchOAuthToken).mockResolvedValue({ access_token: "tok", expires_in: 3600 });
		vi.mocked(solveTimeLockWithProgress).mockResolvedValue("solved-nonce");
	});

	it("happy path: makes two fetch calls and saves credentials", async () => {
		makeHappyFetch();
		const result = await performRegistration(API_URL, CONFIG_DIR, PROFILE, REG_PARAMS);

		expect(result).toEqual({
			org_id: SOLVE_RESPONSE.org_id,
			client_id: SOLVE_RESPONSE.client_id,
		});
		expect(fetch).toHaveBeenCalledTimes(2);
		expect(fetch).toHaveBeenNthCalledWith(
			1,
			`${API_URL}/auth/register`,
			expect.objectContaining({ method: "POST" }),
		);
		expect(fetch).toHaveBeenNthCalledWith(
			2,
			`${API_URL}/auth/register/solve`,
			expect.objectContaining({ method: "POST" }),
		);
		expect(saveCredentials).toHaveBeenCalledWith(
			CONFIG_DIR,
			expect.objectContaining({
				[PROFILE]: expect.objectContaining({ client_id: SOLVE_RESPONSE.client_id }),
			}),
		);
		expect(cacheToken).toHaveBeenCalledWith(CONFIG_DIR, PROFILE, expect.objectContaining({ access_token: "tok" }));
	});

	it("passes onProgress to solveTimeLockWithProgress", async () => {
		makeHappyFetch();
		const onProgress = vi.fn();
		await performRegistration(API_URL, CONFIG_DIR, PROFILE, REG_PARAMS, onProgress);
		expect(solveTimeLockWithProgress).toHaveBeenCalledWith(
			CHALLENGE.prefix,
			CHALLENGE.modulus,
			CHALLENGE.difficulty,
			onProgress,
		);
	});

	it("409 on register → throws 'Email or slug already registered'", async () => {
		makeFetchSequence([{ status: 409, body: {} }]);
		await expect(performRegistration(API_URL, CONFIG_DIR, PROFILE, REG_PARAMS))
			.rejects.toThrow("Email or slug already registered");
	});

	it("429 on register → throws rate limit message", async () => {
		makeFetchSequence([{ status: 429, body: {} }]);
		await expect(performRegistration(API_URL, CONFIG_DIR, PROFILE, REG_PARAMS))
			.rejects.toThrow("Rate limited");
	});

	it("unsupported algorithm → throws", async () => {
		makeFetchSequence([
			{ status: 200, body: { ...CHALLENGE, algorithm: "sha256-v1" } },
		]);
		await expect(performRegistration(API_URL, CONFIG_DIR, PROFILE, REG_PARAMS))
			.rejects.toThrow("Unsupported algorithm");
	});

	it("410 on solve → throws 'Challenge expired'", async () => {
		makeFetchSequence([
			{ status: 200, body: CHALLENGE },
			{ status: 410, body: {} },
		]);
		await expect(performRegistration(API_URL, CONFIG_DIR, PROFILE, REG_PARAMS))
			.rejects.toThrow("Challenge expired");
	});

	it("409 on solve → throws 'Conflict'", async () => {
		makeFetchSequence([
			{ status: 200, body: CHALLENGE },
			{ status: 409, body: {} },
		]);
		await expect(performRegistration(API_URL, CONFIG_DIR, PROFILE, REG_PARAMS))
			.rejects.toThrow("Conflict");
	});

	it("token cache failure is non-fatal", async () => {
		makeHappyFetch();
		vi.mocked(cacheToken).mockImplementation(() => { throw new Error("disk full"); });

		// Should not throw
		const result = await performRegistration(API_URL, CONFIG_DIR, PROFILE, REG_PARAMS);
		expect(result.org_id).toBe(SOLVE_RESPONSE.org_id);
	});

	it("token cache failure via fetchOAuthToken is non-fatal", async () => {
		makeHappyFetch();
		vi.mocked(fetchOAuthToken).mockRejectedValue(new Error("network error"));

		const result = await performRegistration(API_URL, CONFIG_DIR, PROFILE, REG_PARAMS);
		expect(result.client_id).toBe(SOLVE_RESPONSE.client_id);
		expect(cacheToken).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// performAgentCreation
// ---------------------------------------------------------------------------

const AGENT_ID = "00000000-0000-0000-0000-000000000010";

const BASE_AGENT = {
	id: AGENT_ID,
	name: "Test Agent",
	handle: "test-agent",
	human_oversight: false,
	incoming_policy: "open",
	outgoing_policy: "open",
	created_at: "2026-01-01T00:00:00Z",
};

function makeClient(overrides: Partial<{ post: ReturnType<typeof vi.fn> }> = {}) {
	return {
		get: vi.fn(),
		post: overrides.post ?? vi.fn().mockResolvedValue(BASE_AGENT),
		delete: vi.fn(),
		put: vi.fn(),
		patch: vi.fn(),
	};
}

describe("performAgentCreation", () => {
	afterEach(() => {
		vi.mocked(loadCredentials).mockReturnValue({});
		vi.mocked(saveCredentials).mockReset();
		vi.mocked(saveAgentKeys).mockReset();
	});

	it("happy path: calls client.post, saves keys, returns agent data", async () => {
		const client = makeClient();
		const result = await performAgentCreation(client, CONFIG_DIR, PROFILE, { name: "Test Agent" });

		expect(client.post).toHaveBeenCalledWith(
			"/agents",
			expect.objectContaining({
				name: "Test Agent",
				signing_public_key: { kty: "OKP", crv: "Ed25519", x: "signing-pub" },
				encryption_public_key: { kty: "OKP", crv: "X25519", x: "enc-pub" },
			}),
		);
		expect(generateAgentKeys).toHaveBeenCalled();
		expect(signingPublicKeyToJWK).toHaveBeenCalled();
		expect(encryptionPublicKeyToJWK).toHaveBeenCalled();
		expect(saveAgentKeys).toHaveBeenCalledWith(CONFIG_DIR, AGENT_ID, expect.anything());
		expect(result).toMatchObject({ id: AGENT_ID, name: "Test Agent" });
	});

	it("with poll_url and existing profile: saves poll_url to credentials", async () => {
		vi.mocked(loadCredentials).mockReturnValue({
			[PROFILE]: { client_id: "cid", client_secret: "csec" },
		});
		const agentWithPoll = { ...BASE_AGENT, poll_url: "https://poll.example.com/queue" };
		const client = makeClient({ post: vi.fn().mockResolvedValue(agentWithPoll) });

		await performAgentCreation(client, CONFIG_DIR, PROFILE, { name: "Test Agent" });

		expect(saveCredentials).toHaveBeenCalledWith(
			CONFIG_DIR,
			expect.objectContaining({
				[PROFILE]: expect.objectContaining({ poll_url: "https://poll.example.com/queue" }),
			}),
		);
	});

	it("without poll_url: does not save credentials", async () => {
		vi.mocked(loadCredentials).mockReturnValue({
			[PROFILE]: { client_id: "cid", client_secret: "csec" },
		});
		const client = makeClient(); // returns BASE_AGENT (no poll_url)
		await performAgentCreation(client, CONFIG_DIR, PROFILE, { name: "Test Agent" });
		expect(saveCredentials).not.toHaveBeenCalled();
	});

	it("with poll_url but no existing profile entry: does not save credentials", async () => {
		vi.mocked(loadCredentials).mockReturnValue({}); // no profile entry
		const agentWithPoll = { ...BASE_AGENT, poll_url: "https://poll.example.com/queue" };
		const client = makeClient({ post: vi.fn().mockResolvedValue(agentWithPoll) });

		await performAgentCreation(client, CONFIG_DIR, PROFILE, { name: "Test Agent" });

		expect(saveCredentials).not.toHaveBeenCalled();
	});

	it("passes humanOversight param through to POST body", async () => {
		const client = makeClient();
		await performAgentCreation(client, CONFIG_DIR, PROFILE, {
			name: "Test Agent",
			humanOversight: true,
		});
		expect(client.post).toHaveBeenCalledWith(
			"/agents",
			expect.objectContaining({ human_oversight: true }),
		);
	});

	it("passes unlisted: true through to POST body", async () => {
		const client = makeClient();
		await performAgentCreation(client, CONFIG_DIR, PROFILE, {
			name: "Test Agent",
			unlisted: true,
		});
		expect(client.post).toHaveBeenCalledWith(
			"/agents",
			expect.objectContaining({ unlisted: true }),
		);
	});

	it("passes unlisted: false explicitly (not dropped)", async () => {
		const client = makeClient();
		await performAgentCreation(client, CONFIG_DIR, PROFILE, {
			name: "Test Agent",
			unlisted: false,
		});
		const body = vi.mocked(client.post).mock.calls[0]?.[1] as Record<string, unknown>;
		expect(body).toHaveProperty("unlisted", false);
	});

	it("omits humanOversight when not provided", async () => {
		const client = makeClient();
		await performAgentCreation(client, CONFIG_DIR, PROFILE, { name: "Test Agent" });
		const body = vi.mocked(client.post).mock.calls[0]?.[1] as Record<string, unknown>;
		expect(body).not.toHaveProperty("human_oversight");
	});
});
