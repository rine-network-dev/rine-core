import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { performAgentCreation } from "../src/agent-create.js";
import { AgentIdMismatchError } from "../src/errors.js";

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock("../src/mls-ops.js", () => ({
	publishMlsKeyPackages: vi.fn().mockResolvedValue({ stored: 10 }),
}));

// ---------------------------------------------------------------------------
// Helper imports (after mocks are registered)
// ---------------------------------------------------------------------------
import { publishMlsKeyPackages } from "../src/mls-ops.js";
import { saveRoot } from "../src/owner.js";
import { loadProfiles } from "../src/profiles.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PROFILE = "default";

const BASE_AGENT = {
	id: "00000000-0000-0000-0000-000000000010",
	name: "Test Agent",
	handle: "test-agent",
	human_oversight: false,
	incoming_policy: "open",
	outgoing_policy: "open",
	created_at: "2026-01-01T00:00:00Z",
};

/** A client whose `POST /agents` echoes the id the caller minted. */
function makeClient(extra: Record<string, unknown> = {}) {
	return {
		get: vi.fn(),
		delete: vi.fn(),
		put: vi.fn(),
		patch: vi.fn(),
		post: vi.fn(async (path: string, body?: unknown) => {
			if (path === "/agents") {
				const id = (body as { id: string }).id;
				return { ...BASE_AGENT, id, ...extra };
			}
			return BASE_AGENT;
		}),
	};
}

function postBody(client: ReturnType<typeof makeClient>): Record<string, unknown> {
	return vi.mocked(client.post).mock.calls[0]?.[1] as Record<string, unknown>;
}

let tmp: string;
let configDir: string;
let ownerDir: string;

function dirs() {
	return { configDir, ownerDir };
}

beforeEach(() => {
	tmp = mkdtempSync(join(tmpdir(), "rine-agent-create-"));
	configDir = join(tmp, "config");
	ownerDir = join(tmp, "owner");
	mkdirSync(configDir, { recursive: true });
	mkdirSync(ownerDir, { recursive: true });
	saveRoot(ownerDir, new Uint8Array(32).fill(3));
	vi.mocked(publishMlsKeyPackages).mockClear();
	vi.mocked(publishMlsKeyPackages).mockResolvedValue({ stored: 10 });
});

afterEach(() => {
	rmSync(tmp, { recursive: true, force: true });
	vi.restoreAllMocks();
});

describe("performAgentCreation", () => {
	it("happy path: posts the client-minted id and keys, saves leaf files, writes the profile", async () => {
		const client = makeClient();
		const result = await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
		});

		const body = postBody(client);
		expect(body.id).toMatch(UUID_RE);
		expect(body.name).toBe("Test Agent");
		expect(body.branch).toBe("main");
		expect(body.signing_public_key).toMatchObject({ kty: "OKP", crv: "Ed25519" });
		expect(body.encryption_public_key).toMatchObject({ kty: "OKP", crv: "X25519" });
		expect(body.pq_encryption_public_key).toMatchObject({ kty: "MLKEM" });
		expect(body.pq_signing_public_key).toMatchObject({ kty: "MLDSA" });
		expect(body.mls_signing_public_key).toMatchObject({ kty: "OKP", crv: "Ed25519" });
		expect(typeof body.agent_certificate).toBe("string");
		expect(body.agent_certificate).toBeTruthy();
		expect(Object.keys(body).filter((k) => k.startsWith("client_"))).toEqual([]);

		expect(result).toMatchObject({ id: body.id, name: "Test Agent" });

		const keyDir = join(configDir, "keys", body.id as string);
		for (const file of [
			"signing.key",
			"encryption.key",
			"pq_encryption.key",
			"mls.key",
			"key_gen",
		]) {
			expect(existsSync(join(keyDir, file))).toBe(true);
		}

		const entry = loadProfiles(configDir)[PROFILE];
		expect(entry?.principal).toBe(`agent:${body.id}`);
		expect(entry?.agent_id).toBe(body.id);
		expect(entry?.branch).toBe("main");
	});

	it("test_create_when_the_server_answers_another_id_then_it_throws_and_nothing_is_saved", async () => {
		const SERVER_ID = "00000000-0000-0000-0000-0000000000ff";
		const client = makeClient({ id: SERVER_ID });
		client.post.mockImplementation(async () => ({ ...BASE_AGENT, id: SERVER_ID }));

		const err = await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
		}).catch((e) => e);

		expect(err).toBeInstanceOf(AgentIdMismatchError);
		expect(err.serverId).toBe(SERVER_ID);
		expect(err.mintedId).toMatch(UUID_RE);
		expect(existsSync(join(configDir, "keys", SERVER_ID))).toBe(false);
		expect(existsSync(join(configDir, "keys", err.mintedId))).toBe(false);
		expect(loadProfiles(configDir)[PROFILE]).toBeUndefined();
		expect(publishMlsKeyPackages).not.toHaveBeenCalled();
	});

	it("publishes an initial batch of MLS KeyPackages (MLS-ready from birth)", async () => {
		const client = makeClient();
		const result = await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
		});
		expect(publishMlsKeyPackages).toHaveBeenCalledWith(
			configDir,
			result.id,
			client,
		);
	});

	it("agent creation succeeds even if MLS KeyPackage publish fails (non-fatal)", async () => {
		vi.mocked(publishMlsKeyPackages).mockRejectedValueOnce(new Error("mls down"));
		const client = makeClient();
		const result = await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
		});
		expect(result.id).toMatch(UUID_RE);
		expect(existsSync(join(configDir, "keys", result.id, "signing.key"))).toBe(true);
	});

	it("with poll_url: saves poll_url into the agent profile", async () => {
		const client = makeClient({ poll_url: "https://poll.example.com/queue" });
		const result = await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
		});
		expect(loadProfiles(configDir)[PROFILE]?.poll_url).toBe(
			"https://poll.example.com/queue",
		);
		expect(result.poll_url).toBe("https://poll.example.com/queue");
	});

	it("without poll_url: the profile carries no poll_url", async () => {
		const client = makeClient();
		await performAgentCreation(client, dirs(), PROFILE, { name: "Test Agent" });
		expect(loadProfiles(configDir)[PROFILE]).not.toHaveProperty("poll_url");
	});

	it("a second creation with the same profile name leaves the first profile untouched", async () => {
		const first = makeClient();
		const firstResult = await performAgentCreation(first, dirs(), PROFILE, {
			name: "Test Agent",
		});
		const second = makeClient({ poll_url: "https://poll.example.com/queue" });
		const secondResult = await performAgentCreation(second, dirs(), PROFILE, {
			name: "Test Agent",
		});

		expect(secondResult.id).not.toBe(firstResult.id);
		const entry = loadProfiles(configDir)[PROFILE];
		expect(entry?.agent_id).toBe(firstResult.id);
		expect(entry).not.toHaveProperty("poll_url");
	});

	it("passes humanOversight param through to POST body", async () => {
		const client = makeClient();
		await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
			humanOversight: true,
		});
		expect(postBody(client)).toHaveProperty("human_oversight", true);
	});

	it("passes unlisted: true through to POST body", async () => {
		const client = makeClient();
		await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
			unlisted: true,
		});
		expect(postBody(client)).toHaveProperty("unlisted", true);
	});

	it("passes unlisted: false explicitly (not dropped)", async () => {
		const client = makeClient();
		await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
			unlisted: false,
		});
		expect(postBody(client)).toHaveProperty("unlisted", false);
	});

	it("omits humanOversight when not provided", async () => {
		const client = makeClient();
		await performAgentCreation(client, dirs(), PROFILE, { name: "Test Agent" });
		expect(postBody(client)).not.toHaveProperty("human_oversight");
	});

	// -----------------------------------------------------------------------
	// SPIFFE identity verification wiring: performAgentCreation
	// runs verifyIdentitySpiffe after POST /agents when --verify-identity is set
	// or SPIFFE_ENDPOINT_SOCKET is present.
	// -----------------------------------------------------------------------

	const SOCKET_ENV = "SPIFFE_ENDPOINT_SOCKET";
	const SPIFFE_AUDIENCE = "spiffe://challenge.rine.network/tok-1";
	const SPIFFE_RESULT = {
		agent_id: BASE_AGENT.id,
		spiffe_id: "spiffe://prod.acme.example/web",
		trust_domain: "prod.acme.example",
		trust_tier: 2,
		verified_at: "2026-06-30T00:00:00Z",
	};

	/** Client whose POST routes /agents, the SVID challenge, and verify-svid. */
	function makeSpiffeClient() {
		return {
			get: vi.fn(),
			delete: vi.fn(),
			put: vi.fn(),
			patch: vi.fn(),
			post: vi.fn(async (path: string, body?: unknown) => {
				if (path === "/agents") {
					const id = (body as { id: string }).id;
					return { ...BASE_AGENT, id };
				}
				if (path.endsWith("/verify-svid/challenge"))
					return { audience: SPIFFE_AUDIENCE, expires_in: 300 };
				if (path.endsWith("/verify-svid")) return SPIFFE_RESULT;
				return BASE_AGENT;
			}),
		};
	}

	it("verifyIdentity flag + --svid: creates agent then verifies, attaching identity", async () => {
		const client = makeSpiffeClient();
		const result = await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
			verifyIdentity: true,
			svid: "the.jwt.svid",
		});

		const paths = vi.mocked(client.post).mock.calls.map((c) => c[0]);
		expect(paths).toEqual([
			"/agents",
			`/agents/${result.id}/verify-svid/challenge`,
			`/agents/${result.id}/verify-svid`,
		]);
		expect(result.identity).toEqual(SPIFFE_RESULT);
	});

	it("does NOT verify identity when neither flag nor SPIFFE endpoint present", async () => {
		delete process.env[SOCKET_ENV];
		const client = makeSpiffeClient();
		const result = await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
		});
		const paths = vi.mocked(client.post).mock.calls.map((c) => c[0]);
		expect(paths).toEqual(["/agents"]);
		expect(result.identity).toBeUndefined();
	});

	it("auto-runs verification when SPIFFE_ENDPOINT_SOCKET is present (with --svid)", async () => {
		process.env[SOCKET_ENV] = "unix:///tmp/spire.sock";
		try {
			const client = makeSpiffeClient();
			const result = await performAgentCreation(client, dirs(), PROFILE, {
				name: "Test Agent",
				svid: "the.jwt.svid",
			});
			expect(result.identity).toEqual(SPIFFE_RESULT);
		} finally {
			delete process.env[SOCKET_ENV];
		}
	});

	it("surfaces a verification failure (no SVID + endpoint) as identityError — agent created, error not swallowed, NOT thrown", async () => {
		process.env[SOCKET_ENV] = "unix:///tmp/spire.sock";
		try {
			const client = makeSpiffeClient();
			const result = await performAgentCreation(client, dirs(), PROFILE, {
				name: "Test Agent",
				log: () => {},
			});
			expect(existsSync(join(configDir, "keys", result.id, "signing.key"))).toBe(true);
			expect(result.id).toMatch(UUID_RE);
			expect(result.identity).toBeUndefined();
			expect(result.identityError).toContain("auto-fetch");
		} finally {
			delete process.env[SOCKET_ENV];
		}
	});

	it("a supplied --svid triggers verification even WITHOUT --verify-identity (no silent discard)", async () => {
		delete process.env[SOCKET_ENV];
		const client = makeSpiffeClient();
		const result = await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
			svid: "the.jwt.svid",
		});
		const paths = vi.mocked(client.post).mock.calls.map((c) => c[0]);
		expect(paths).toEqual([
			"/agents",
			`/agents/${result.id}/verify-svid/challenge`,
			`/agents/${result.id}/verify-svid`,
		]);
		expect(result.identity).toEqual(SPIFFE_RESULT);
	});

	it("captures a verify HTTP failure in identityError without throwing (creation preserved)", async () => {
		const client = makeSpiffeClient();
		vi.mocked(client.post).mockImplementation(async (path: string, body?: unknown) => {
			if (path === "/agents") {
				const id = (body as { id: string }).id;
				return { ...BASE_AGENT, id };
			}
			if (path.endsWith("/verify-svid/challenge"))
				return { audience: SPIFFE_AUDIENCE, expires_in: 300 };
			if (path.endsWith("/verify-svid")) throw new Error("422 invalid SVID");
			return BASE_AGENT;
		});
		const result = await performAgentCreation(client, dirs(), PROFILE, {
			name: "Test Agent",
			svid: "bad.jwt",
		});
		expect(result.id).toMatch(UUID_RE);
		expect(result.identity).toBeUndefined();
		expect(result.identityError).toContain("422");
	});
});
