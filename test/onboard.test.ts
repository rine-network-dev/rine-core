import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { validateSlug, performRegistration } from "../src/onboard.js";

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock("../src/config.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../src/config.js")>();
	return { ...actual, cacheToken: vi.fn() };
});

vi.mock("../src/timelock.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../src/timelock.js")>();
	return {
		...actual,
		solveTimeLockWithProgress: vi.fn().mockResolvedValue("solved-nonce"),
	};
});

// ---------------------------------------------------------------------------
// Helper imports (after mocks are registered)
// ---------------------------------------------------------------------------
import { PROFILES_FILE, cacheToken } from "../src/config.js";
import { PHRASE_FILE, ROOT_KEY_FILE } from "../src/owner.js";
import { loadProfiles } from "../src/profiles.js";
import { solveTimeLockWithProgress } from "../src/timelock.js";

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
const REG_PARAMS = { email: "test@example.com", slug: "my-org", name: "My Org" };
const API_URL = "https://api.test";
const PROFILE = "default";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

/** Stub global `fetch` with a router; an unrouted URL is a test bug. */
function stubFetch(
	handler: (url: string, init?: RequestInit) => { status: number; body: unknown },
): void {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string, init?: RequestInit) => {
			const r = handler(url, init);
			const ok = r.status >= 200 && r.status < 300;
			return {
				ok,
				status: r.status,
				statusText: ok ? "OK" : "Error",
				json: () => Promise.resolve(r.body),
			};
		}),
	);
}

/** What the server does on a solve it accepts: register the org id the client sent. */
const ACCEPT = "accept";
type SolveOutcome = typeof ACCEPT | { status: number; body: unknown };

/** Register → challenge, solve → `solve`, token → 200. */
function stubFlow(
	solve: SolveOutcome,
	token: { status: number; body: unknown } = {
		status: 200,
		body: { access_token: "tok", expires_in: 3600 },
	},
): void {
	let registeredOrg: unknown;
	stubFetch((url, init) => {
		if (url.endsWith("/auth/register")) {
			registeredOrg = (JSON.parse(init?.body as string) as { org_id: string }).org_id;
			return { status: 200, body: CHALLENGE };
		}
		if (url.endsWith("/auth/register/solve"))
			return solve === ACCEPT ? { status: 200, body: { org_id: registeredOrg } } : solve;
		if (url.endsWith("/oauth/token")) return token;
		throw new Error(`Unexpected fetch ${url}`);
	});
}

function bodyOf(callIndex: number): Record<string, unknown> {
	const init = vi.mocked(fetch).mock.calls[callIndex]?.[1] as RequestInit;
	return JSON.parse(init.body as string) as Record<string, unknown>;
}

let tmp: string;
let configDir: string;
let ownerDir: string;

const dirs = () => ({ configDir, ownerDir });
const register = (onProgress?: (pct: number) => void) =>
	performRegistration(API_URL, dirs(), PROFILE, REG_PARAMS, onProgress);

beforeEach(() => {
	tmp = mkdtempSync(join(tmpdir(), "rine-onboard-"));
	configDir = join(tmp, "config");
	ownerDir = join(tmp, "owner");
	mkdirSync(configDir, { recursive: true });
	mkdirSync(ownerDir, { recursive: true });
	vi.mocked(solveTimeLockWithProgress).mockResolvedValue("solved-nonce");
	vi.mocked(cacheToken).mockReset();
});

afterEach(() => {
	rmSync(tmp, { recursive: true, force: true });
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// validateSlug
// ---------------------------------------------------------------------------

describe("validateSlug", () => {
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

// ---------------------------------------------------------------------------
// performRegistration
// ---------------------------------------------------------------------------

describe("performRegistration", () => {
	it("happy path: registers, solves, writes the owner files and caches an org token", async () => {
		stubFlow(ACCEPT);
		const result = await register();

		expect(result.org_id).toBe(bodyOf(0).org_id);
		expect(typeof result.org_words).toBe("string");
		expect(result.phrase_path).toBe(join(ownerDir, PHRASE_FILE));

		expect(fetch).toHaveBeenCalledTimes(3);
		for (const [i, path] of [
			"/auth/register",
			"/auth/register/solve",
			"/oauth/token",
		].entries()) {
			expect(fetch).toHaveBeenNthCalledWith(
				i + 1,
				`${API_URL}${path}`,
				expect.objectContaining({ method: "POST" }),
			);
		}

		const reg = bodyOf(0);
		expect(reg).toMatchObject({
			email: REG_PARAMS.email,
			org_slug: REG_PARAMS.slug,
		});
		expect(reg.org_id).toMatch(UUID_RE);
		expect(reg.org_signing_public_key).toMatch(BASE64URL_RE);
		expect(reg.org_pq_signing_public_key).toMatch(BASE64URL_RE);

		const solve = bodyOf(1);
		expect(solve).toMatchObject({
			challenge_id: CHALLENGE.challenge_id,
			nonce: "solved-nonce",
			org_name: REG_PARAMS.name,
			org_slug: REG_PARAMS.slug,
			consent: true,
		});
		expect(solve.reader_public_key).toMatch(BASE64URL_RE);
		expect((solve.proof as string).split(".")).toHaveLength(3);
		const main = solve.main_branch as Record<string, unknown>;
		for (const field of [
			"signing_public_key",
			"pq_signing_public_key",
			"escrow_public_key",
			"escrow_pq_public_key",
			"reader_public_key",
			"certificate",
		]) {
			expect(main[field]).toBeTruthy();
		}

		for (const file of [ROOT_KEY_FILE, PHRASE_FILE]) {
			const path = join(ownerDir, file);
			expect(existsSync(path)).toBe(true);
			expect(statSync(path).mode & 0o777).toBe(0o600);
		}

		const entry = loadProfiles(ownerDir)[PROFILE];
		expect(entry?.org_id).toMatch(UUID_RE);
		expect(entry?.principal).toBe(`org:${entry?.org_id}`);
		expect(cacheToken).toHaveBeenCalledWith(
			ownerDir,
			`org:${entry?.org_id}`,
			expect.objectContaining({ access_token: "tok" }),
		);
	});

	it("passes onProgress to solveTimeLockWithProgress", async () => {
		stubFlow(ACCEPT);
		const onProgress = vi.fn();
		await register(onProgress);
		expect(solveTimeLockWithProgress).toHaveBeenCalledWith(
			CHALLENGE.prefix,
			CHALLENGE.modulus,
			CHALLENGE.difficulty,
			onProgress,
		);
	});

	it("429 on register → throws", async () => {
		stubFetch(() => ({ status: 429, body: {} }));
		await expect(register()).rejects.toThrow("Rate limited");
	});

	it.each([
		["Email already in use", { error: "ConflictError", detail: "Email already in use" }],
		["Slug already taken", { error: "conflict", detail: "Slug already taken" }],
		[
			"This org id is already registered",
			{
				error: "ConflictError",
				detail:
					"This org id is already registered. Generate a new org root and register again.",
			},
		],
		["email, slug or org id already registered", {}],
	])("409 on register → names the collision: %s", async (message, body) => {
		stubFetch(() => ({ status: 409, body }));
		await expect(register()).rejects.toThrow(`Conflict: ${message}`);
	});

	it("unsupported algorithm → throws", async () => {
		stubFetch(() => ({ status: 200, body: { ...CHALLENGE, algorithm: "sha256-v1" } }));
		await expect(register()).rejects.toThrow("Unsupported algorithm");
	});

	it.each([
		[410, "Challenge expired"],
		[409, "Conflict"],
	])("%i on solve → throws", async (status, message) => {
		stubFlow({ status, body: {} });
		await expect(register()).rejects.toThrow(message);
	});

	it("token cache failure is non-fatal", async () => {
		stubFlow(ACCEPT);
		vi.mocked(cacheToken).mockImplementation(() => {
			throw new Error("disk full");
		});
		expect((await register()).org_id).toMatch(UUID_RE);
	});

	it("token fetch failure is non-fatal", async () => {
		stubFlow(ACCEPT, { status: 500, body: { detail: "boom" } });
		expect((await register()).org_id).toBe(bodyOf(0).org_id);
		expect(cacheToken).not.toHaveBeenCalled();
	});

	it("test_performRegistration_when_the_server_registers_another_org_then_it_throws_and_keeps_the_root", async () => {
		stubFlow({ status: 200, body: { org_id: "00000000-0000-0000-0000-000000000001" } });
		await expect(register()).rejects.toThrow(/not the org this root derives/);
		expect(existsSync(join(ownerDir, ROOT_KEY_FILE))).toBe(true);
	});

	it("test_performRegistration_when_profiles_json_is_corrupt_then_it_names_the_file_and_writes_no_root", async () => {
		const profilesPath = join(ownerDir, PROFILES_FILE);
		writeFileSync(profilesPath, "{ truncated");
		stubFlow(ACCEPT);

		await expect(register()).rejects.toThrow(profilesPath);

		expect(existsSync(join(ownerDir, ROOT_KEY_FILE))).toBe(false);
		expect(existsSync(join(ownerDir, PHRASE_FILE))).toBe(false);
		expect(readFileSync(profilesPath, "utf-8")).toBe("{ truncated");
		expect(fetch).not.toHaveBeenCalled();
	});

	it("test_performRegistration_when_solve_is_refused_with_5xx_then_the_root_is_kept", async () => {
		stubFlow({ status: 502, body: { detail: "bad gateway" } });
		await expect(register()).rejects.toThrow("Solve failed");
		expect(existsSync(join(ownerDir, ROOT_KEY_FILE))).toBe(true);
		expect(existsSync(join(ownerDir, PHRASE_FILE))).toBe(true);
	});

	it("test_performRegistration_when_solve_is_refused_with_4xx_then_the_owner_files_are_removed", async () => {
		stubFlow({ status: 400, body: { detail: "bad proof" } });
		await expect(register()).rejects.toThrow("Solve failed");
		expect(existsSync(join(ownerDir, ROOT_KEY_FILE))).toBe(false);
		expect(existsSync(join(ownerDir, PHRASE_FILE))).toBe(false);
		expect(loadProfiles(ownerDir)).toEqual({});
	});

	it("test_performRegistration_when_solve_hits_a_network_error_then_the_root_is_kept", async () => {
		let rootExistedAtSolve = false;
		stubFetch((url) => {
			if (url.endsWith("/auth/register")) return { status: 200, body: CHALLENGE };
			rootExistedAtSolve = existsSync(join(ownerDir, ROOT_KEY_FILE));
			throw new Error("network down");
		});
		await expect(register()).rejects.toThrow("network down");
		expect(rootExistedAtSolve).toBe(true);
		expect(existsSync(join(ownerDir, ROOT_KEY_FILE))).toBe(true);
		expect(existsSync(join(ownerDir, PHRASE_FILE))).toBe(true);
	});

	it("test_performRegistration_when_the_owner_dir_is_inside_a_git_worktree_then_it_refuses_before_any_request", async () => {
		const repo = join(tmp, "repo");
		mkdirSync(join(repo, ".git"), { recursive: true });
		stubFetch(() => {
			throw new Error("fetch must not be called");
		});
		await expect(
			performRegistration(
				API_URL,
				{ configDir, ownerDir: join(repo, "owner") },
				PROFILE,
				REG_PARAMS,
			),
		).rejects.toThrow(/git worktree/);
		expect(fetch).not.toHaveBeenCalled();
	});

	it("test_performRegistration_result_never_contains_the_phrase", async () => {
		const captured: string[] = [];
		for (const method of ["log", "info", "warn", "error"] as const) {
			vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
				captured.push(args.map(String).join(" "));
			});
		}
		stubFlow(ACCEPT);
		const result = await register();

		const words = readFileSync(join(ownerDir, PHRASE_FILE), "utf-8")
			.trim()
			.split(/\s+/);
		expect(words).toHaveLength(24);
		const haystacks = [JSON.stringify(result), captured.join("\n")];
		for (let i = 0; i + 3 <= words.length; i++) {
			const run = words.slice(i, i + 3).join(" ");
			for (const haystack of haystacks) expect(haystack).not.toContain(run);
		}
	});
});
