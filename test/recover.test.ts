/**
 * Recovery from the phrase, end to end against the real derivation and a stubbed
 * server: a test here fails when recovery trusts a mismatching agent, persists
 * before the reseat, accepts a rolled-back generation or echoes the phrase.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	agentKeysFromDerived,
	loadAgentKeys,
	phraseFromEntropy,
	saveAgentKeys,
} from "../src/crypto/index.js";
import { EscrowLoss, writeGap } from "../src/mls-escrow-gap.js";
import { PHRASE_FILE, ROOT_KEY_FILE, loadRoot } from "../src/owner.js";
import { loadProfiles } from "../src/profiles.js";
import {
	AgentRecoveryStatus,
	NO_ORG_FOR_PHRASE,
	performRecovery,
} from "../src/recover.js";
import { World } from "./crypto/world.js";

const API_URL = "https://api.test";
const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const SECOND_AGENT = "b1b2c3d4-e5f6-7890-abcd-ef1234567890";
const ROOT = new Uint8Array(32).fill(7);
const PHRASE = phraseFromEntropy(ROOT);

let tmp: string;
let configDir: string;
let ownerDir: string;
let world: World;
let requests: string[];
let tokenStatus: number;
let tokenBody: Record<string, unknown>;
let currentGen: number | undefined;
let rootAtGroupsRead: boolean | undefined;
let agentIds: string[];
let failKeysFor: string | undefined;

const dirs = () => ({ configDir, ownerDir });

function json(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

/** The server's `GET /agents/{id}/keys`: the current generation, or `?gen=N`. */
function agentKeys(agentId: string, gen: string | null): Response {
	const generations = world.agents.get(agentId) ?? [];
	const newest = Math.max(...generations.map((g) => g.gen));
	const wanted = gen === null ? (currentGen ?? newest) : Number(gen);
	const found = generations.find((g) => g.gen === wanted);
	return found ? json(200, found.response) : json(404, { detail: "Key generation not found" });
}

function stubServer(): void {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: string) => {
			const url = new URL(input);
			requests.push(url.pathname + url.search);
			if (url.pathname === "/oauth/token") {
				return tokenStatus === 200
					? json(200, { access_token: "tok", expires_in: 900 })
					: json(tokenStatus, tokenBody);
			}
			if (url.pathname === "/orgs/me/branches") {
				return json(200, { branches: [{ name: "main", revoked_at: null }] });
			}
			if (url.pathname === "/agents") {
				return json(200, { items: agentIds.map((id) => ({ id, name: `agent-${id}` })) });
			}
			const keysOf = agentIds.find((id) => url.pathname === `/agents/${id}/keys`);
			if (keysOf !== undefined) {
				if (keysOf === failKeysFor) return json(500, { detail: "boom" });
				return agentKeys(keysOf, url.searchParams.get("gen"));
			}
			if (url.pathname === "/groups") {
				rootAtGroupsRead = fs.existsSync(join(ownerDir, ROOT_KEY_FILE));
				return json(200, { items: [] });
			}
			throw new Error(`unexpected request ${url.pathname}`);
		}),
	);
}

beforeEach(() => {
	tmp = fs.mkdtempSync(join(tmpdir(), "rine-recover-"));
	configDir = join(tmp, "config");
	ownerDir = join(tmp, "owner");
	fs.mkdirSync(configDir, { recursive: true });
	world = new World(ROOT);
	world.addAgent({ id: AGENT });
	requests = [];
	tokenStatus = 200;
	tokenBody = { detail: "unknown org" };
	currentGen = undefined;
	rootAtGroupsRead = undefined;
	agentIds = [AGENT];
	failKeysFor = undefined;
	stubServer();
});

afterEach(() => {
	fs.rmSync(tmp, { recursive: true, force: true });
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("performRecovery", () => {
	it("test_performRecovery_when_the_phrase_matches_then_it_restores_agents_and_the_owner_files", async () => {
		const report = await performRecovery(API_URL, dirs(), "default", PHRASE);

		expect(report.org_id).toBe(world.org.orgId);
		expect(report.agents).toMatchObject([
			{ agent_id: AGENT, status: AgentRecoveryStatus.Restored, key_gen: 0 },
		]);
		const agent = world.agents.get(AGENT)![0]!;
		expect(loadAgentKeys(configDir, AGENT).signing.publicKey).toEqual(
			agent.derived.ed25519.publicKey,
		);
		expect(loadRoot(ownerDir)).toEqual(ROOT);
		expect(fs.existsSync(join(ownerDir, PHRASE_FILE))).toBe(true);
		expect(loadProfiles(ownerDir).default?.org_id).toBe(world.org.orgId);
	});

	it("test_performRecovery_when_a_gap_marker_is_on_disk_then_the_report_lists_it", async () => {
		writeGap(configDir, AGENT, GROUP, { epoch: 7, reason: EscrowLoss.Refused });

		const report = await performRecovery(API_URL, dirs(), "default", PHRASE);

		expect(report.gap_markers).toEqual([
			{ agent_id: AGENT, group_id: GROUP, epoch: 7, reason: EscrowLoss.Refused },
		]);
	});

	it("test_performRecovery_when_no_org_matches_the_phrase_then_it_refuses_and_writes_nothing", async () => {
		tokenStatus = 401;

		await expect(performRecovery(API_URL, dirs(), "default", PHRASE)).rejects.toThrow(
			NO_ORG_FOR_PHRASE,
		);
		expect(fs.existsSync(ownerDir)).toBe(false);
	});

	it("test_performRecovery_when_the_clock_is_off_then_the_refusal_names_the_clock_not_the_phrase", async () => {
		tokenStatus = 401;
		tokenBody = {
			error: "invalid_client",
			reason: "clock_skew",
			detail: "clock skew: check this machine's clock",
		};

		const attempt = performRecovery(API_URL, dirs(), "default", PHRASE);

		await expect(attempt).rejects.toThrow("clock skew");
		await expect(attempt).rejects.not.toThrow(NO_ORG_FOR_PHRASE);
		expect(fs.existsSync(ownerDir)).toBe(false);
	});

	it("test_performRecovery_when_the_org_words_are_asked_for_then_they_arrive_before_any_request", async () => {
		const seen: number[] = [];
		await performRecovery(API_URL, dirs(), "default", PHRASE, () => {
			seen.push(requests.length);
		});

		expect(seen).toEqual([0]);
	});

	it("test_performRecovery_when_the_server_copy_differs_then_the_agent_is_a_mismatch_and_not_restored", async () => {
		const foreign = new World(new Uint8Array(32).fill(9));
		const impostor = foreign.addAgent({ id: AGENT });
		world.agents.set(AGENT, [{ ...impostor, org: world.org }]);

		const report = await performRecovery(API_URL, dirs(), "default", PHRASE);

		expect(report.agents[0]?.status).toBe(AgentRecoveryStatus.Mismatch);
		expect(() => loadAgentKeys(configDir, AGENT)).toThrow();
	});

	it("test_performRecovery_when_the_server_reports_an_old_generation_as_current_then_the_agent_is_a_mismatch", async () => {
		world.addAgent({ id: AGENT, gen: 1 });
		currentGen = 0;

		const report = await performRecovery(API_URL, dirs(), "default", PHRASE);

		expect(report.agents[0]).toMatchObject({
			status: AgentRecoveryStatus.Mismatch,
			reason: expect.stringContaining("below one it also serves"),
		});
		expect(() => loadAgentKeys(configDir, AGENT)).toThrow();
	});

	it("test_performRecovery_when_the_server_reports_an_older_generation_than_the_device_holds_then_the_agent_is_a_mismatch", async () => {
		world.addAgent({ id: AGENT, gen: 1 });
		saveAgentKeys(configDir, AGENT, agentKeysFromDerived(world.agents.get(AGENT)![1]!.derived));
		currentGen = 0;
		const requestsBefore = requests.length;

		const report = await performRecovery(API_URL, dirs(), "default", PHRASE);

		expect(report.agents[0]).toMatchObject({
			status: AgentRecoveryStatus.Mismatch,
			reason: expect.stringContaining("older than the one held on this device"),
		});
		expect(requests.length).toBeGreaterThan(requestsBefore);
		expect(loadAgentKeys(configDir, AGENT).keyGen).toBe(1);
	});

	it("test_performRecovery_when_a_later_agent_fails_to_load_then_no_earlier_agent_keys_are_written", async () => {
		world.addAgent({ id: SECOND_AGENT });
		agentIds = [AGENT, SECOND_AGENT];
		failKeysFor = SECOND_AGENT;

		await expect(performRecovery(API_URL, dirs(), "default", PHRASE)).rejects.toThrow();

		expect(() => loadAgentKeys(configDir, AGENT)).toThrow();
		expect(fs.existsSync(join(ownerDir, ROOT_KEY_FILE))).toBe(false);
	});

	it("test_performRecovery_when_agents_are_reseated_then_the_root_is_saved_only_afterwards", async () => {
		await performRecovery(API_URL, dirs(), "default", PHRASE);

		expect(rootAtGroupsRead).toBe(false);
		expect(fs.existsSync(join(ownerDir, ROOT_KEY_FILE))).toBe(true);
	});

	it("test_performRecovery_when_an_org_root_exists_then_it_refuses_before_any_request", async () => {
		fs.mkdirSync(ownerDir, { recursive: true });
		fs.writeFileSync(join(ownerDir, ROOT_KEY_FILE), "x");

		await expect(performRecovery(API_URL, dirs(), "default", PHRASE)).rejects.toThrow(
			/org root already exists/,
		);
		expect(requests).toEqual([]);
	});

	it("test_performRecovery_report_and_output_never_contain_the_phrase", async () => {
		const captured: string[] = [];
		for (const method of ["log", "info", "warn", "error"] as const) {
			vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
				captured.push(args.map(String).join(" "));
			});
		}
		const report = await performRecovery(API_URL, dirs(), "default", PHRASE);

		const words = PHRASE.split(/\s+/);
		const haystacks = [JSON.stringify(report), captured.join("\n")];
		for (let i = 0; i + 3 <= words.length; i++) {
			const run = words.slice(i, i + 3).join(" ");
			for (const haystack of haystacks) expect(haystack).not.toContain(run);
		}
	});
});
