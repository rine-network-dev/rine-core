import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolveAuth } from "../src/auth-resolve.js";
import { loadDelegateSeed, saveDelegateSeed } from "../src/delegate-files.js";
import type { HttpClient } from "../src/http.js";
import * as gov from "../src/org-governance.js";
import { DelegateScope } from "../src/org-governance-types.js";
import { PrincipalKind, parsePrincipal, principalString } from "../src/principal.js";
import { saveProfiles } from "../src/profiles.js";
import shapes from "./fixtures/governance-shapes.json" with { type: "json" };

const AGENT = "11111111-1111-4111-8111-111111111111";
const DELEGATE = "33333333-3333-4333-8333-333333333333";
const ORG = "22222222-2222-4222-8222-222222222222";

function fake() {
	const fn = () => vi.fn(async () => ({ changed: true }));
	return { get: fn(), post: fn(), patch: fn(), delete: fn() } as unknown as HttpClient &
		Record<"get" | "post" | "patch" | "delete", ReturnType<typeof vi.fn>>;
}

describe("org governance routes", () => {
	it("test_suspend_when_agent_then_posts_to_agent_suspend", async () => {
		const c = fake();
		await gov.suspendAgent(c, AGENT);
		await gov.resumeAgent(c, AGENT);
		expect(c.post.mock.calls.map((x) => x[0])).toEqual([
			`/agents/${AGENT}/suspend`,
			`/agents/${AGENT}/resume`,
		]);
		await gov.getSuspension(c, AGENT);
		expect(c.get).toHaveBeenCalledWith(`/agents/${AGENT}/suspension`);
	});

	it("test_suspend_when_id_not_uuid_then_refused_before_any_request", async () => {
		const c = fake();
		await expect(gov.suspendAgent(c, "../x")).rejects.toThrow(/Invalid agent ID/);
		expect(c.post).not.toHaveBeenCalled();
	});

	it("test_branch_when_name_then_suspend_and_resume_paths", async () => {
		const c = fake();
		await gov.suspendBranch(c, "partner-a");
		await gov.resumeBranch(c, "partner-a");
		expect(c.post.mock.calls.map((x) => x[0])).toEqual([
			"/orgs/me/branches/partner-a/suspend",
			"/orgs/me/branches/partner-a/resume",
		]);
		await expect(gov.suspendBranch(c, "Bad Name")).rejects.toThrow();
	});

	it("test_freeze_when_called_then_org_routes", async () => {
		const c = fake();
		await gov.freezeOrg(c);
		await gov.unfreezeOrg(c);
		expect(c.post.mock.calls.map((x) => x[0])).toEqual(["/org/freeze", "/org/unfreeze"]);
	});

	it("test_delegate_when_created_then_only_public_key_leaves", async () => {
		const c = fake();
		const key = gov.newDelegateKey();
		expect(key.seed).toHaveLength(32);
		await gov.createDelegate(c, "ops-bot", [DelegateScope.Suspend], key.publicKey);
		const [path, body] = c.post.mock.calls[0] as [string, Record<string, unknown>];
		expect(path).toBe("/org/delegates");
		expect(body).toEqual({
			name: "ops-bot",
			scopes: ["suspend"],
			signing_public_key: key.publicKey,
		});
		expect(JSON.stringify(body)).not.toContain(Buffer.from(key.seed).toString("base64url"));
		await gov.listDelegates(c);
		await gov.revokeDelegate(c, DELEGATE);
		expect(c.get).toHaveBeenCalledWith("/org/delegates");
		expect(c.delete).toHaveBeenCalledWith(`/org/delegates/${DELEGATE}`);
	});

	it("test_events_when_fetched_then_cursor_and_limit_are_params", async () => {
		const c = fake();
		await gov.fetchOrgEvents(c, 7, 50);
		await gov.fetchOrgEvents(c, 0);
		await gov.listAgentStates(c);
		expect(c.get.mock.calls).toEqual([
			["/org/events", { after_seq: 7, limit: 50 }],
			["/org/events", { after_seq: 0 }],
			["/org/agents/states"],
		]);
	});
});

/** `governance-shapes.json` is each response model of `schemas_governance.py` dumped as the server sends it. */
describe("governance response shapes", () => {
	const answering = (body: unknown) =>
		({ get: vi.fn(async () => body) }) as unknown as HttpClient;

	it("test_list_delegates_when_server_wraps_the_list_then_returns_the_array", async () => {
		const list = await gov.listDelegates(answering(shapes.delegate_list));
		expect(list).toEqual(shapes.delegate_list.delegates);
		expect(list[0]?.name).toBe("ops");
	});

	it("test_list_agent_states_when_server_answers_a_bare_array_then_a_branchless_agent_passes", async () => {
		const states = await gov.listAgentStates(answering(shapes.agent_states));
		expect(states.map((s) => s.branch)).toEqual(["main", null]);
	});
});

describe("pickAgent", () => {
	const agents = [
		{ id: AGENT, name: "alpha", handle: "alpha@acme.rine.network" },
		{ id: DELEGATE, name: "beta", handle: null },
	];

	it("test_pick_when_uuid_then_passes_through", () => {
		expect(gov.pickAgent(agents, AGENT.toUpperCase())).toBe(AGENT);
	});

	it("test_pick_when_handle_or_name_then_resolves", () => {
		expect(gov.pickAgent(agents, "alpha@acme.rine.network")).toBe(AGENT);
		expect(gov.pickAgent(agents, "beta")).toBe(DELEGATE);
	});

	it("test_pick_when_no_match_then_throws_and_never_falls_back_to_the_only_agent", () => {
		expect(() => gov.pickAgent([agents[0] as (typeof agents)[0]], "other")).toThrow(/No agent matches/);
	});

	it("test_pick_when_ambiguous_then_throws", () => {
		const twins = [
			{ id: AGENT, name: "same", handle: null },
			{ id: DELEGATE, name: "same", handle: null },
		];
		expect(() => gov.pickAgent(twins, "same")).toThrow(/matches 2 agents/);
	});
});

describe("delegate principal and key file", () => {
	let tmp: string;
	beforeEach(() => {
		tmp = fs.mkdtempSync(join(tmpdir(), "rine-delegate-"));
	});
	afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

	it("test_principal_when_delegate_then_round_trips_without_an_org", () => {
		const p = { kind: PrincipalKind.Delegate, delegateId: DELEGATE } as const;
		expect(principalString(p)).toBe(`delegate:${DELEGATE}`);
		expect(parsePrincipal(`delegate:${DELEGATE}`)).toEqual(p);
		expect(() => parsePrincipal(`delegate:${DELEGATE}:main`)).toThrow();
		expect(() => parsePrincipal("delegate:nope")).toThrow();
	});

	it("test_seed_when_saved_then_loads_back_with_mode_0600", () => {
		const seed = new Uint8Array(32).fill(9);
		saveDelegateSeed(tmp, DELEGATE, seed);
		expect(loadDelegateSeed(tmp, DELEGATE)).toEqual(seed);
		const mode = fs.statSync(join(tmp, "delegates", `${DELEGATE}.json`)).mode & 0o777;
		expect(mode).toBe(0o600);
		expect(loadDelegateSeed(tmp, "44444444-4444-4444-8444-444444444444")).toBeUndefined();
	});

	it("test_seed_when_file_names_another_delegate_then_corrupt", () => {
		saveDelegateSeed(tmp, DELEGATE, new Uint8Array(32).fill(1));
		const other = "44444444-4444-4444-8444-444444444444";
		fs.copyFileSync(
			join(tmp, "delegates", `${DELEGATE}.json`),
			join(tmp, "delegates", `${other}.json`),
		);
		expect(() => loadDelegateSeed(tmp, other)).toThrow(/Corrupt delegate key file/);
	});

	it("test_resolve_when_delegate_profile_then_signs_as_delegate_with_no_org_key", () => {
		saveDelegateSeed(tmp, DELEGATE, new Uint8Array(32).fill(5));
		saveProfiles(tmp, {
			ops: { org_id: ORG, principal: `delegate:${DELEGATE}` },
		});
		const empty = join(tmp, "owner");
		fs.mkdirSync(empty);
		const r = resolveAuth({ configDir: tmp, ownerDir: empty }, "ops");
		expect(r?.signer.principal).toEqual({ kind: PrincipalKind.Delegate, delegateId: DELEGATE });
		expect(r?.orgId).toBe(ORG);
		expect(r?.cacheDir).toBe(tmp);
	});

	it("test_resolve_when_delegate_key_file_missing_then_no_identity", () => {
		saveProfiles(tmp, { ops: { org_id: ORG, principal: `delegate:${DELEGATE}` } });
		const empty = join(tmp, "owner");
		fs.mkdirSync(empty);
		expect(resolveAuth({ configDir: tmp, ownerDir: empty }, "ops")).toBeUndefined();
	});
});
