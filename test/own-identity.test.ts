import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { deriveAgent, deriveBranch, deriveOrg } from "../src/crypto/index.js";
import { pinsFor } from "../src/crypto/key-pins.js";
import { ORG_CLAIM_MISMATCH, resolveAuth } from "../src/auth-resolve.js";
import { orgIdOfAgent, ownIdentityFor, pinOwnIdentity } from "../src/own-identity.js";
import { saveRoot } from "../src/owner.js";
import { PrincipalKind, principalString } from "../src/principal.js";
import { saveProfiles } from "../src/profiles.js";
import { World } from "./crypto/world.js";
import { FIXTURE_ROOT } from "../src/testing.js";

const AGENT_A = "11111111-1111-4111-8111-111111111111";
const AGENT_B = "22222222-2222-4222-8222-222222222222";
const OTHER_ORG = "99999999-9999-4999-8999-999999999999";

let tmp: string;
let configDir: string;
let ownerDir: string;

const dirs = () => ({ configDir, ownerDir });

beforeEach(() => {
	tmp = fs.mkdtempSync(join(tmpdir(), "rine-own-identity-"));
	configDir = join(tmp, "config");
	ownerDir = join(tmp, "owner");
	fs.mkdirSync(configDir, { recursive: true });
	fs.mkdirSync(ownerDir, { recursive: true });
});

afterEach(() => {
	fs.rmSync(tmp, { recursive: true, force: true });
});

/** A config dir acting as `AGENT_A` of a fresh org, with `AGENT_B`'s keys too. */
function agentDir(): World {
	const world = new World(FIXTURE_ROOT);
	for (const id of [AGENT_A, AGENT_B]) {
		world.save(configDir, world.addAgent({ id, branch: "main" }));
	}
	saveProfiles(configDir, {
		default: {
			org_id: world.org.orgId,
			principal: `agent:${AGENT_A}`,
			agent_id: AGENT_A,
			branch: "main",
		},
	});
	return world;
}

describe("ownIdentityFor", () => {
	it("test_ownIdentityFor_when_no_auth_then_undefined", () => {
		expect(ownIdentityFor(configDir, resolveAuth(dirs()))).toBeUndefined();
	});

	it("test_ownIdentityFor_when_agent_profile_then_org_id_and_local_agent_ids", () => {
		const world = agentDir();
		expect(ownIdentityFor(configDir, resolveAuth(dirs()))).toEqual({
			orgId: world.org.orgId,
			agentIds: [AGENT_A, AGENT_B],
		});
	});

	it("test_ownIdentityFor_when_named_profile_absent_then_undefined", () => {
		agentDir();
		expect(ownIdentityFor(configDir, resolveAuth(dirs(), "work"))).toBeUndefined();
	});
});

describe("pinOwnIdentity", () => {
	it("test_pinOwnIdentity_when_agent_profile_then_pins_the_org_and_local_agents", () => {
		const world = agentDir();
		const client = {};
		pinOwnIdentity(client, configDir, () => resolveAuth(dirs()));
		const pins = pinsFor(client);
		expect(pins.ownOrgId).toBe(world.org.orgId);
		expect([...pins.ownAgentIds].sort()).toEqual([AGENT_A, AGENT_B]);
	});

	it("test_pinOwnIdentity_when_no_identity_then_pins_nothing", () => {
		const client = {};
		pinOwnIdentity(client, configDir, () => resolveAuth(dirs()));
		expect(pinsFor(client).ownOrgId).toBeUndefined();
	});

	it("test_pinOwnIdentity_when_the_org_claim_is_contradicted_then_it_returns_without_pinning", () => {
		saveRoot(ownerDir, FIXTURE_ROOT);
		saveProfiles(ownerDir, {
			default: {
				org_id: OTHER_ORG,
				principal: principalString({ kind: PrincipalKind.Org, orgId: OTHER_ORG }),
			},
		});
		expect(() => resolveAuth(dirs())).toThrow(ORG_CLAIM_MISMATCH);
		const client = {};
		expect(() => pinOwnIdentity(client, configDir, () => resolveAuth(dirs()))).not.toThrow();
		expect(pinsFor(client).ownOrgId).toBeUndefined();
	});
});

describe("orgIdOfAgent", () => {
	it("test_orgIdOfAgent_when_profile_names_the_agent_then_that_org", () => {
		const world = agentDir();
		expect(orgIdOfAgent(configDir, AGENT_A)).toBe(world.org.orgId);
	});

	it("test_orgIdOfAgent_when_no_profile_names_the_agent_then_the_sole_org", () => {
		const world = agentDir();
		expect(orgIdOfAgent(configDir, AGENT_B)).toBe(world.org.orgId);
	});

	it("test_orgIdOfAgent_when_profiles_disagree_then_undefined", () => {
		const world = agentDir();
		saveProfiles(configDir, {
			default: {
				org_id: world.org.orgId,
				principal: `agent:${AGENT_A}`,
				agent_id: AGENT_A,
				branch: "main",
			},
			other: {
				org_id: OTHER_ORG,
				principal: `agent:${AGENT_B}`,
				agent_id: AGENT_B,
				branch: "main",
			},
		});
		expect(orgIdOfAgent(configDir, "33333333-3333-4333-8333-333333333333")).toBeUndefined();
	});

	it("test_orgIdOfAgent_when_no_profiles_then_undefined", () => {
		expect(orgIdOfAgent(configDir, AGENT_A)).toBeUndefined();
	});
});

describe("orgIdOfAgent with a branch profile", () => {
	it("test_orgIdOfAgent_when_only_a_branch_profile_then_its_org", () => {
		const org = deriveOrg(FIXTURE_ROOT);
		const branch = deriveBranch(org, "main");
		const derived = deriveAgent(branch, AGENT_A, 0);
		expect(derived.id).toBe(AGENT_A);
		saveProfiles(configDir, {
			default: {
				org_id: org.orgId,
				principal: `branch:${org.orgId}:main`,
				branch: "main",
			},
		});
		expect(orgIdOfAgent(configDir, AGENT_A)).toBe(org.orgId);
	});
});
