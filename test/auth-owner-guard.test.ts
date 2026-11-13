import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveAuth } from "../src/auth-resolve.js";
import {
	agentKeysFromDerived,
	deriveAgent,
	deriveBranch,
	deriveOrg,
	saveAgentKeys,
} from "../src/crypto/index.js";
import { saveRoot } from "../src/owner.js";
import { PrincipalKind } from "../src/principal.js";
import { saveProfiles } from "../src/profiles.js";
import { FIXTURE_ROOT } from "../src/testing.js";

const AGENT_ID = "11111111-1111-4111-8111-111111111111";
const BRANCH = "main";
const OTHER_ROOT = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

let tmp: string;
let configDir: string;
let ownerDir: string;

/** An owner dir holding `root`'s org root and org profile. */
function holdOwner(root: Uint8Array): void {
	const org = deriveOrg(root);
	saveRoot(ownerDir, root);
	saveProfiles(ownerDir, {
		default: { org_id: org.orgId, principal: `org:${org.orgId}` },
	});
}

/** A runtime dir holding the fixed agent of `root`'s org (an agent kit). */
function holdAgent(root: Uint8Array): void {
	const org = deriveOrg(root);
	const derived = deriveAgent(deriveBranch(org, BRANCH), AGENT_ID, 0);
	saveAgentKeys(configDir, AGENT_ID, agentKeysFromDerived(derived));
	saveProfiles(configDir, {
		default: {
			org_id: org.orgId,
			principal: `agent:${AGENT_ID}`,
			agent_id: AGENT_ID,
			branch: BRANCH,
		},
	});
}

beforeEach(() => {
	tmp = fs.mkdtempSync(join(tmpdir(), "rine-owner-guard-"));
	configDir = join(tmp, "config");
	ownerDir = join(tmp, "owner");
	fs.mkdirSync(configDir, { recursive: true });
	fs.mkdirSync(ownerDir, { recursive: true });
});

afterEach(() => {
	fs.rmSync(tmp, { recursive: true, force: true });
});

describe("resolveAuth when the owner dir and the runtime dir name different orgs", () => {
	it("test_resolveAuth_when_owner_root_is_org_a_and_runtime_agent_is_org_b_then_signs_as_the_runtime_agent", () => {
		holdOwner(OTHER_ROOT);
		holdAgent(FIXTURE_ROOT);

		const auth = resolveAuth({ configDir, ownerDir });

		expect(auth?.signer.principal).toEqual({
			kind: PrincipalKind.Agent,
			agentId: AGENT_ID,
		});
		expect(auth?.orgId).toBe(deriveOrg(FIXTURE_ROOT).orgId);
		expect(auth?.cacheDir).toBe(configDir);
		expect(auth?.agentId).toBe(AGENT_ID);
	});

	it("test_resolveAuth_when_owner_root_is_the_same_org_as_the_runtime_agent_then_signs_as_the_org", () => {
		holdOwner(FIXTURE_ROOT);
		holdAgent(FIXTURE_ROOT);

		const auth = resolveAuth({ configDir, ownerDir });

		expect(auth?.signer.principal).toEqual({
			kind: PrincipalKind.Org,
			orgId: deriveOrg(FIXTURE_ROOT).orgId,
		});
		expect(auth?.cacheDir).toBe(ownerDir);
	});

	it("test_resolveAuth_when_runtime_dir_has_no_profile_then_the_owner_org_signs", () => {
		holdOwner(FIXTURE_ROOT);

		const auth = resolveAuth({ configDir, ownerDir });

		expect(auth?.signer.principal).toEqual({
			kind: PrincipalKind.Org,
			orgId: deriveOrg(FIXTURE_ROOT).orgId,
		});
		expect(auth?.cacheDir).toBe(ownerDir);
	});

	it("test_resolveAuth_when_named_profile_names_another_org_than_the_owner_then_the_runtime_profile_signs", () => {
		holdOwner(OTHER_ROOT);
		holdAgent(FIXTURE_ROOT);
		const named = {
			org_id: deriveOrg(FIXTURE_ROOT).orgId,
			principal: `agent:${AGENT_ID}`,
			agent_id: AGENT_ID,
			branch: BRANCH,
		};
		saveProfiles(configDir, { default: named, kit: named });

		const auth = resolveAuth({ configDir, ownerDir }, "kit");

		expect(auth?.signer.principal).toEqual({
			kind: PrincipalKind.Agent,
			agentId: AGENT_ID,
		});
	});
});
