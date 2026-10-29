import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AgentOnlyOwnerDirError, resolveAuth } from "../src/auth-resolve.js";
import { saveBranchSecrets } from "../src/branch-files.js";
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
const org = () => deriveOrg(FIXTURE_ROOT);

let tmp: string;
let configDir: string;
let ownerDir: string;

const agentOnly = () => ({ configDir, agentOnly: true as const });

function holdAgent(): void {
	const derived = deriveAgent(deriveBranch(org(), BRANCH), AGENT_ID, 0);
	saveAgentKeys(configDir, AGENT_ID, agentKeysFromDerived(derived));
	saveProfiles(configDir, {
		default: {
			org_id: org().orgId,
			principal: `agent:${AGENT_ID}`,
			agent_id: AGENT_ID,
			branch: BRANCH,
		},
	});
}

beforeEach(() => {
	tmp = fs.mkdtempSync(join(tmpdir(), "rine-agent-only-"));
	configDir = join(tmp, "config");
	ownerDir = join(tmp, "owner");
	fs.mkdirSync(configDir, { recursive: true });
	fs.mkdirSync(ownerDir, { recursive: true });
	saveRoot(ownerDir, FIXTURE_ROOT);
	saveProfiles(ownerDir, {
		default: { org_id: org().orgId, principal: `org:${org().orgId}` },
	});
});

afterEach(() => {
	fs.rmSync(tmp, { recursive: true, force: true });
});

describe("resolveAuth for an agent-only runtime", () => {
	it("test_resolveAuth_when_agent_only_and_agent_profile_then_signs_as_the_agent_not_the_org", () => {
		holdAgent();

		const auth = resolveAuth(agentOnly());

		expect(auth?.signer.principal).toEqual({
			kind: PrincipalKind.Agent,
			agentId: AGENT_ID,
		});
		expect(auth?.cacheDir).toBe(configDir);
		expect(auth?.agentId).toBe(AGENT_ID);
	});

	it("test_resolveAuth_when_agent_only_and_the_host_owner_dir_holds_an_org_profile_then_nothing_resolves", () => {
		expect(resolveAuth(agentOnly())).toBeUndefined();
	});

	it("test_resolveAuth_when_agent_only_and_profile_names_a_branch_then_branch_keys_stay_unread", () => {
		saveBranchSecrets(configDir, deriveBranch(org(), BRANCH));
		saveProfiles(configDir, {
			default: {
				org_id: org().orgId,
				principal: `branch:${org().orgId}:${BRANCH}`,
				branch: BRANCH,
			},
		});

		expect(resolveAuth(agentOnly())).toBeUndefined();
	});

	it("test_resolveAuth_when_agent_only_with_an_explicit_owner_dir_then_it_throws_the_typed_error", () => {
		holdAgent();
		const dirs = { configDir, ownerDir, agentOnly: true } as unknown as Parameters<
			typeof resolveAuth
		>[0];

		expect(() => resolveAuth(dirs)).toThrow(AgentOnlyOwnerDirError);
	});
});
