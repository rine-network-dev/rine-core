import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { saveBranchSecrets } from "../src/branch-files.js";
import {
	agentKeysFromDerived,
	deriveAgent,
	deriveBranch,
	deriveOrg,
	saveAgentKeys,
} from "../src/crypto/index.js";
import { ORG_CLAIM_MISMATCH, resolveAuth } from "../src/auth-resolve.js";
import { loadCustody, localAgentIds } from "../src/custody.js";
import { saveRoot } from "../src/owner.js";
import { PrincipalKind } from "../src/principal.js";
import { saveProfiles } from "../src/profiles.js";
import { FIXTURE_ROOT } from "../src/testing.js";

const AGENT_ID = "11111111-1111-4111-8111-111111111111";
const BRANCH = "main";

let tmp: string;
let configDir: string;
let ownerDir: string;

const dirs = () => ({ configDir, ownerDir });
const org = () => deriveOrg(FIXTURE_ROOT);

beforeEach(() => {
	tmp = fs.mkdtempSync(join(tmpdir(), "rine-custody-"));
	configDir = join(tmp, "config");
	ownerDir = join(tmp, "owner");
	fs.mkdirSync(configDir, { recursive: true });
	fs.mkdirSync(ownerDir, { recursive: true });
});

afterEach(() => {
	fs.rmSync(tmp, { recursive: true, force: true });
});

describe("loadCustody", () => {
	it("test_loadCustody_when_root_exists_then_orgId_matches_deriveOrg", () => {
		saveRoot(ownerDir, FIXTURE_ROOT);
		expect(loadCustody(dirs(), BRANCH).orgId).toBe(org().orgId);
	});

	it("test_loadCustody_when_only_branch_key_files_then_branch_matches_the_root_derived_branch", () => {
		const derived = deriveBranch(org(), BRANCH);
		saveBranchSecrets(configDir, derived);
		saveProfiles(configDir, {
			default: {
				org_id: org().orgId,
				principal: `branch:${org().orgId}:${BRANCH}`,
				branch: BRANCH,
			},
		});

		const custody = loadCustody(dirs(), BRANCH);
		expect(custody.orgId).toBe(org().orgId);
		expect(custody.branch.ed25519.publicKey).toEqual(derived.ed25519.publicKey);
		expect(custody.branch.mlDsa65.publicKey).toEqual(derived.mlDsa65.publicKey);
		expect(custody.branch.reader.publicKey).toEqual(derived.reader.publicKey);
	});

	it("test_loadCustody_when_neither_root_nor_branch_files_then_throws", () => {
		expect(() => loadCustody(dirs(), BRANCH)).toThrow(/No key material/);
	});
});

describe("localAgentIds", () => {
	it("test_localAgentIds_when_keys_dir_holds_mixed_names_then_lists_only_canonical_uuids", () => {
		const keys = join(configDir, "keys");
		fs.mkdirSync(join(keys, AGENT_ID), { recursive: true });
		fs.mkdirSync(join(keys, "not-a-uuid"), { recursive: true });
		fs.mkdirSync(join(keys, "11111111-1111-4111-8111-11111111111Z"), {
			recursive: true,
		});
		fs.writeFileSync(join(keys, "stray.txt"), "x");

		expect(localAgentIds(configDir)).toEqual([AGENT_ID]);
	});

	it("test_localAgentIds_when_keys_dir_is_absent_then_returns_empty", () => {
		expect(localAgentIds(configDir)).toEqual([]);
	});
});

describe("resolveAuth", () => {
	it("test_resolveAuth_when_root_and_owner_default_profile_then_org_principal_cached_in_owner_dir", () => {
		saveRoot(ownerDir, FIXTURE_ROOT);
		saveProfiles(ownerDir, {
			default: { org_id: org().orgId, principal: `org:${org().orgId}` },
		});

		const auth = resolveAuth(dirs());
		expect(auth?.signer.principal).toEqual({
			kind: PrincipalKind.Org,
			orgId: org().orgId,
		});
		expect(auth?.cacheDir).toBe(ownerDir);
		expect(auth?.agentId).toBeUndefined();
	});

	it("test_resolveAuth_when_no_root_and_runtime_agent_profile_then_agent_principal_cached_in_config_dir", () => {
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

		const auth = resolveAuth(dirs());
		expect(auth?.signer.principal).toEqual({
			kind: PrincipalKind.Agent,
			agentId: AGENT_ID,
		});
		expect(auth?.cacheDir).toBe(configDir);
		expect(auth?.agentId).toBe(AGENT_ID);
	});

	it("test_resolveAuth_when_explicit_profile_name_then_runtime_profile_wins_over_the_root", () => {
		saveRoot(ownerDir, FIXTURE_ROOT);
		saveProfiles(ownerDir, {
			default: { org_id: org().orgId, principal: `org:${org().orgId}` },
		});
		const derived = deriveAgent(deriveBranch(org(), BRANCH), AGENT_ID, 0);
		saveAgentKeys(configDir, AGENT_ID, agentKeysFromDerived(derived));
		saveProfiles(configDir, {
			work: {
				org_id: org().orgId,
				principal: `agent:${AGENT_ID}`,
				agent_id: AGENT_ID,
				branch: BRANCH,
			},
		});

		const auth = resolveAuth(dirs(), "work");
		expect(auth?.signer.principal).toEqual({
			kind: PrincipalKind.Agent,
			agentId: AGENT_ID,
		});
		expect(auth?.cacheDir).toBe(configDir);
	});

	it("test_resolveAuth_when_org_profile_org_id_differs_from_root_then_it_throws", () => {
		saveRoot(ownerDir, FIXTURE_ROOT);
		saveProfiles(ownerDir, {
			default: {
				org_id: "99999999-9999-4999-8999-999999999999",
				principal: "org:99999999-9999-4999-8999-999999999999",
			},
		});

		expect(() => resolveAuth(dirs())).toThrow(ORG_CLAIM_MISMATCH);
	});

	it("test_resolveAuth_when_branch_profile_org_id_differs_from_its_principal_then_it_throws", () => {
		const derived = deriveBranch(org(), BRANCH);
		saveBranchSecrets(configDir, derived);
		saveProfiles(configDir, {
			default: {
				org_id: "99999999-9999-4999-8999-999999999999",
				principal: `branch:${org().orgId}:${BRANCH}`,
				branch: BRANCH,
			},
		});

		expect(() => resolveAuth(dirs())).toThrow(ORG_CLAIM_MISMATCH);
	});

	it("test_resolveAuth_when_branch_profile_principal_matches_org_id_but_root_differs_then_it_throws", () => {
		saveRoot(ownerDir, FIXTURE_ROOT);
		const other = deriveOrg(new Uint8Array(32).fill(6));
		saveProfiles(ownerDir, {
			default: {
				org_id: other.orgId,
				principal: `branch:${other.orgId}:${BRANCH}`,
				branch: BRANCH,
			},
		});

		expect(() => resolveAuth(dirs())).toThrow(ORG_CLAIM_MISMATCH);
	});

	it("test_resolveAuth_when_reader_profile_org_id_differs_from_its_principal_then_it_throws", () => {
		saveRoot(ownerDir, FIXTURE_ROOT);
		saveProfiles(ownerDir, {
			default: {
				org_id: "99999999-9999-4999-8999-999999999999",
				principal: `reader:${org().orgId}`,
			},
		});

		expect(() => resolveAuth(dirs())).toThrow(ORG_CLAIM_MISMATCH);
	});

	it("test_resolveAuth_when_no_profile_then_undefined", () => {
		expect(resolveAuth(dirs())).toBeUndefined();
	});

	it("test_resolveAuth_when_branch_profile_and_no_root_then_resolves_from_branch_key_files", () => {
		const derived = deriveBranch(org(), BRANCH);
		saveBranchSecrets(configDir, derived);
		saveProfiles(configDir, {
			default: {
				org_id: org().orgId,
				principal: `branch:${org().orgId}:${BRANCH}`,
				branch: BRANCH,
			},
		});

		const auth = resolveAuth(dirs());
		expect(auth?.signer.principal).toEqual({
			kind: PrincipalKind.Branch,
			orgId: org().orgId,
			name: BRANCH,
		});
		expect(auth?.signer.seed).toEqual(derived.ed25519.privateKey);
		expect(auth?.cacheDir).toBe(configDir);
	});
});

