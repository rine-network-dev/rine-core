import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { holdsBranchKeys, saveBranchSecrets } from "../src/branch-files.js";
import { loadCustody } from "../src/custody.js";
import { deriveBranch, deriveOrg } from "../src/crypto/derive.js";
import { addProfileIfAbsent } from "../src/profiles.js";

let dir: string;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-branch-files-"));
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("holdsBranchKeys", () => {
	it("test_holdsBranchKeys_when_a_branch_was_saved_then_true", () => {
		saveBranchSecrets(dir, deriveBranch(deriveOrg(new Uint8Array(32).fill(3)), "partner-a"));
		expect(holdsBranchKeys(dir)).toBe(true);
	});

	it("test_holdsBranchKeys_when_nothing_saved_then_false", () => {
		expect(holdsBranchKeys(dir)).toBe(false);
	});

	it("test_holdsBranchKeys_when_branch_is_a_plain_file_then_false", () => {
		fs.writeFileSync(join(dir, "branch"), "x");
		expect(holdsBranchKeys(dir)).toBe(false);
	});
});

describe("saveBranchSecrets", () => {
	it("test_loadCustody_when_only_branch_secrets_and_a_profile_exist_then_round_trips", () => {
		const branch = deriveBranch(deriveOrg(new Uint8Array(32).fill(3)), "partner-a");
		saveBranchSecrets(dir, branch);
		addProfileIfAbsent(dir, "default", { org_id: "org-1", principal: "org:org-1", branch: "partner-a" });
		const empty = fs.mkdtempSync(join(tmpdir(), "rine-no-owner-"));
		try {
			const custody = loadCustody({ configDir: dir, ownerDir: empty }, "partner-a");
			expect(custody.orgId).toBe("org-1");
			expect(custody.branch.bRead).toEqual(branch.bRead);
			expect(custody.branch.bSign).toEqual(branch.bSign);
		} finally {
			fs.rmSync(empty, { recursive: true, force: true });
		}
	});
});
