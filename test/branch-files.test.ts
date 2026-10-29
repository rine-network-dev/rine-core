import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { holdsBranchKeys, saveBranchSecrets } from "../src/branch-files.js";
import { deriveBranch, deriveOrg } from "../src/crypto/derive.js";

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
