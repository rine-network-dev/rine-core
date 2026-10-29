import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { phraseFromEntropy, toBase64Url } from "../src/crypto/index.js";
import {
	PHRASE_FILE,
	ROOT_KEY_FILE,
	assertOwnerDirAllowed,
	loadRoot,
	readOwnerPhrase,
	removeOwnerFiles,
	saveRoot,
} from "../src/owner.js";

const ROOT = new Uint8Array(32).fill(9);

let tmp: string;

beforeEach(() => {
	tmp = fs.mkdtempSync(join(tmpdir(), "rine-owner-"));
});

afterEach(() => {
	fs.rmSync(tmp, { recursive: true, force: true });
	vi.restoreAllMocks();
});

describe("saveRoot / loadRoot", () => {
	it("test_saveRoot_when_called_then_writes_both_files_0600_in_a_0700_dir", () => {
		const ownerDir = join(tmp, "owner");
		saveRoot(ownerDir, ROOT);

		expect(fs.statSync(ownerDir).mode & 0o777).toBe(0o700);
		for (const file of [ROOT_KEY_FILE, PHRASE_FILE]) {
			expect(fs.statSync(join(ownerDir, file)).mode & 0o777).toBe(0o600);
		}
		expect(fs.readFileSync(join(ownerDir, ROOT_KEY_FILE), "utf-8").trim()).toBe(
			toBase64Url(ROOT),
		);
	});

	it("test_loadRoot_when_saved_then_returns_the_same_bytes", () => {
		const ownerDir = join(tmp, "owner");
		saveRoot(ownerDir, ROOT);
		expect(loadRoot(ownerDir)).toEqual(ROOT);
	});

	it("test_loadRoot_when_no_root_file_then_returns_undefined", () => {
		expect(loadRoot(join(tmp, "empty"))).toBeUndefined();
	});

	it("test_saveRoot_when_called_twice_then_throws", () => {
		const ownerDir = join(tmp, "owner");
		saveRoot(ownerDir, ROOT);
		expect(() => saveRoot(ownerDir, new Uint8Array(32).fill(1))).toThrow(
			/already exists/,
		);
	});

	it("test_saveRoot_when_root_key_is_a_dangling_link_then_it_is_kept_and_named", () => {
		const ownerDir = join(tmp, "owner");
		fs.mkdirSync(ownerDir, { recursive: true });
		const path = join(ownerDir, ROOT_KEY_FILE);
		fs.symlinkSync(join(tmp, "nowhere"), path);

		expect(() => saveRoot(ownerDir, ROOT)).toThrow(/is not an org root/);
		expect(fs.readlinkSync(path)).toBe(join(tmp, "nowhere"));
	});

	it("test_loadRoot_when_root_key_has_the_wrong_length_then_throws", () => {
		const ownerDir = join(tmp, "owner");
		fs.mkdirSync(ownerDir, { recursive: true });
		fs.writeFileSync(join(ownerDir, ROOT_KEY_FILE), `${toBase64Url(new Uint8Array(16))}\n`);
		expect(() => loadRoot(ownerDir)).toThrow(/Corrupt/);
	});
});

describe("assertOwnerDirAllowed", () => {
	it("test_assertOwnerDirAllowed_when_dir_is_inside_a_git_worktree_then_throws", () => {
		const repo = join(tmp, "repo");
		fs.mkdirSync(join(repo, ".git"), { recursive: true });
		expect(() => assertOwnerDirAllowed(join(repo, "owner"))).toThrow(/git worktree/);
	});

	it("test_assertOwnerDirAllowed_when_dir_is_cwd_dot_rine_then_throws", () => {
		const cwd = join(tmp, "project");
		fs.mkdirSync(cwd, { recursive: true });
		vi.spyOn(process, "cwd").mockReturnValue(cwd);
		expect(() => assertOwnerDirAllowed(join(cwd, ".rine", "owner"))).toThrow(
			/project \.rine/,
		);
	});

	it("test_assertOwnerDirAllowed_when_a_symlink_leads_into_a_git_worktree_then_throws", () => {
		const repo = join(tmp, "repo");
		fs.mkdirSync(join(repo, ".git"), { recursive: true });
		fs.symlinkSync(repo, join(tmp, "link"));
		expect(() => assertOwnerDirAllowed(join(tmp, "link", "owner"))).toThrow(/git worktree/);
	});

	it("test_assertOwnerDirAllowed_when_dir_equals_or_contains_the_config_dir_then_throws", () => {
		const config = join(tmp, "outer", "config");
		fs.mkdirSync(config, { recursive: true });
		expect(() => assertOwnerDirAllowed(config, config)).toThrow(/config/);
		expect(() => assertOwnerDirAllowed(join(tmp, "outer"), config)).toThrow(/config/);
		expect(() => assertOwnerDirAllowed(join(config, "owner"), config)).toThrow(/config/);
	});

	it("test_assertOwnerDirAllowed_when_dir_is_a_plain_temp_dir_then_passes", () => {
		expect(() => assertOwnerDirAllowed(join(tmp, "owner"))).not.toThrow();
	});
});

describe("readOwnerPhrase", () => {
	it("test_readOwnerPhrase_when_root_exists_then_equals_phraseFromEntropy", () => {
		const ownerDir = join(tmp, "owner");
		saveRoot(ownerDir, ROOT);
		expect(readOwnerPhrase(ownerDir)).toBe(phraseFromEntropy(ROOT));
	});

	it("test_readOwnerPhrase_when_phrase_file_is_deleted_then_still_works", () => {
		const ownerDir = join(tmp, "owner");
		saveRoot(ownerDir, ROOT);
		fs.rmSync(join(ownerDir, PHRASE_FILE));
		expect(readOwnerPhrase(ownerDir)).toBe(phraseFromEntropy(ROOT));
	});
});

describe("removeOwnerFiles", () => {
	it("test_removeOwnerFiles_when_called_then_removes_the_three_files", () => {
		const ownerDir = join(tmp, "owner");
		saveRoot(ownerDir, ROOT);
		fs.writeFileSync(join(ownerDir, "profiles.json"), "{}");

		removeOwnerFiles(ownerDir);

		for (const file of [ROOT_KEY_FILE, PHRASE_FILE, "profiles.json"]) {
			expect(fs.existsSync(join(ownerDir, file))).toBe(false);
		}
	});
});
