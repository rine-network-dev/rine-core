/**
 * Whether this host has an MLS store for an agent.
 *
 * The question is answered from the filesystem alone — the store root exists as
 * a directory — so it never opens the native addon. An absent path is the answer
 * `false`; a path that is a regular file is not a store either.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { mlsStoreRoot } from "../../src/crypto/mls.js";
import { holdsMlsStore } from "../../src/crypto/mls-store-probe.js";

const AGENT = "a1a1a1a1-0000-4000-8000-000000000001";

let dirs: string[] = [];

function configDir(): string {
	const dir = fs.mkdtempSync(join(tmpdir(), "rine-store-held-"));
	dirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of dirs) {
		fs.rmSync(dir, { recursive: true, force: true });
	}
	dirs = [];
});

describe("holdsMlsStore", () => {
	it("test_holds_when_the_store_root_is_absent_then_it_is_false", () => {
		expect(holdsMlsStore(configDir(), AGENT)).toBe(false);
	});

	it("test_holds_when_the_store_root_is_a_directory_then_it_is_true", () => {
		const dir = configDir();
		fs.mkdirSync(mlsStoreRoot(dir, AGENT), { recursive: true });
		expect(holdsMlsStore(dir, AGENT)).toBe(true);
	});

	it("test_holds_when_the_store_root_is_a_regular_file_then_it_is_false", () => {
		const dir = configDir();
		const root = mlsStoreRoot(dir, AGENT);
		fs.mkdirSync(join(root, ".."), { recursive: true });
		fs.writeFileSync(root, "not a store");
		expect(holdsMlsStore(dir, AGENT)).toBe(false);
	});
});
