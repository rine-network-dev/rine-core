import * as fs from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { deriveBranch, deriveOrg } from "../src/crypto/derive.js";
import { toBase64Url } from "../src/crypto/keys.js";
import { ReadKey } from "../src/org-reader/keys.js";
import { ROOT_KEY_FILE } from "../src/owner.js";
import { PrincipalKind } from "../src/principal.js";
import { hex, kat, unhex } from "./crypto/kat-fixture.js";

const root = kat.roots.roots[0];
const dirs: string[] = [];

function ownerDirWith(rootBytes: Uint8Array): string {
	const dir = mkdtempSync(join(tmpdir(), "rine-readkey-"));
	dirs.push(dir);
	fs.writeFileSync(join(dir, ROOT_KEY_FILE), toBase64Url(rootBytes));
	return dir;
}

afterEach(() => {
	for (const dir of dirs.splice(0))
		rmSync(dir, { recursive: true, force: true });
});

describe("ReadKey", () => {
	it("fromOwnerDir takes the org id from the root", () => {
		const key = ReadKey.fromOwnerDir(ownerDirWith(unhex(root.entropy)));
		expect(key.orgId).toBe(root.org.org_id);
		expect(key.principal).toEqual({
			kind: PrincipalKind.Reader,
			orgId: root.org.org_id,
		});
		expect(hex(key.signer.seed)).toBe(root.org.reader.seed);
	});

	it("fromOwnerDir without a root.key throws", () => {
		const dir = mkdtempSync(join(tmpdir(), "rine-readkey-"));
		dirs.push(dir);
		expect(() => ReadKey.fromOwnerDir(dir)).toThrow(/No root\.key/);
	});

	it("fromRoot leaves the caller's root untouched", () => {
		const entropy = unhex(root.entropy);
		ReadKey.fromRoot(entropy);
		expect(hex(entropy)).toBe(root.entropy);
	});

	it("branchRead equals the full derivation's bRead and is cached", () => {
		const entropy = unhex(root.entropy);
		const key = ReadKey.fromRoot(entropy);
		const expected = deriveBranch(deriveOrg(entropy), "main").bRead;
		expect(hex(key.branchRead("main"))).toBe(hex(expected));
		expect(key.branchRead("main")).toBe(key.branchRead("main"));
	});

	it("branchRead rejects an invalid branch name", () => {
		const key = ReadKey.fromRoot(unhex(root.entropy));
		expect(() => key.branchRead("Bad Name")).toThrow(/invalid branch name/);
	});

	it("shows no secret bytes through JSON.stringify, Object.keys or inspect", () => {
		const key = ReadKey.fromRoot(unhex(root.entropy));
		key.branchRead("main");
		const secrets = [root.r_read, root.org.reader.seed, root.entropy];
		const shown = [
			JSON.stringify(key),
			inspect(key, { showHidden: true, depth: 5 }),
			Object.keys(key).join(","),
			Object.getOwnPropertyNames(key).join(","),
		].join("\n");
		for (const secret of secrets) expect(shown).not.toContain(secret);
		expect(Object.keys(key)).toEqual(["orgId"]);
	});

	it("dispose zeroes the signer seed and every cached bRead, then refuses use", () => {
		const key = ReadKey.fromRoot(unhex(root.entropy));
		const seed = key.signer.seed;
		const bRead = key.branchRead("main");
		key.dispose();
		expect(seed.every((byte) => byte === 0)).toBe(true);
		expect(bRead.every((byte) => byte === 0)).toBe(true);
		expect(() => key.signer).toThrow(/disposed/);
		expect(() => key.branchRead("main")).toThrow(/disposed/);
		expect(() => key.dispose()).not.toThrow();
	});
});
