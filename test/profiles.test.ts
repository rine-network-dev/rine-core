import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	addProfileIfAbsent,
	getProfile,
	loadProfiles,
	saveProfiles,
} from "../src/profiles.js";
import type { ProfileEntry } from "../src/types.js";

const ORG_ID = "22222222-2222-4222-8222-222222222222";
const AGENT_ID = "11111111-1111-4111-8111-111111111111";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-profiles-test-"));
}

function entry(overrides: Partial<ProfileEntry> = {}): ProfileEntry {
	return {
		org_id: ORG_ID,
		principal: `agent:${AGENT_ID}`,
		agent_id: AGENT_ID,
		...overrides,
	};
}

describe("profiles round-trip", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
	});

	it("returns empty object for missing file", () => {
		expect(loadProfiles(dir)).toEqual({});
	});

	it("returns empty object for a corrupt file", () => {
		fs.writeFileSync(join(dir, "profiles.json"), "{not json");
		expect(loadProfiles(dir)).toEqual({});
	});

	it("saves and loads profiles", () => {
		const profiles = { default: entry() };
		saveProfiles(dir, profiles);
		expect(loadProfiles(dir)).toEqual(profiles);
	});

	it("sets secure permissions on the profiles file and its dir", () => {
		saveProfiles(dir, { default: entry() });
		expect(fs.statSync(join(dir, "profiles.json")).mode & 0o777).toBe(0o600);
		expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
	});
});

describe("getProfile", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
	});

	it("defaults to the profile named default", () => {
		saveProfiles(dir, { default: entry() });
		expect(getProfile(dir)).toEqual(entry());
	});

	it("returns undefined for an unknown name", () => {
		saveProfiles(dir, { default: entry() });
		expect(getProfile(dir, "other")).toBeUndefined();
	});
});

describe("addProfileIfAbsent", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
	});

	it("returns true and writes when the name is free", () => {
		expect(addProfileIfAbsent(dir, "default", entry())).toBe(true);
		expect(loadProfiles(dir)).toEqual({ default: entry() });
	});

	it("returns false and leaves the file untouched when the name is taken", () => {
		saveProfiles(dir, { default: entry() });
		const before = fs.readFileSync(join(dir, "profiles.json"), "utf-8");
		expect(
			addProfileIfAbsent(dir, "default", entry({ org_id: "other" })),
		).toBe(false);
		expect(fs.readFileSync(join(dir, "profiles.json"), "utf-8")).toBe(before);
	});

	it.each([
		["truncated JSON", '{"default": {"org_id": '],
		["a JSON array", "[]"],
		["JSON null", "null"],
	])("refuses to overwrite a profiles file holding %s", (_label, corrupt) => {
		const file = join(dir, "profiles.json");
		fs.writeFileSync(file, corrupt);
		expect(() => addProfileIfAbsent(dir, "default", entry())).toThrow(file);
		expect(() => saveProfiles(dir, { default: entry() })).toThrow(file);
		expect(fs.readFileSync(file, "utf-8")).toBe(corrupt);
	});
});

describe("profiles on a filesystem without hard links", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		vi.spyOn(fs, "linkSync").mockImplementation(() => {
			throw Object.assign(new Error("operation not permitted"), {
				code: "EPERM",
			});
		});
	});
	afterEach(() => {
		vi.restoreAllMocks();
		fs.rmSync(dir, { recursive: true });
	});

	it("test_save_profiles_when_the_link_is_refused_then_the_profiles_are_written", () => {
		saveProfiles(dir, { default: entry() });

		expect(loadProfiles(dir)).toEqual({ default: entry() });
		expect(fs.readdirSync(dir)).toEqual(["profiles.json"]);
	});

	it("test_add_profile_if_absent_when_the_link_is_refused_then_it_adds_once", () => {
		expect(addProfileIfAbsent(dir, "default", entry())).toBe(true);
		expect(addProfileIfAbsent(dir, "default", entry({ agent_id: "x" }))).toBe(
			false,
		);

		expect(getProfile(dir)).toEqual(entry());
	});
});
