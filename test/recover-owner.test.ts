import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deriveOrg, orgWords } from "../src/crypto/index.js";
import { phraseFromEntropy } from "../src/crypto/phrase.js";
import { resolveAuth } from "../src/auth-resolve.js";
import { loadRoot } from "../src/owner.js";
import { loadProfiles } from "../src/profiles.js";
import { restoreOwnerFromPhrase } from "../src/recover-owner.js";

const ROOT = new Uint8Array(32).fill(9);
const PHRASE = phraseFromEntropy(ROOT);

let tmp: string;
let configDir: string;
let ownerDir: string;

beforeEach(() => {
	tmp = fs.mkdtempSync(join(tmpdir(), "rine-recover-owner-"));
	configDir = join(tmp, "config");
	ownerDir = join(tmp, "owner");
	fs.mkdirSync(configDir, { recursive: true });
});

afterEach(() => {
	vi.unstubAllGlobals();
	fs.rmSync(tmp, { recursive: true, force: true });
});

describe("restoreOwnerFromPhrase", () => {
	it("test_restoreOwner_when_phrase_given_then_root_and_org_profile_are_written_with_no_request", () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);
		const org = deriveOrg(ROOT);

		const restored = restoreOwnerFromPhrase({ configDir, ownerDir }, "default", PHRASE);

		expect(restored).toEqual({ orgId: org.orgId, orgWords: orgWords(org.orgId) });
		expect(loadRoot(ownerDir)).toEqual(ROOT);
		expect(loadProfiles(ownerDir).default?.org_id).toBe(org.orgId);
		expect(resolveAuth({ configDir, ownerDir })?.orgId).toBe(org.orgId);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("test_restoreOwner_when_phrase_given_then_the_runtime_dir_is_left_untouched", () => {
		restoreOwnerFromPhrase({ configDir, ownerDir }, "default", PHRASE);
		expect(fs.readdirSync(configDir)).toEqual([]);
	});

	it("test_restoreOwner_when_the_owner_dir_already_holds_a_root_then_it_refuses", () => {
		restoreOwnerFromPhrase({ configDir, ownerDir }, "default", PHRASE);
		expect(() => restoreOwnerFromPhrase({ configDir, ownerDir }, "default", PHRASE)).toThrow(
			/already exists/,
		);
	});

	it("test_restoreOwner_when_the_phrase_is_invalid_then_nothing_is_written_and_it_is_not_echoed", () => {
		const bad = "abandon ability able";
		let message = "";
		try {
			restoreOwnerFromPhrase({ configDir, ownerDir }, "default", bad);
		} catch (err) {
			message = (err as Error).message;
		}
		expect(message).not.toBe("");
		expect(message).not.toContain(bad);
		expect(fs.existsSync(join(ownerDir, "root.key"))).toBe(false);
	});
});
