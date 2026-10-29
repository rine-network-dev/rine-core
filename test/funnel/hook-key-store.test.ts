// saveHookSecret writes the hook's HMAC secret atomically: 0600 from creation,
// and a file planted at a predictable temp path is never followed or reused.

import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	hookSecretPath,
	loadHookSecret,
	saveHookSecret,
} from "../../src/funnel/hook-key-store.js";

const AGENT_ID = "11111111-2222-3333-4444-555555555555";
const SECRET = "ab".repeat(32);

describe("saveHookSecret", () => {
	let cfg: string;
	beforeEach(() => {
		cfg = fs.mkdtempSync(join(tmpdir(), "rine-hook-store-"));
	});
	afterEach(() => {
		fs.rmSync(cfg, { recursive: true, force: true });
	});

	it("never writes through a symlink planted at the predictable temp path", () => {
		const path = hookSecretPath(cfg, AGENT_ID, "github");
		fs.mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
		const victim = join(cfg, "victim.txt");
		fs.writeFileSync(victim, "untouched");
		fs.symlinkSync(victim, `${path}.tmp`);

		saveHookSecret(cfg, AGENT_ID, "github", SECRET);

		expect(fs.readFileSync(victim, "utf8")).toBe("untouched");
		expect(fs.lstatSync(path).isSymbolicLink()).toBe(false);
		expect(fs.statSync(path).mode & 0o777).toBe(0o600);
		expect(loadHookSecret(cfg, AGENT_ID, "github")).toBe(SECRET);
	});

	it("leaves no temp file of its own behind", () => {
		saveHookSecret(cfg, AGENT_ID, "github", SECRET);
		const dir = dirname(hookSecretPath(cfg, AGENT_ID, "github"));
		expect(fs.readdirSync(dir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
	});
});
