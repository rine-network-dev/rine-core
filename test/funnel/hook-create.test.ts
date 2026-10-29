// createHook owns the funnel hook allocation for every surface: the secret is
// generated and saved before the (non-idempotent) POST, and a failed POST puts
// the hook's secret file back the way it was.

import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHook } from "../../src/funnel/hook-create.js";
import {
	hookSecretPath,
	loadHookSecret,
	saveHookSecret,
} from "../../src/funnel/hook-key-store.js";

const AGENT_ID = "11111111-2222-3333-4444-555555555555";
const CREATED = {
	hook_name: "github",
	hostname: "github.a1b2c3d4e5.hook.rine.network",
	active: true,
	created_at: "2026-10-17T00:00:00Z",
	control_ws_url: "wss://rine.network/funnel/ws",
	termination: "zero_trust",
	agent_id: AGENT_ID,
};

describe("createHook", () => {
	let cfg: string;
	beforeEach(() => {
		cfg = fs.mkdtempSync(join(tmpdir(), "rine-hook-create-"));
	});
	afterEach(() => {
		fs.rmSync(cfg, { recursive: true, force: true });
	});

	it("saves a fresh secret before the POST and returns it with the server's hook", async () => {
		let storedDuringPost: string | undefined;
		const post = vi.fn(async () => {
			storedDuringPost = loadHookSecret(cfg, AGENT_ID, "github");
			return CREATED;
		});
		const result = await createHook(
			{ post },
			cfg,
			AGENT_ID,
			"github",
			"zero_trust",
		);
		expect(post).toHaveBeenCalledWith(`/agents/${AGENT_ID}/funnel/hooks`, {
			hook_name: "github",
			tier: "zero_trust",
		});
		expect(result.created).toEqual(CREATED);
		expect(result.secret).toMatch(/^[0-9a-f]{64}$/);
		expect(storedDuringPost).toBe(result.secret);
		expect(result.storedAt).toBe(hookSecretPath(cfg, AGENT_ID, "github"));
		expect(loadHookSecret(cfg, AGENT_ID, "github")).toBe(result.secret);
		expect(fs.statSync(result.storedAt).mode & 0o777).toBe(0o600);
	});

	it("sends tier null when no tier is chosen, so the server picks the default", async () => {
		const post = vi.fn(async () => CREATED);
		await createHook({ post }, cfg, AGENT_ID, "github");
		expect(post).toHaveBeenCalledWith(`/agents/${AGENT_ID}/funnel/hooks`, {
			hook_name: "github",
			tier: null,
		});
	});

	it("restores the prior secret when creating over an existing name fails", async () => {
		const prior = "a".repeat(64);
		saveHookSecret(cfg, AGENT_ID, "github", prior);
		const refusal = new Error("409 hook exists");
		const post = vi.fn(async () => {
			throw refusal;
		});
		await expect(
			createHook({ post }, cfg, AGENT_ID, "github"),
		).rejects.toBe(refusal);
		expect(loadHookSecret(cfg, AGENT_ID, "github")).toBe(prior);
	});

	it("leaves no secret behind when a first create fails", async () => {
		const post = vi.fn(async () => {
			throw new Error("network down");
		});
		await expect(
			createHook({ post }, cfg, AGENT_ID, "github"),
		).rejects.toThrow("network down");
		expect(fs.existsSync(hookSecretPath(cfg, AGENT_ID, "github"))).toBe(false);
	});

	it("rethrows the POST error when putting the secret file back fails too", async () => {
		const secretDir = dirname(hookSecretPath(cfg, AGENT_ID, "github"));
		const refusal = new Error("network down");
		const post = vi.fn(async () => {
			fs.chmodSync(secretDir, 0o500);
			throw refusal;
		});
		try {
			await expect(
				createHook({ post }, cfg, AGENT_ID, "github"),
			).rejects.toBe(refusal);
		} finally {
			fs.chmodSync(secretDir, 0o700);
		}
	});
});
