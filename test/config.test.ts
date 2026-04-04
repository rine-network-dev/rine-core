import * as fs from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	DEFAULT_API_URL,
	cacheToken,
	getCredentialEntry,
	loadCredentials,
	loadTokenCache,
	resolveApiUrl,
	resolveConfigDir,
	saveCredentials,
	saveTokenCache,
} from "../src/config.js";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-config-test-"));
}

describe("resolveConfigDir", () => {
	const origEnv = { ...process.env };

	afterEach(() => {
		process.env = { ...origEnv };
	});

	it("uses RINE_CONFIG_DIR env when set", () => {
		process.env.RINE_CONFIG_DIR = "/custom/dir";
		expect(resolveConfigDir()).toBe("/custom/dir");
	});

	it("uses cwd/.rine when it exists", () => {
		delete process.env.RINE_CONFIG_DIR;
		const tmp = makeTmpDir();
		const local = join(tmp, ".rine");
		fs.mkdirSync(local);
		const origCwd = process.cwd;
		process.cwd = () => tmp;
		try {
			expect(resolveConfigDir()).toBe(local);
		} finally {
			process.cwd = origCwd;
			fs.rmSync(tmp, { recursive: true });
		}
	});

	it("falls back to ~/.config/rine", () => {
		delete process.env.RINE_CONFIG_DIR;
		const tmp = makeTmpDir();
		const origCwd = process.cwd;
		process.cwd = () => tmp;
		try {
			const result = resolveConfigDir();
			expect(result).toMatch(/\.config\/rine$/);
		} finally {
			process.cwd = origCwd;
			fs.rmSync(tmp, { recursive: true });
		}
	});
});

describe("resolveApiUrl", () => {
	const origEnv = { ...process.env };

	afterEach(() => {
		process.env = { ...origEnv };
	});

	it("returns default when env not set", () => {
		delete process.env.RINE_API_URL;
		expect(resolveApiUrl()).toBe(DEFAULT_API_URL);
	});

	it("uses RINE_API_URL env", () => {
		process.env.RINE_API_URL = "https://custom.api";
		expect(resolveApiUrl()).toBe("https://custom.api");
	});

	it("strips trailing slash", () => {
		process.env.RINE_API_URL = "https://custom.api/";
		expect(resolveApiUrl()).toBe("https://custom.api");
	});
});

describe("credentials round-trip", () => {
	let dir: string;

	beforeEach(() => { dir = makeTmpDir(); });
	afterEach(() => { fs.rmSync(dir, { recursive: true }); });

	it("returns empty object for missing file", () => {
		expect(loadCredentials(dir)).toEqual({});
	});

	it("saves and loads credentials", () => {
		const creds = {
			default: { client_id: "id1", client_secret: "secret1" },
		};
		saveCredentials(dir, creds);
		expect(loadCredentials(dir)).toEqual(creds);
	});

	it("sets secure permissions on credentials file", () => {
		saveCredentials(dir, { default: { client_id: "a", client_secret: "b" } });
		const stat = fs.statSync(join(dir, "credentials.json"));
		expect(stat.mode & 0o777).toBe(0o600);
	});
});

describe("token cache round-trip", () => {
	let dir: string;

	beforeEach(() => { dir = makeTmpDir(); });
	afterEach(() => { fs.rmSync(dir, { recursive: true }); });

	it("returns empty object for missing file", () => {
		expect(loadTokenCache(dir)).toEqual({});
	});

	it("saves and loads token cache", () => {
		const cache = {
			default: { access_token: "tok", expires_at: 9999999999 },
		};
		saveTokenCache(dir, cache);
		expect(loadTokenCache(dir)).toEqual(cache);
	});
});

describe("cacheToken", () => {
	let dir: string;

	beforeEach(() => { dir = makeTmpDir(); });
	afterEach(() => { fs.rmSync(dir, { recursive: true }); });

	it("caches token with computed expiry", () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

		cacheToken(dir, "default", { access_token: "tok123", expires_in: 3600 });
		const cache = loadTokenCache(dir);
		expect(cache.default?.access_token).toBe("tok123");
		expect(cache.default?.expires_at).toBeCloseTo(
			new Date("2026-01-01T00:00:00Z").getTime() / 1000 + 3600,
			0,
		);

		vi.useRealTimers();
	});
});

describe("getCredentialEntry", () => {
	let dir: string;
	const origEnv = { ...process.env };

	beforeEach(() => { dir = makeTmpDir(); });
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
		process.env = { ...origEnv };
	});

	it("prefers env vars over file", () => {
		saveCredentials(dir, { default: { client_id: "file", client_secret: "file" } });
		process.env.RINE_CLIENT_ID = "env-id";
		process.env.RINE_CLIENT_SECRET = "env-secret";
		const entry = getCredentialEntry(dir);
		expect(entry?.client_id).toBe("env-id");
		expect(entry?.client_secret).toBe("env-secret");
	});

	it("falls back to credentials file", () => {
		delete process.env.RINE_CLIENT_ID;
		delete process.env.RINE_CLIENT_SECRET;
		saveCredentials(dir, { default: { client_id: "file-id", client_secret: "file-secret" } });
		const entry = getCredentialEntry(dir);
		expect(entry?.client_id).toBe("file-id");
	});

	it("returns undefined when nothing is configured", () => {
		delete process.env.RINE_CLIENT_ID;
		delete process.env.RINE_CLIENT_SECRET;
		expect(getCredentialEntry(dir)).toBeUndefined();
	});

	it("requires both env vars to use env path", () => {
		process.env.RINE_CLIENT_ID = "only-id";
		delete process.env.RINE_CLIENT_SECRET;
		expect(getCredentialEntry(dir)).toBeUndefined();
	});
});
