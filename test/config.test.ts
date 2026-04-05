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

/** Save/restore a single env var without replacing process.env (which breaks C-level getenv). */
function withEnv(key: string, value: string | undefined, fn: () => void): void {
	const prev = process.env[key];
	if (value === undefined) delete process.env[key];
	else process.env[key] = value;
	try { fn(); } finally {
		if (prev === undefined) delete process.env[key];
		else process.env[key] = prev;
	}
}

describe("resolveConfigDir", () => {
	it("uses RINE_CONFIG_DIR env when set", () => {
		withEnv("RINE_CONFIG_DIR", "/custom/dir", () => {
			expect(resolveConfigDir()).toBe("/custom/dir");
		});
	});

	it("prefers ~/.config/rine when both locations have credentials", () => {
		const tmpHome = makeTmpDir();
		const tmpCwd = makeTmpDir();
		const homeConfig = join(tmpHome, ".config", "rine");
		const cwdConfig = join(tmpCwd, ".rine");
		fs.mkdirSync(homeConfig, { recursive: true });
		fs.writeFileSync(join(homeConfig, "credentials.json"), "{}");
		fs.mkdirSync(cwdConfig, { recursive: true });
		fs.writeFileSync(join(cwdConfig, "credentials.json"), "{}");

		const origCwd = process.cwd;
		process.cwd = () => tmpCwd;
		try {
			withEnv("RINE_CONFIG_DIR", undefined, () => {
				withEnv("HOME", tmpHome, () => {
					expect(resolveConfigDir()).toBe(homeConfig);
				});
			});
		} finally {
			process.cwd = origCwd;
			fs.rmSync(tmpHome, { recursive: true });
			fs.rmSync(tmpCwd, { recursive: true });
		}
	});

	it("uses cwd/.rine when only it has credentials", () => {
		const tmpHome = makeTmpDir();
		const tmpCwd = makeTmpDir();
		const cwdConfig = join(tmpCwd, ".rine");
		fs.mkdirSync(cwdConfig, { recursive: true });
		fs.writeFileSync(join(cwdConfig, "credentials.json"), "{}");

		const origCwd = process.cwd;
		process.cwd = () => tmpCwd;
		try {
			withEnv("RINE_CONFIG_DIR", undefined, () => {
				withEnv("HOME", tmpHome, () => {
					expect(resolveConfigDir()).toBe(cwdConfig);
				});
			});
		} finally {
			process.cwd = origCwd;
			fs.rmSync(tmpHome, { recursive: true });
			fs.rmSync(tmpCwd, { recursive: true });
		}
	});

	it("returns first writable candidate when no credentials exist", () => {
		const tmpHome = makeTmpDir();
		const tmpCwd = makeTmpDir();

		const origCwd = process.cwd;
		process.cwd = () => tmpCwd;
		try {
			withEnv("RINE_CONFIG_DIR", undefined, () => {
				withEnv("HOME", tmpHome, () => {
					const result = resolveConfigDir();
					expect(result).toBe(join(tmpHome, ".config", "rine"));
				});
			});
		} finally {
			process.cwd = origCwd;
			fs.rmSync(tmpHome, { recursive: true });
			fs.rmSync(tmpCwd, { recursive: true });
		}
	});

	it("falls back to cwd/.rine when home is unwritable", () => {
		const tmpCwd = makeTmpDir();
		const readonlyHome = makeTmpDir();
		fs.chmodSync(readonlyHome, 0o444);

		const origCwd = process.cwd;
		process.cwd = () => tmpCwd;
		try {
			withEnv("RINE_CONFIG_DIR", undefined, () => {
				withEnv("HOME", readonlyHome, () => {
					const result = resolveConfigDir();
					expect(result).toBe(join(tmpCwd, ".rine"));
				});
			});
		} finally {
			process.cwd = origCwd;
			fs.chmodSync(readonlyHome, 0o755);
			fs.rmSync(readonlyHome, { recursive: true });
			fs.rmSync(tmpCwd, { recursive: true });
		}
	});
});

describe("resolveApiUrl", () => {
	it("returns default when env not set", () => {
		withEnv("RINE_API_URL", undefined, () => {
			expect(resolveApiUrl()).toBe(DEFAULT_API_URL);
		});
	});

	it("uses RINE_API_URL env", () => {
		withEnv("RINE_API_URL", "https://custom.api", () => {
			expect(resolveApiUrl()).toBe("https://custom.api");
		});
	});

	it("strips trailing slash", () => {
		withEnv("RINE_API_URL", "https://custom.api/", () => {
			expect(resolveApiUrl()).toBe("https://custom.api");
		});
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
		try {
			cacheToken(dir, "default", { access_token: "tok123", expires_in: 3600 });
			const cache = loadTokenCache(dir);
			expect(cache.default?.access_token).toBe("tok123");
			expect(cache.default?.expires_at).toBeCloseTo(
				new Date("2026-01-01T00:00:00Z").getTime() / 1000 + 3600,
				0,
			);
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("getCredentialEntry", () => {
	let dir: string;

	beforeEach(() => { dir = makeTmpDir(); });
	afterEach(() => { fs.rmSync(dir, { recursive: true }); });

	it("prefers env vars over file", () => {
		saveCredentials(dir, { default: { client_id: "file", client_secret: "file" } });
		withEnv("RINE_CLIENT_ID", "env-id", () => {
			withEnv("RINE_CLIENT_SECRET", "env-secret", () => {
				const entry = getCredentialEntry(dir);
				expect(entry?.client_id).toBe("env-id");
				expect(entry?.client_secret).toBe("env-secret");
			});
		});
	});

	it("falls back to credentials file", () => {
		withEnv("RINE_CLIENT_ID", undefined, () => {
			withEnv("RINE_CLIENT_SECRET", undefined, () => {
				saveCredentials(dir, { default: { client_id: "file-id", client_secret: "file-secret" } });
				const entry = getCredentialEntry(dir);
				expect(entry?.client_id).toBe("file-id");
			});
		});
	});

	it("returns undefined when nothing is configured", () => {
		withEnv("RINE_CLIENT_ID", undefined, () => {
			withEnv("RINE_CLIENT_SECRET", undefined, () => {
				expect(getCredentialEntry(dir)).toBeUndefined();
			});
		});
	});

	it("requires both env vars to use env path", () => {
		withEnv("RINE_CLIENT_ID", "only-id", () => {
			withEnv("RINE_CLIENT_SECRET", undefined, () => {
				expect(getCredentialEntry(dir)).toBeUndefined();
			});
		});
	});
});
