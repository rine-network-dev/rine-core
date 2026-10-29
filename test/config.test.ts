import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	DEFAULT_API_URL,
	cacheToken,
	createAtomicExclusive,
	loadTokenCache,
	resolveApiUrl,
	resolveConfigDir,
	saveTokenCache,
	writeAtomic,
} from "../src/config.js";
import { UPGRADE_DETAIL } from "../src/crypto/upgrade-detail.js";
import { resolveAuth } from "../src/auth-resolve.js";
import { TEST_AGENT_ID } from "./signer-fixture.js";

const TEST_PRINCIPAL = `agent:${TEST_AGENT_ID}`;

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-config-test-"));
}

/** Save/restore a single env var without replacing process.env (which breaks C-level getenv). */
function withEnv(key: string, value: string | undefined, fn: () => void): void {
	const prev = process.env[key];
	if (value === undefined) delete process.env[key];
	else process.env[key] = value;
	try {
		fn();
	} finally {
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

	it("prefers ~/.config/rine when both locations have profiles", () => {
		const tmpHome = makeTmpDir();
		const tmpCwd = makeTmpDir();
		const homeConfig = join(tmpHome, ".config", "rine");
		const cwdConfig = join(tmpCwd, ".rine");
		fs.mkdirSync(homeConfig, { recursive: true });
		fs.writeFileSync(join(homeConfig, "profiles.json"), "{}");
		fs.mkdirSync(cwdConfig, { recursive: true });
		fs.writeFileSync(join(cwdConfig, "profiles.json"), "{}");

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

	it("uses cwd/.rine when only it has profiles", () => {
		const tmpHome = makeTmpDir();
		const tmpCwd = makeTmpDir();
		const cwdConfig = join(tmpCwd, ".rine");
		fs.mkdirSync(cwdConfig, { recursive: true });
		fs.writeFileSync(join(cwdConfig, "profiles.json"), "{}");

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

	it("returns first writable candidate when no profiles exist", () => {
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

	it("throws UPGRADE_DETAIL when the chosen dir holds only the retired sign-in file", () => {
		const dir = makeTmpDir();
		try {
			fs.writeFileSync(join(dir, "credentials.json"), "{}");
			withEnv("RINE_CONFIG_DIR", dir, () => {
				expect(() => resolveConfigDir()).toThrow(UPGRADE_DETAIL);
			});
		} finally {
			fs.rmSync(dir, { recursive: true });
		}
	});

	it("does not throw when profiles.json is also present", () => {
		const dir = makeTmpDir();
		try {
			fs.writeFileSync(join(dir, "credentials.json"), "{}");
			fs.writeFileSync(join(dir, "profiles.json"), "{}");
			withEnv("RINE_CONFIG_DIR", dir, () => {
				expect(resolveConfigDir()).toBe(dir);
			});
		} finally {
			fs.rmSync(dir, { recursive: true });
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

describe("writeAtomic", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
	});

	it("writes the content and leaves no temp file behind", () => {
		const path = join(dir, "file.json");
		writeAtomic(path, '{"a":1}');
		expect(fs.readFileSync(path, "utf-8")).toBe('{"a":1}');
		expect(fs.readdirSync(dir)).toEqual(["file.json"]);
	});

	it("test_writeAtomic_when_a_symlink_sits_at_the_old_temp_name_then_it_is_not_written_through", () => {
		const path = join(dir, "file.json");
		const victim = join(dir, "victim");
		fs.writeFileSync(victim, "untouched");
		fs.symlinkSync(victim, `${path}.tmp`);
		writeAtomic(path, "secret");
		expect(fs.readFileSync(victim, "utf-8")).toBe("untouched");
		expect(fs.readFileSync(path, "utf-8")).toBe("secret");
	});

	it("test_writeAtomic_when_the_rename_fails_then_no_temp_file_is_left", () => {
		const path = join(dir, "occupied");
		fs.mkdirSync(path);
		fs.writeFileSync(join(path, "inside"), "x");

		expect(() => writeAtomic(path, "secret")).toThrow();

		expect(fs.readdirSync(dir)).toEqual(["occupied"]);
	});

	it("sets secure permissions on the written file", () => {
		const path = join(dir, "file.json");
		writeAtomic(path, "{}");
		expect(fs.statSync(path).mode & 0o777).toBe(0o600);
	});

	describe("on a filesystem without hard links", () => {
		beforeEach(() => {
			vi.spyOn(fs, "linkSync").mockImplementation(() => {
				throw Object.assign(new Error("operation not permitted"), { code: "EPERM" });
			});
		});
		afterEach(() => {
			vi.restoreAllMocks();
		});

		it("test_create_atomic_exclusive_when_the_link_is_refused_then_the_exclusive_file_is_created_in_place", () => {
			const path = join(dir, "marker.gap");

			expect(createAtomicExclusive(path, "refused")).toBe(true);

			expect(fs.readFileSync(path, "utf-8")).toBe("refused");
			expect(fs.statSync(path).mode & 0o777).toBe(0o600);
			expect(fs.readdirSync(dir)).toEqual(["marker.gap"]);
		});

		it("test_create_atomic_exclusive_when_the_link_is_refused_and_the_file_exists_then_the_first_content_is_kept", () => {
			const path = join(dir, "marker.gap");
			fs.writeFileSync(path, "first");

			expect(createAtomicExclusive(path, "second")).toBe(false);

			expect(fs.readFileSync(path, "utf-8")).toBe("first");
			expect(fs.readdirSync(dir)).toEqual(["marker.gap"]);
		});
	});
});

describe("token cache round-trip", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
	});

	it("returns empty object for missing file", () => {
		expect(loadTokenCache(dir)).toEqual({});
	});

	it("saves and loads token cache keyed by principal string", () => {
		const cache = {
			[TEST_PRINCIPAL]: { access_token: "tok", expires_at: 9999999999 },
		};
		saveTokenCache(dir, cache);
		expect(loadTokenCache(dir)).toEqual(cache);
	});
});

describe("cacheToken", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
	});

	it("caches token with computed expiry", () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
		try {
			cacheToken(dir, TEST_PRINCIPAL, {
				access_token: "tok123",
				expires_in: 3600,
			});
			const cache = loadTokenCache(dir);
			expect(cache[TEST_PRINCIPAL]?.access_token).toBe("tok123");
			expect(cache[TEST_PRINCIPAL]?.expires_at).toBeCloseTo(
				new Date("2026-01-01T00:00:00Z").getTime() / 1000 + 3600,
				0,
			);
		} finally {
			vi.useRealTimers();
		}
	});

	it("does not throw when config dir is read-only (0o444)", () => {
		// Verify the chmod actually blocks writes on this machine; if running as root
		// the restriction won't apply, so we fall back to a targeted spy.
		fs.chmodSync(dir, 0o444);
		const probe = `${dir}/probe.txt`;
		let chmodEffective = false;
		try {
			fs.writeFileSync(probe, "x");
		} catch {
			chmodEffective = true;
		}
		fs.chmodSync(dir, 0o755); // restore so cleanup works

		if (chmodEffective) {
			// Real read-only dir: re-apply the restriction, test, then restore
			fs.chmodSync(dir, 0o444);
			try {
				expect(() =>
					cacheToken(dir, TEST_PRINCIPAL, {
						access_token: "tok",
						expires_in: 900,
					}),
				).not.toThrow();
			} finally {
				fs.chmodSync(dir, 0o755);
			}
		} else {
			// chmod ineffective (e.g. running as root) — simulate via spy
			const writeStub = vi
				.spyOn(fs, "writeFileSync")
				.mockImplementation((path, _data, _opts) => {
					if (String(path).includes("token_cache")) {
						const err = Object.assign(new Error("EACCES: permission denied"), {
							code: "EACCES",
						});
						throw err;
					}
				});
			try {
				expect(() =>
					cacheToken(dir, TEST_PRINCIPAL, {
						access_token: "tok",
						expires_in: 900,
					}),
				).not.toThrow();
			} finally {
				writeStub.mockRestore();
			}
		}
	});
});

describe("retired client-secret env vars", () => {
	let configDir: string;
	let ownerDir: string;

	beforeEach(() => {
		configDir = makeTmpDir();
		ownerDir = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(configDir, { recursive: true });
		fs.rmSync(ownerDir, { recursive: true });
	});

	it("RINE_CLIENT_ID/RINE_CLIENT_SECRET change nothing for a profile-less dir", () => {
		withEnv("RINE_CLIENT_ID", "env-id", () => {
			withEnv("RINE_CLIENT_SECRET", "env-secret", () => {
				withEnv("RINE_CONFIG_DIR", configDir, () => {
					expect(resolveConfigDir()).toBe(configDir);
				});
				expect(resolveAuth({ configDir, ownerDir })).toBeUndefined();
			});
		});
	});
});
