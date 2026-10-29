/**
 * Regression tests for token-cache-write-failure resilience.
 *
 * These tests verify that getOrRefreshToken returns the freshly-fetched token
 * even when the token cache cannot be persisted (e.g. read-only / foreign-owned
 * token_cache.json on the user's laptop).
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getOrRefreshToken } from "../src/http.js";
import { TEST_SIGNER } from "./signer-fixture.js";

// Mock only loadTokenCache so the cache always appears empty (forces fresh fetch).
// cacheToken is kept real so we exercise the actual best-effort fix in config.ts.
vi.mock("../src/config.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../src/config.js")>();
	return {
		...actual,
		// Simulate: no valid cached token — getOrRefreshToken must call fetchOAuthToken
		loadTokenCache: vi.fn().mockReturnValue({}),
	};
});

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-token-cache-test-"));
}

describe("getOrRefreshToken — cache write failure resilience", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => {
		// Ensure dir is writable before cleanup (chmod in case a test left it read-only)
		try {
			fs.chmodSync(dir, 0o755);
		} catch {
			/* ignore */
		}
		fs.rmSync(dir, { recursive: true, force: true });
		vi.restoreAllMocks();
	});

	it("returns usable token even when token cache dir is read-only", async () => {
		// Simulate a successful POST /oauth/token
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				statusText: "OK",
				json: () =>
					Promise.resolve({ access_token: "fresh-tok", expires_in: 900 }),
			}),
		);

		// Make config dir read-only so saveTokenCache / writeAtomic will throw.
		// On environments where chmod is ineffective (e.g. running as root),
		// detect and fall back to a module-level mock of saveTokenCache instead.
		fs.chmodSync(dir, 0o444);
		const probe = join(dir, "probe.txt");
		let chmodEffective = false;
		try {
			fs.writeFileSync(probe, "x");
		} catch {
			chmodEffective = true;
		}

		if (!chmodEffective) {
			// chmod didn't block writes (running as root). Restore and mock saveTokenCache.
			fs.chmodSync(dir, 0o755);
			const { saveTokenCache } = await import("../src/config.js");
			vi.mocked(
				saveTokenCache as (...args: unknown[]) => void,
			).mockImplementation(() => {
				const err = Object.assign(new Error("EACCES: permission denied"), {
					code: "EACCES",
				});
				throw err;
			});
		}

		let result: string;
		try {
			result = await getOrRefreshToken(dir, "https://api.test", TEST_SIGNER);
		} finally {
			if (chmodEffective) fs.chmodSync(dir, 0o755);
		}

		// The token must be returned despite the cache write failing
		expect(result).toBe("fresh-tok");
	});
});
