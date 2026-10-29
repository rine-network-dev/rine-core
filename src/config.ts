import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { UPGRADE_DETAIL } from "./crypto/upgrade-detail.js";
import { refusesHardLinks } from "./hard-links.js";
import type { TokenCache } from "./types.js";

export const DEFAULT_API_URL = "https://rine.network";

export const PROFILES_FILE = "profiles.json";
/** The retired sign-in file. Discovery refuses a dir that holds only this one. */
const LEGACY_SIGN_IN_FILE = "credentials.json";

function refuseRetiredSignIn(dir: string): void {
	if (
		!fs.existsSync(join(dir, PROFILES_FILE)) &&
		fs.existsSync(join(dir, LEGACY_SIGN_IN_FILE))
	) {
		throw new Error(UPGRADE_DETAIL);
	}
}

/**
 * Resolve the runtime config directory.
 * Priority: RINE_CONFIG_DIR > ~/.config/rine > cwd/.rine
 * Reading: first candidate with profiles.json wins. A candidate that holds the
 * retired sign-in file and no profiles.json stops discovery with the upgrade
 * text; it is never silently skipped.
 * Writing: first candidate where mkdir succeeds.
 */
export function resolveConfigDir(): string {
	if (process.env.RINE_CONFIG_DIR) {
		refuseRetiredSignIn(process.env.RINE_CONFIG_DIR);
		return process.env.RINE_CONFIG_DIR;
	}

	const candidates = [
		join(homedir(), ".config", "rine"),
		join(process.cwd(), ".rine"),
	];

	for (const dir of candidates) {
		refuseRetiredSignIn(dir);
		if (fs.existsSync(join(dir, PROFILES_FILE))) return dir;
	}

	// No profiles anywhere — return first candidate we can write to (onboarding case)
	for (const dir of candidates) {
		try {
			fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
			return dir;
		} catch {}
	}

	// Last resort: return preferred path, let downstream fail with a clear error
	return candidates[0] as string;
}

/** Resolve API URL from environment or default. */
export function resolveApiUrl(): string {
	return (process.env.RINE_API_URL ?? DEFAULT_API_URL).replace(/\/$/, "");
}

export function ensureDir(dir: string): void {
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

/** Create `path` with `content`, failing when it exists; a failed write leaves no file. */
function createExclusive(path: string, content: string | Uint8Array): void {
	const fd = fs.openSync(path, "wx", 0o600);
	try {
		fs.writeFileSync(fd, content);
		fs.fsyncSync(fd);
	} catch (error) {
		fs.closeSync(fd);
		fs.rmSync(path, { force: true });
		throw error;
	}
	fs.closeSync(fd);
}

/**
 * Write `content` to a fresh 0600 temp file beside `path` and return its name.
 * The name is random and opened exclusively, so a symlink planted at a
 * predictable temp path is never followed and a stale temp file is never
 * reused; 0600 is in force before any byte is written, so the content (e.g.
 * wallet.key) is never readable at the umask default. A failed write removes it.
 */
function writeTemp(path: string, content: string | Uint8Array): string {
	const tmpPath = `${path}.${randomBytes(8).toString("hex")}.tmp`;
	const fd = fs.openSync(tmpPath, "wx", 0o600);
	try {
		fs.writeFileSync(fd, content);
		// On disk before it is put in place, so a crash never leaves the target empty.
		fs.fsyncSync(fd);
	} catch (error) {
		fs.closeSync(fd);
		fs.rmSync(tmpPath, { force: true });
		throw error;
	}
	fs.closeSync(fd);
	return tmpPath;
}

/**
 * Atomically write a 0600 file (tmp + rename), replacing any file at `path`:
 * the crash-safe write of the agent key files, the profile/token stores, the
 * owner-dir root files and the x402 wallet policy + spend journal.
 */
export function writeAtomic(path: string, content: string | Uint8Array): void {
	const tmpPath = writeTemp(path, content);
	try {
		fs.renameSync(tmpPath, path);
	} catch (error) {
		fs.rmSync(tmpPath, { force: true });
		throw error;
	}
}

/**
 * Put the file at `source` at `path` unless `path` exists (then false): a hard
 * link, so an existing file is never replaced. A filesystem without hard links
 * (some network and FUSE mounts) gets an `O_EXCL` copy instead, exclusive but not
 * atomic: a reader can see it before the write lands, and a crash mid-write can
 * leave it short. Mirrors Python `rine._atomic_file.link_exclusive`.
 */
export function linkExclusive(source: string, path: string): boolean {
	try {
		fs.linkSync(source, path);
		return true;
	} catch (error) {
		if (!refusesHardLinks(error)) {
			if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
			throw error;
		}
	}
	try {
		createExclusive(path, fs.readFileSync(source));
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
		throw error;
	}
}

/**
 * Create a 0600 file holding `content` unless one exists (then false): a temp
 * file put in place by {@link linkExclusive}, and removed either way.
 */
export function createAtomicExclusive(
	path: string,
	content: string | Uint8Array,
): boolean {
	const tmpPath = writeTemp(path, content);
	try {
		return linkExclusive(tmpPath, path);
	} finally {
		fs.rmSync(tmpPath, { force: true });
	}
}

export function loadTokenCache(dir: string): TokenCache {
	const path = join(dir, "token_cache.json");
	try {
		const raw = fs.readFileSync(path, "utf-8");
		return JSON.parse(raw) as TokenCache;
	} catch {
		return {};
	}
}

export function saveTokenCache(dir: string, cache: TokenCache): void {
	ensureDir(dir);
	writeAtomic(join(dir, "token_cache.json"), JSON.stringify(cache, null, 2));
}

/** Cache `token` under `principal` (the principal string). */
export function cacheToken(
	dir: string,
	principal: string,
	token: { access_token: string; expires_in: number },
): void {
	const cache = loadTokenCache(dir);
	cache[principal] = {
		access_token: token.access_token,
		expires_at: Date.now() / 1000 + token.expires_in,
	};
	// Token cache is a disposable best-effort optimisation. A write failure (e.g.
	// read-only or foreign-owned token_cache.json) must NOT crash an otherwise-
	// successful auth flow — the caller already holds the fresh token in memory.
	// This is the token-storm-diagnosis fix: a cache write failure never crashes auth.
	try {
		saveTokenCache(dir, cache);
	} catch {
		// swallow — cache miss on next call is the only consequence
	}
}
