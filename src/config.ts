import * as fs from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { CredentialEntry, Credentials, TokenCache } from "./types.js";

export const DEFAULT_API_URL = "https://rine.network";

/** Resolve config directory. Priority: RINE_CONFIG_DIR env > cwd/.rine > ~/.config/rine */
export function resolveConfigDir(): string {
	if (process.env.RINE_CONFIG_DIR) return process.env.RINE_CONFIG_DIR;
	const local = join(process.cwd(), ".rine");
	if (fs.existsSync(local)) return local;
	return join(homedir(), ".config", "rine");
}

/** Resolve API URL from environment or default. */
export function resolveApiUrl(): string {
	return (process.env.RINE_API_URL ?? DEFAULT_API_URL).replace(/\/$/, "");
}

function ensureDir(dir: string): void {
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

function writeAtomic(path: string, content: string): void {
	const tmpPath = `${path}.tmp`;
	fs.writeFileSync(tmpPath, content, "utf-8");
	fs.renameSync(tmpPath, path);
	fs.chmodSync(path, 0o600);
}

export function loadCredentials(configDir: string): Credentials {
	const path = join(configDir, "credentials.json");
	try {
		const raw = fs.readFileSync(path, "utf-8");
		return JSON.parse(raw) as Credentials;
	} catch {
		return {};
	}
}

export function saveCredentials(configDir: string, creds: Credentials): void {
	ensureDir(configDir);
	writeAtomic(join(configDir, "credentials.json"), JSON.stringify(creds, null, 2));
}

export function loadTokenCache(configDir: string): TokenCache {
	const path = join(configDir, "token_cache.json");
	try {
		const raw = fs.readFileSync(path, "utf-8");
		return JSON.parse(raw) as TokenCache;
	} catch {
		return {};
	}
}

export function saveTokenCache(configDir: string, cache: TokenCache): void {
	ensureDir(configDir);
	writeAtomic(join(configDir, "token_cache.json"), JSON.stringify(cache, null, 2));
}

export function cacheToken(
	configDir: string,
	profile: string,
	token: { access_token: string; expires_in: number },
): void {
	const cache = loadTokenCache(configDir);
	cache[profile] = {
		access_token: token.access_token,
		expires_at: Date.now() / 1000 + token.expires_in,
	};
	saveTokenCache(configDir, cache);
}

/**
 * Resolves credentials for a profile. Priority:
 * 1. RINE_CLIENT_ID + RINE_CLIENT_SECRET env vars (both required)
 * 2. credentials.json for the given profile
 */
export function getCredentialEntry(
	configDir: string,
	profile = "default",
): CredentialEntry | undefined {
	const envId = process.env.RINE_CLIENT_ID;
	const envSecret = process.env.RINE_CLIENT_SECRET;
	if (envId && envSecret) {
		return { client_id: envId, client_secret: envSecret };
	}
	const creds = loadCredentials(configDir);
	return creds[profile];
}
