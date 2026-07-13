import { cacheToken, loadTokenCache } from "./config.js";
import { RineApiError } from "./errors.js";
import { sleep } from "./funnel/propagation.js";
import {
	MAX_RETRY_WAIT_MS,
	TOKEN_RETRY_MAX_ATTEMPTS,
	fullJitterBackoffMs,
	retryAfterMsFromResponse,
} from "./retry.js";
import type { CredentialEntry } from "./types.js";

/**
 * Fetches an OAuth token from POST /oauth/token.
 *
 * On a 429 the POST honors `Retry-After` (falling back to full-jitter exponential
 * backoff), retrying up to {@link TOKEN_RETRY_MAX_ATTEMPTS} times with a cumulative
 * wait capped at {@link MAX_RETRY_WAIT_MS} — so a co-located multi-agent host's
 * synchronized refresh no longer hard-fails on a transient limit, while a genuinely
 * down server still fails fast (rate-limit-resilience REQ-TS-01, D-3). Non-429
 * failures throw immediately, exactly as before. `rng` is injectable for tests.
 */
export async function fetchOAuthToken(
	apiUrl: string,
	clientId: string,
	clientSecret: string,
	opts: { rng?: () => number } = {},
): Promise<{ access_token: string; expires_in: number }> {
	const rng = opts.rng ?? Math.random;
	let spentMs = 0;
	for (let attempt = 1; ; attempt++) {
		const res = await fetch(`${apiUrl}/oauth/token`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "client_credentials",
				client_id: clientId,
				client_secret: clientSecret,
			}).toString(),
		});
		if (res.ok) {
			return res.json() as Promise<{
				access_token: string;
				expires_in: number;
			}>;
		}
		// Retry only on 429, only while attempts and the total-wait budget remain.
		// Read the header (never the body) on a retry so the body stays consumable
		// for the final throw.
		if (res.status === 429 && attempt < TOKEN_RETRY_MAX_ATTEMPTS) {
			const header = retryAfterMsFromResponse(res);
			const wait = header > 0 ? header : fullJitterBackoffMs(attempt, rng);
			if (spentMs + wait <= MAX_RETRY_WAIT_MS) {
				spentMs += wait;
				await sleep(wait);
				continue;
			}
		}
		const body = (await res.json().catch(() => ({}))) as { detail?: string };
		throw new RineApiError(
			res.status,
			body.detail ?? "Token request failed",
			res,
		);
	}
}

/**
 * Resolves a valid access token. Priority:
 * 1. opts.envToken — used directly, no cache/refresh
 * 2. Token cache — returned while more than `opts.refreshMargin` seconds remain
 *    (default 60; callers pass a per-instance jittered margin — see
 *    {@link jitteredRefreshMargin} — so co-located clients desynchronize, D-4)
 * 3. POST /oauth/token — fetches fresh token and caches it
 */
export async function getOrRefreshToken(
	configDir: string,
	apiUrl: string,
	entry: CredentialEntry | undefined,
	profileName: string,
	opts?: { force?: boolean; envToken?: string; refreshMargin?: number },
): Promise<string> {
	if (opts?.envToken) return opts.envToken;

	const now = Date.now() / 1000;
	if (!opts?.force) {
		const cache = loadTokenCache(configDir);
		const cached = cache[profileName];
		if (
			cached !== undefined &&
			cached.expires_at - now > (opts?.refreshMargin ?? 60)
		) {
			return cached.access_token;
		}
	}

	if (!entry) {
		throw new RineApiError(0, "No credentials found. Run login first.");
	}

	const data = await fetchOAuthToken(
		apiUrl,
		entry.client_id,
		entry.client_secret,
	);
	cacheToken(configDir, profileName, data);
	return data.access_token;
}
