import { type AssertionSigner, buildAssertion } from "./assertion.js";
import { cacheToken, loadTokenCache } from "./config.js";
import { RineApiError, type RineErrorBody, revokedErrorFor } from "./errors.js";
import {
	MAX_RETRY_WAIT_MS,
	TOKEN_RETRY_MAX_ATTEMPTS,
	fullJitterBackoffMs,
	retryAfterMsFromResponse,
} from "./retry.js";
import { principalString } from "./principal.js";
import { sleep } from "./timing.js";

const CLIENT_ASSERTION_TYPE =
	"urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/**
 * Fetches an OAuth token from POST /oauth/token with a `private_key_jwt`
 * assertion signed by `signer`. Every attempt, including a 429
 * retry, signs a fresh assertion: the server accepts each `jti` once.
 *
 * On a 429 the POST honors `Retry-After` (falling back to full-jitter exponential
 * backoff), retrying up to {@link TOKEN_RETRY_MAX_ATTEMPTS} times with a cumulative
 * wait capped at {@link MAX_RETRY_WAIT_MS} — so a co-located multi-agent host's
 * synchronized refresh no longer hard-fails on a transient limit, while a genuinely
 * down server still fails fast. Non-429
 * failures throw immediately, exactly as before. `rng` is injectable for tests;
 * `fetch` replaces the global one (the org reader counts requests through it).
 */
export async function fetchOAuthToken(
	apiUrl: string,
	signer: AssertionSigner,
	opts: { rng?: () => number; fetch?: typeof fetch } = {},
): Promise<{ access_token: string; expires_in: number }> {
	const rng = opts.rng ?? Math.random;
	let spentMs = 0;
	for (let attempt = 1; ; attempt++) {
		const res = await (opts.fetch ?? fetch)(`${apiUrl}/oauth/token`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "client_credentials",
				client_assertion_type: CLIENT_ASSERTION_TYPE,
				client_assertion: buildAssertion(signer, apiUrl),
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
		const body = (await res.json().catch(() => ({}))) as RineErrorBody;
		// `detail` is a string on every route that reaches here; the body type
		// admits the validation array other routes send, which this throw has
		// always passed through verbatim.
		const detail = (body.detail ?? "Token request failed") as string;
		const code = typeof body.error === "string" ? body.error : undefined;
		throw (
			revokedErrorFor(res, detail, code, body) ??
			new RineApiError(res.status, detail, res, code, body)
		);
	}
}

/**
 * Resolves a valid access token. Priority:
 * 1. opts.envToken — used directly, no cache/refresh
 * 2. Token cache in `cacheDir`, keyed by principal string — returned while more
 *    than `opts.refreshMargin` seconds remain
 *    (default 60; callers pass a per-instance jittered margin — see
 *    {@link jitteredRefreshMargin} — so co-located clients desynchronize)
 * 3. POST /oauth/token — fetches fresh token and caches it
 */
export async function getOrRefreshToken(
	cacheDir: string,
	apiUrl: string,
	signer: AssertionSigner | undefined,
	opts?: { force?: boolean; envToken?: string; refreshMargin?: number },
): Promise<string> {
	if (opts?.envToken) return opts.envToken;

	const now = Date.now() / 1000;
	if (!opts?.force) {
		const cached = signer
			? loadTokenCache(cacheDir)[principalString(signer.principal)]
			: undefined;
		if (
			cached !== undefined &&
			cached.expires_at - now > (opts?.refreshMargin ?? 60)
		) {
			return cached.access_token;
		}
	}

	if (!signer) {
		throw new RineApiError(0, "No identity found. Run onboarding first.");
	}

	const data = await fetchOAuthToken(apiUrl, signer);
	cacheToken(cacheDir, principalString(signer.principal), data);
	return data.access_token;
}
