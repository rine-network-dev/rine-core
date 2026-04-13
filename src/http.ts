import { cacheToken, loadTokenCache } from "./config.js";
import { RineApiError } from "./errors.js";
import type { ApiError, CredentialEntry } from "./types.js";

export type TokenFn = (force?: boolean) => Promise<string>;

export interface HttpClientOptions {
	tokenFn: TokenFn;
	apiUrl: string;
	/** Whether 401 auto-retry is possible (requires client credentials). */
	canRefresh?: boolean;
	/** Headers injected on every request (e.g. X-Rine-Agent). */
	defaultHeaders?: Record<string, string>;
	/**
	 * Default abort signal applied to every request made by this instance.
	 * Use one short-lived HttpClient per cancellation scope — e.g. one per
	 * SDK crypto operation. A fired signal propagates to fetch() as-is; the
	 * resulting AbortError is NOT wrapped in RineApiError.
	 */
	signal?: AbortSignal;
}

async function parseErrorDetail(res: Response): Promise<string> {
	try {
		const body = (await res.json()) as ApiError;
		if (typeof body.detail === "string") return body.detail;
		if (Array.isArray(body.detail)) {
			return body.detail.map((e) => e.msg).join("; ");
		}
	} catch {
		// ignore parse failures
	}
	return res.statusText;
}

export class HttpClient {
	private readonly baseUrl: string;
	private readonly tokenFn: TokenFn;
	private readonly canRefresh: boolean;
	private readonly defaultHeaders: Record<string, string>;
	private readonly defaultSignal: AbortSignal | undefined;

	constructor(opts: HttpClientOptions) {
		this.baseUrl = opts.apiUrl;
		this.tokenFn = opts.tokenFn;
		this.canRefresh = opts.canRefresh ?? true;
		this.defaultHeaders = opts.defaultHeaders ?? {};
		this.defaultSignal = opts.signal;
	}

	private async request(
		method: string,
		path: string,
		body?: unknown,
		params?: Record<string, string | number | boolean>,
		extraHeaders?: Record<string, string>,
	): Promise<unknown> {
		let url = this.baseUrl + path;
		if (params) {
			const qs = new URLSearchParams(
				Object.entries(params)
					.filter(([, v]) => v !== undefined && v !== null)
					.map(([k, v]) => [k, String(v)]),
			).toString();
			if (qs) url += `?${qs}`;
		}

		const doFetch = async (force?: boolean): Promise<Response> => {
			const token = await this.tokenFn(force);
			const headers: Record<string, string> = {
				Authorization: `Bearer ${token}`,
				...this.defaultHeaders,
				...extraHeaders,
			};
			if (body !== undefined) {
				headers["Content-Type"] = "application/json";
			}
			const init: RequestInit = { method, headers, signal: this.defaultSignal };
			if (body !== undefined) {
				init.body = JSON.stringify(body);
			}
			return fetch(url, init);
		};

		let res = await doFetch();
		if (res.status === 401 && this.canRefresh) {
			res = await doFetch(true);
		}
		if (!res.ok) {
			const detail = await parseErrorDetail(res);
			throw new RineApiError(res.status, detail, res);
		}
		if (res.status === 204) return undefined;
		return res.json();
	}

	get(
		path: string,
		params?: Record<string, string | number | boolean>,
		extraHeaders?: Record<string, string>,
	): Promise<unknown> {
		return this.request("GET", path, undefined, params, extraHeaders);
	}

	post(
		path: string,
		body?: unknown,
		extraHeaders?: Record<string, string>,
	): Promise<unknown> {
		return this.request("POST", path, body, undefined, extraHeaders);
	}

	put(
		path: string,
		body?: unknown,
		extraHeaders?: Record<string, string>,
	): Promise<unknown> {
		return this.request("PUT", path, body, undefined, extraHeaders);
	}

	patch(
		path: string,
		body?: unknown,
		extraHeaders?: Record<string, string>,
	): Promise<unknown> {
		return this.request("PATCH", path, body, undefined, extraHeaders);
	}

	delete(
		path: string,
		extraHeaders?: Record<string, string>,
	): Promise<unknown> {
		return this.request("DELETE", path, undefined, undefined, extraHeaders);
	}

	/** Unauthenticated GET for public endpoints (e.g. /directory/*). */
	static async publicGet(
		apiUrl: string,
		path: string,
		params?: URLSearchParams,
	): Promise<unknown> {
		const qs = params?.toString();
		const url = qs ? `${apiUrl}${path}?${qs}` : `${apiUrl}${path}`;
		const res = await fetch(url, { headers: { Accept: "application/json" } });
		if (!res.ok) {
			const detail = await parseErrorDetail(res);
			throw new RineApiError(res.status, detail, res);
		}
		return res.json();
	}
}

/**
 * Fetches an OAuth token from POST /oauth/token.
 */
export async function fetchOAuthToken(
	apiUrl: string,
	clientId: string,
	clientSecret: string,
): Promise<{ access_token: string; expires_in: number }> {
	const res = await fetch(`${apiUrl}/oauth/token`, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "client_credentials",
			client_id: clientId,
			client_secret: clientSecret,
		}).toString(),
	});
	if (!res.ok) {
		const body = (await res.json().catch(() => ({}))) as {
			detail?: string;
		};
		throw new RineApiError(res.status, body.detail ?? "Token request failed");
	}
	return res.json() as Promise<{ access_token: string; expires_in: number }>;
}

/**
 * Resolves a valid access token. Priority:
 * 1. opts.envToken — used directly, no cache/refresh
 * 2. Token cache — returned if not expired (60s margin)
 * 3. POST /oauth/token — fetches fresh token and caches it
 */
export async function getOrRefreshToken(
	configDir: string,
	apiUrl: string,
	entry: CredentialEntry | undefined,
	profileName: string,
	opts?: { force?: boolean; envToken?: string },
): Promise<string> {
	if (opts?.envToken) return opts.envToken;

	const now = Date.now() / 1000;
	if (!opts?.force) {
		const cache = loadTokenCache(configDir);
		const cached = cache[profileName];
		if (cached !== undefined && cached.expires_at - now > 60) {
			return cached.access_token;
		}
	}

	if (!entry) {
		throw new RineApiError(0, "No credentials found. Run login first.");
	}

	const data = await fetchOAuthToken(apiUrl, entry.client_id, entry.client_secret);
	cacheToken(configDir, profileName, data);
	return data.access_token;
}
