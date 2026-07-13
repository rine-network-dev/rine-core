import type { AgentKeysResponse } from "./api-types.js";
import type { TtlCache } from "./cache.js";
import { RineApiError } from "./errors.js";
import { sleep } from "./funnel/propagation.js";
import { MAX_RETRY_WAIT_MS, retryAfterMsFromResponse } from "./retry.js";
import type { ApiError } from "./types.js";

// The token helpers moved to token.ts to keep this file under the size cap; they
// stay reachable from "./http.js" for back-compat with existing import sites.
export { fetchOAuthToken, getOrRefreshToken } from "./token.js";

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
	/**
	 * Optional per-agent key cache (GET /agents/{id}/keys) shared by
	 * fetchRecipientKeys and verifyEnvelopeSender. Attach it to a PERSISTENT client
	 * (or, in the SDK, to a single instance threaded into every short-lived core
	 * client) so a multi-agent host stops re-fetching the same keys on every send
	 * and inbound-verify (D-5). Absent ⇒ no caching.
	 */
	keyCache?: TtlCache<AgentKeysResponse>;
}

/**
 * Parse an error response body ONCE, extracting both the human-readable detail
 * and the structured error code. The server sends {"error": "<code>", "detail":
 * "..."} for typed errors (e.g. epoch_conflict); callers use `code` to branch.
 */
async function parseError(
	res: Response,
): Promise<{ detail: string; code?: string }> {
	try {
		const body = (await res.json()) as ApiError;
		const code = typeof body.error === "string" ? body.error : undefined;
		if (typeof body.detail === "string") return { detail: body.detail, code };
		if (Array.isArray(body.detail)) {
			return { detail: body.detail.map((e) => e.msg).join("; "), code };
		}
		return { detail: res.statusText, code };
	} catch {
		// ignore parse failures
	}
	return { detail: res.statusText };
}

export class HttpClient {
	private readonly baseUrl: string;
	private readonly tokenFn: TokenFn;
	private readonly canRefresh: boolean;
	private readonly defaultHeaders: Record<string, string>;
	private readonly defaultSignal: AbortSignal | undefined;
	/** Shared per-agent key cache; see {@link HttpClientOptions.keyCache}. */
	readonly keyCache: TtlCache<AgentKeysResponse> | undefined;

	constructor(opts: HttpClientOptions) {
		this.baseUrl = opts.apiUrl;
		this.tokenFn = opts.tokenFn;
		this.canRefresh = opts.canRefresh ?? true;
		this.defaultHeaders = opts.defaultHeaders ?? {};
		this.defaultSignal = opts.signal;
		this.keyCache = opts.keyCache;
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
		// Single 429 retry honoring Retry-After (capped), mirroring the Python SDK's
		// normal-call behavior (REQ-TS-03, D-6). Read the header off `res` — never the
		// body — so the retried response is the one parseError consumes on failure.
		if (res.status === 429) {
			await sleep(Math.min(retryAfterMsFromResponse(res), MAX_RETRY_WAIT_MS));
			res = await doFetch();
		}
		if (!res.ok) {
			const { detail, code } = await parseError(res);
			throw new RineApiError(res.status, detail, res, code);
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

	async markDelivered(
		agentId: string,
		messageIds: string[],
		extraHeaders?: Record<string, string>,
	): Promise<{ marked: number }> {
		return this.post(
			`/agents/${agentId}/messages/mark-delivered`,
			{ message_ids: messageIds },
			extraHeaders,
		) as Promise<{ marked: number }>;
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
			const { detail, code } = await parseError(res);
			throw new RineApiError(res.status, detail, res, code);
		}
		return res.json();
	}
}
