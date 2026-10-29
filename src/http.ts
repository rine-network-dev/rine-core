import type { AgentKeysResponse } from "./api-types.js";
import { TtlCache } from "./cache.js";
import { pinsFor, sharePins } from "./crypto/key-pins.js";
import { rineErrorFromResponse } from "./errors.js";
import type { HttpClientOptions, TokenFn } from "./http-options.js";
import { MAX_RETRY_WAIT_MS, retryAfterMsFromResponse } from "./retry.js";
import { sleep } from "./timing.js";

// The token helpers live in token.ts and are reachable from "./http.js" too.
export { fetchOAuthToken, getOrRefreshToken } from "./token.js";

export type { HttpClientOptions, TokenFn } from "./http-options.js";

/** Pin `client`'s own org and agent ids into its key-chain pins. */
export function seedOwnPins(
	client: object,
	own: NonNullable<HttpClientOptions["ownIdentity"]>,
): void {
	const pins = pinsFor(client);
	pins.ownOrgId = own.orgId;
	for (const id of own.agentIds) pins.ownAgentIds.add(id);
}

export class HttpClient {
	private readonly baseUrl: string;
	private readonly tokenFn: TokenFn;
	private readonly canRefresh: boolean;
	private readonly defaultHeaders: Record<string, string>;
	private readonly defaultSignal: AbortSignal | undefined;
	private readonly fetchFn: typeof fetch | undefined;
	/** Per-agent key cache; see {@link HttpClientOptions.keyCache}. */
	readonly keyCache: TtlCache<AgentKeysResponse>;

	constructor(opts: HttpClientOptions) {
		this.baseUrl = opts.apiUrl;
		this.tokenFn = opts.tokenFn;
		this.canRefresh = opts.canRefresh ?? true;
		this.defaultHeaders = opts.defaultHeaders ?? {};
		this.defaultSignal = opts.signal;
		this.fetchFn = opts.fetch;
		this.keyCache = opts.keyCache ?? new TtlCache();
		if (opts.keyPins) sharePins(this, opts.keyPins);
		if (opts.ownIdentity) seedOwnPins(this, opts.ownIdentity);
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
			return (this.fetchFn ?? fetch)(url, init);
		};

		let res = await doFetch();
		if (res.status === 401 && this.canRefresh) {
			res = await doFetch(true);
		}
		// Single 429 retry honoring Retry-After (capped), mirroring the Python SDK's
		// normal-call behavior. Read the header off `res` — never the
		// body — so the retried response is the one whose body becomes the error.
		//
		// A wait this client is not going to honour is not a wait worth taking:
		// the hour-window limiters (the public directory, group admission)
		// answer `Retry-After` in the thousands of seconds, so sleeping the
		// 30 s cap and retrying is a guaranteed second 429 — the operator just
		// waits half a minute for it. Report the first one instead.
		if (res.status === 429) {
			const waitMs = retryAfterMsFromResponse(res);
			if (waitMs <= MAX_RETRY_WAIT_MS) {
				await sleep(waitMs);
				res = await doFetch();
			}
		}
		if (!res.ok) throw await rineErrorFromResponse(res);
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

	/**
	 * `params` exists so a DELETE that carries a query parameter can still be
	 * written as one path literal. `mls_removal_epoch` is the caller
	 * (`deleteGroupMember`): spliced into the path string it becomes a literal no
	 * route matches, which is invisible to a reader and to the client⇄server
	 * contract test that extracts these paths.
	 */
	delete(
		path: string,
		extraHeaders?: Record<string, string>,
		params?: Record<string, string | number | boolean>,
	): Promise<unknown> {
		return this.request("DELETE", path, undefined, params, extraHeaders);
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
		if (!res.ok) throw await rineErrorFromResponse(res);
		return res.json();
	}
}
