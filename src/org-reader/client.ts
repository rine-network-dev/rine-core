/**
 * The reader's HTTP client. Its only credential is the `reader:` principal's assertion, its token lives in
 * memory, and every request goes through the process's request budget. It is GET-only by type, so no write path is reachable.
 */
import type { AgentKeysResponse } from "../api-types.js";
import type { AssertionSigner } from "../assertion.js";
import type { TtlCache } from "../cache.js";
import { fetchAgentKeys } from "../crypto/agent-keys.js";
import { KeyChainError, type VerifiedAgentKeys } from "../crypto/key-chain.js";
import {
	HttpClient,
	type HttpClientOptions,
	fetchOAuthToken,
} from "../http.js";
import { jitteredRefreshMargin } from "../retry.js";
import { withDeadline } from "./deadline.js";
import { TokenBucket, createBudgetedFetch } from "./fetch-budget.js";
import {
	type ActivityPage,
	type EscrowRows,
	MalformedPageError,
	pageOf,
} from "./page-envelope.js";

const ESCROW_PAGE = 500;
/** Escrow pagination stops here, or on a repeated cursor. */
export const ESCROW_MAX_PAGES = 20;
export const ESCROW_MAX_ROWS = 10_000;
const ACTIVITY_PAGE_MAX = 100;

/** What `fetchAgentKeys` and the key pins need from the client, and nothing that can write. */
export type ReaderKeyClient = Pick<HttpClient, "get"> & {
	readonly keyCache: TtlCache<AgentKeysResponse>;
};

export interface ReaderClientOptions {
	readonly apiUrl: string;
	readonly signer: AssertionSigner;
	/** Shared by every client of one process, so they draw from one bucket. */
	readonly bucket?: TokenBucket;
	/** The transport underneath the budget, the global `fetch` when absent. */
	readonly fetch?: typeof fetch;
	/** Milliseconds, for the token's expiry. */
	readonly now?: () => number;
	/** Per-request deadline in milliseconds, `REQUEST_TIMEOUT_MS` when absent. */
	readonly requestTimeoutMs?: number;
	/** Refresh this long before the token's expiry; drawn once per client with the SDK's jitter when absent. */
	readonly refreshMarginMs?: number;
	readonly ownIdentity?: HttpClientOptions["ownIdentity"];
}

/** One `GET /org/activity?include=payload` request; every field is optional. */
export interface ActivityQuery {
	readonly cursor?: string | null;
	readonly limit?: number;
	/** An RFC 3339 instant: only rows created at or after it. */
	readonly since?: string;
	readonly agent?: string;
	readonly groupId?: string;
	readonly conversationId?: string;
	readonly direction?: string;
	/** Only rows of this message type. */
	readonly type?: string;
}

export class ReaderClient {
	/** The same object every key read goes through, so the key pins attach to it (`pinsFor`). */
	readonly client: ReaderKeyClient;
	private readonly budgetedFetch: typeof fetch;
	private readonly now: () => number;
	private readonly refreshMarginMs: number;
	private token: { value: string; expiresAt: number } | undefined;
	private minting: Promise<string> | undefined;

	constructor(private readonly options: ReaderClientOptions) {
		this.now = options.now ?? Date.now;
		this.refreshMarginMs =
			options.refreshMarginMs ?? jitteredRefreshMargin() * 1000;
		this.budgetedFetch = createBudgetedFetch({
			apiUrl: options.apiUrl,
			bucket: options.bucket ?? new TokenBucket(),
			fetch: withDeadline(options.fetch ?? fetch, options.requestTimeoutMs),
		});
		this.client = new HttpClient({
			apiUrl: options.apiUrl,
			tokenFn: (force) => this.accessToken(force),
			fetch: this.budgetedFetch,
			ownIdentity: options.ownIdentity,
		});
	}

	private accessToken(force = false): Promise<string> {
		if (
			!force &&
			this.token !== undefined &&
			this.now() < this.token.expiresAt
		) {
			return Promise.resolve(this.token.value);
		}
		// One mint at a time: the server accepts each assertion once, and concurrent requests would each sign one.
		this.minting ??= this.mint().finally(() => {
			this.minting = undefined;
		});
		return this.minting;
	}

	private async mint(): Promise<string> {
		const { access_token: value, expires_in: lifetimeS } =
			await fetchOAuthToken(this.options.apiUrl, this.options.signer, {
				fetch: this.budgetedFetch,
			});
		this.token = {
			value,
			expiresAt:
				this.now() + Math.max(lifetimeS * 1000 - this.refreshMarginMs, 0),
		};
		return value;
	}

	/** One page of the org feed with ciphertext (no delivery side effects). */
	async activity(query: ActivityQuery = {}): Promise<ActivityPage> {
		const params: Record<string, string | number> = {
			include: "payload",
			limit: Math.min(
				Math.max(Math.trunc(query.limit ?? ACTIVITY_PAGE_MAX), 1),
				ACTIVITY_PAGE_MAX,
			),
		};
		const filters = {
			since: query.since,
			agent: query.agent,
			group_id: query.groupId,
			conversation_id: query.conversationId,
			direction: query.direction,
			type: query.type,
			cursor: query.cursor,
		};
		for (const [name, value] of Object.entries(filters))
			if (value) params[name] = value;
		const { list, next } = pageOf(
			await this.client.get("/org/activity", params),
			"items",
		);
		if (list.length > ACTIVITY_PAGE_MAX) throw new MalformedPageError();
		return { items: list, nextCursor: next };
	}

	/** Every escrow row the principal may see for a group over an epoch range, within the page and row caps. */
	async escrowRows(
		groupId: string,
		fromEpoch: number,
		toEpoch: number,
	): Promise<EscrowRows> {
		const rows: unknown[] = [];
		const seen = new Set<string>();
		let cursor: string | null = null;
		for (let pages = 0; pages < ESCROW_MAX_PAGES; pages++) {
			const params: Record<string, string | number> = {
				group_id: groupId,
				from_epoch: fromEpoch,
				to_epoch: toEpoch,
				limit: ESCROW_PAGE,
			};
			if (cursor !== null) params.cursor = cursor;
			const { list, next } = pageOf(
				await this.client.get("/orgs/me/mls-escrow", params),
				"rows",
			);
			// A loop, not a spread (a huge page overflows the stack); one row past the cap shows an overflow.
			for (const row of list) {
				if (rows.length > ESCROW_MAX_ROWS) break;
				rows.push(row);
			}
			if (next === null && rows.length <= ESCROW_MAX_ROWS)
				return { rows, complete: true };
			if (rows.length >= ESCROW_MAX_ROWS)
				return { rows: rows.slice(0, ESCROW_MAX_ROWS), complete: false };
			if (next === null || seen.has(next)) return { rows, complete: false };
			seen.add(next);
			cursor = next;
		}
		return { rows, complete: false };
	}

	/** An agent's chain-verified published keys, latest or one past generation. */
	async agentKeys(agentId: string, gen?: number): Promise<VerifiedAgentKeys> {
		try {
			return (await fetchAgentKeys(this.client, agentId, { gen })).keys;
		} catch (err) {
			// A key object missing a field makes the chain check read through `undefined`; the transport's own
			// failures are `ReaderNetworkError`s by now, so a bare TypeError here is a malformed response.
			if (err instanceof TypeError) throw new KeyChainError("malformed");
			throw err;
		}
	}
}
