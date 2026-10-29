/**
 * The `fetch` the reader's `HttpClient` and token mint go through. Every request, an inner 401 or 429 retry
 * included, takes one token from the process's bucket; only GETs and the token mint pass; a
 * body over 8 MiB is refused; and a rejected `fetch` becomes a `ReaderNetworkError`.
 */
import { sleep } from "../timing.js";

/** One reader process's share of the principal's 120 requests per minute. */
export const READER_REQUESTS_PER_MINUTE = 20;
/** The largest response body the reader reads. */
export const MAX_BODY_BYTES = 8 * 1024 * 1024;

const MS_PER_MINUTE = 60_000;
const TOKEN_PATH = "/oauth/token";

/** The network failed, or answered with a body the reader will not read. Carries no row data. */
export class ReaderNetworkError extends Error {
	constructor(reason: string, options?: { cause?: unknown }) {
		super(reason, options);
		this.name = "ReaderNetworkError";
	}
}

export interface TokenBucketOptions {
	readonly perMinute?: number;
	/** Milliseconds, injectable for tests. */
	readonly now?: () => number;
	readonly sleep?: (ms: number) => Promise<void>;
}

/**
 * Refills continuously up to one minute's worth. A caller that finds it empty waits for the next token, so a
 * request is deferred and never dropped; the poller reads `msUntilToken` to defer a whole poll instead.
 */
export class TokenBucket {
	private readonly capacity: number;
	private readonly refillPerMs: number;
	private readonly now: () => number;
	private readonly wait: (ms: number) => Promise<void>;
	private tokens: number;
	private stamp: number;

	constructor(options: TokenBucketOptions = {}) {
		this.capacity = options.perMinute ?? READER_REQUESTS_PER_MINUTE;
		this.refillPerMs = this.capacity / MS_PER_MINUTE;
		this.now = options.now ?? Date.now;
		this.wait = options.sleep ?? sleep;
		this.tokens = this.capacity;
		this.stamp = this.now();
	}

	private refill(): void {
		const at = this.now();
		this.tokens = Math.min(
			this.capacity,
			this.tokens + Math.max(0, at - this.stamp) * this.refillPerMs,
		);
		this.stamp = at;
	}

	/** Milliseconds until a token is available: 0 when one is. */
	msUntilToken(): number {
		this.refill();
		return this.tokens >= 1
			? 0
			: Math.ceil((1 - this.tokens) / this.refillPerMs);
	}

	/** Take one token, waiting for it when the bucket is empty. */
	async take(): Promise<void> {
		for (let wait = this.msUntilToken(); wait > 0; wait = this.msUntilToken())
			await this.wait(wait);
		this.tokens -= 1;
	}
}

export interface BudgetedFetchOptions {
	/** The API origin: the one place a POST is allowed is its `/oauth/token`. */
	readonly apiUrl: string;
	readonly bucket: TokenBucket;
	/** The transport underneath, the global `fetch` when absent. */
	readonly fetch?: typeof fetch;
	readonly maxBodyBytes?: number;
}

function urlOf(input: Parameters<typeof fetch>[0]): string {
	if (typeof input === "string") return input;
	return input instanceof URL ? input.href : input.url;
}

function assertReadOnly(apiUrl: string, url: string, method: string): void {
	if (method === "GET") return;
	if (method === "POST" && url === `${apiUrl.replace(/\/+$/, "")}${TOKEN_PATH}`)
		return;
	throw new TypeError(`the reader sends only GET requests, not ${method}`);
}

/** The body as bytes, refused as soon as it passes the cap; the response is rebuilt around those bytes. */
async function capBody(res: Response, maxBytes: number): Promise<Response> {
	const declared = Number(res.headers.get("content-length"));
	if (Number.isFinite(declared) && declared > maxBytes) {
		await res.body?.cancel();
		throw new ReaderNetworkError("the response body is over the size limit");
	}
	const chunks: Uint8Array[] = [];
	let size = 0;
	const reader = res.body?.getReader();
	for (
		let part = await reader?.read();
		part !== undefined && !part.done;
		part = await reader?.read()
	) {
		size += part.value.byteLength;
		if (size > maxBytes) {
			await reader?.cancel();
			throw new ReaderNetworkError("the response body is over the size limit");
		}
		chunks.push(part.value);
	}
	const body = new Uint8Array(size);
	let at = 0;
	for (const chunk of chunks) {
		body.set(chunk, at);
		at += chunk.byteLength;
	}
	const { status, statusText, headers } = res;
	// A 204/205/304 may not carry a body; the rebuilt response must not either.
	return new Response([204, 205, 304].includes(status) ? null : body, {
		status,
		statusText,
		headers,
	});
}

export function createBudgetedFetch(
	options: BudgetedFetchOptions,
): typeof fetch {
	const maxBytes = options.maxBodyBytes ?? MAX_BODY_BYTES;
	return async (input, init) => {
		assertReadOnly(
			options.apiUrl,
			urlOf(input),
			(
				(input instanceof Request ? input.method : init?.method) ?? "GET"
			).toUpperCase(),
		);
		await options.bucket.take();
		try {
			return await capBody(
				await (options.fetch ?? fetch)(input, init),
				maxBytes,
			);
		} catch (err) {
			if (
				err instanceof ReaderNetworkError ||
				(err instanceof Error && err.name === "AbortError")
			)
				throw err;
			throw new ReaderNetworkError("the request failed", { cause: err });
		}
	};
}
