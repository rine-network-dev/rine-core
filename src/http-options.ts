import type { AgentKeysResponse } from "./api-types.js";
import type { TtlCache } from "./cache.js";
import type { KeyPins } from "./crypto/key-pins.js";

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
	 * Per-agent key cache (GET /agents/{id}/keys) read by the inbound-verify path.
	 * Every client builds its own, which is what a persistent client wants. Pass
	 * one to share a single cache across several clients instead — the SDK does
	 * that, because it spawns a short-lived core client per crypto operation and a
	 * per-instance cache would never see a second read.
	 */
	keyCache?: TtlCache<AgentKeysResponse>;
	/**
	 * The caller's own org and agent ids. They seed the key-chain pins:
	 * a response that places one of the caller's own agents under another org is refused.
	 */
	ownIdentity?: { orgId: string; agentIds: Iterable<string> };
	/**
	 * The key-chain pins to use instead of a fresh set. A caller that builds a
	 * client per operation passes one set to all of them: pins that reset with
	 * every client would let a server re-home a peer or serve a lower `key_gen`
	 * on any single operation.
	 */
	keyPins?: KeyPins;
	/** The `fetch` every request goes through (the global one, read at call time, when absent). */
	fetch?: typeof fetch;
}
