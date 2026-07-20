/**
 * x402 facilitator client (REQ-M04, payee side) — the SINGLE implementation.
 *
 * A facilitator is an EXTERNAL, third-party service (never rine) that verifies a
 * signed x402 `PaymentPayload` and settles it on-chain. rine is a pure metadata
 * relay: it carries the quote / signed authorization / receipt as E2EE messages
 * and NEVER touches settlement or custody. The payee (resource server) calls its
 * OWN facilitator's standard x402 V2 `/verify` + `/settle` HTTP endpoints.
 *
 * These calls are plain HTTP (global `fetch`) to the facilitator base URL — never
 * a rine endpoint and never rine auth (that would be the wrong host and wrong
 * credentials for a facilitator). Every surface (ts-sdk, CLI, MCP) delegates its
 * verify/settle to these functions so there is one facilitator client, not many.
 *
 * Presets provide sensible base URLs for the reference facilitators. EURC and
 * USDC on Base are both first-class assets.
 */

import type { PaymentPayload, SettlementResponse } from "./types.js";
import { X402_VERSION } from "./types.js";

/**
 * Configuration for a facilitator. `url` is the base; the standard x402 V2
 * `/verify` and `/settle` paths are appended (override per-facilitator if a
 * provider namespaces them differently). `headers` carries any provider auth
 * (e.g. a CDP API key pair the caller has minted into a bearer/JWT header).
 */
export interface FacilitatorConfig {
	/** Base URL, e.g. `https://facilitator.payai.network` (no trailing slash required). */
	url: string;
	/** Extra HTTP headers sent on every facilitator call (provider auth). */
	headers?: Record<string, string>;
	/** Verify path relative to `url`. Default `/verify`. */
	verifyPath?: string;
	/** Settle path relative to `url`. Default `/settle`. */
	settlePath?: string;
}

/**
 * Facilitator presets — convenience shortcuts; any facilitator implementing the
 * standard x402 `/verify` + `/settle` API works via an explicit `url`.
 * `cdp` is Coinbase's hosted facilitator, the default (requires the caller to
 * supply CDP API auth via `headers`). `payai` is a keyless hosted multi-chain
 * facilitator. `x402-rs` is the default base of a self-hosted `x402-rs`
 * instance — a first-class option, not a fallback. All expose the standard
 * `/verify` + `/settle` interface; pass a `{ ...preset, headers }` spread to
 * attach auth. Preset keys and base URLs are kept identical to the Python SDK's
 * `FACILITATOR_PRESETS`.
 */
export const FACILITATOR_PRESET = {
	cdp: { url: "https://api.cdp.coinbase.com/platform/v2/x402" },
	payai: { url: "https://facilitator.payai.network" },
	"x402-rs": { url: "http://localhost:8080" },
} as const satisfies Record<string, FacilitatorConfig>;

/** A facilitator `/verify` response (x402 V2). */
export interface VerifyResponse {
	isValid: boolean;
	invalidReason?: string | null;
	payer?: string;
	[k: string]: unknown;
}

/** Options accepted by every facilitator call. */
export interface FacilitatorCallOptions {
	facilitator: FacilitatorConfig;
	signal?: AbortSignal;
}

/** A facilitator HTTP call failed (non-2xx, or a transport/JSON error). */
export class X402FacilitatorError extends Error {
	constructor(
		message: string,
		public readonly status?: number,
		public readonly body?: unknown,
	) {
		super(message);
		this.name = "X402FacilitatorError";
	}
}

/**
 * The standard x402 V2 facilitator request body. `paymentRequirements` is the
 * single requirement the payer accepted (echoed verbatim from the signed
 * payload's `accepted` field — no rename/reshape, per the verbatim-object rule).
 */
export function facilitatorRequestBody(pp: PaymentPayload): {
	x402Version: number;
	paymentPayload: PaymentPayload;
	paymentRequirements: PaymentPayload["accepted"];
} {
	return {
		x402Version: pp.x402Version ?? X402_VERSION,
		paymentPayload: pp,
		paymentRequirements: pp.accepted,
	};
}

async function facilitatorPost<T>(
	cfg: FacilitatorConfig,
	path: string,
	body: unknown,
	signal?: AbortSignal,
): Promise<T> {
	const url = cfg.url.replace(/\/+$/, "") + path;
	let res: Response;
	try {
		res = await fetch(url, {
			method: "POST",
			headers: { "content-type": "application/json", ...cfg.headers },
			body: JSON.stringify(body),
			signal,
		});
	} catch (err) {
		if (err instanceof Error && err.name === "AbortError") throw err;
		throw new X402FacilitatorError(
			`facilitator request to ${url} failed: ${err instanceof Error ? err.message : String(err)}`,
		);
	}
	const text = await res.text();
	let parsed: unknown;
	try {
		parsed = text ? JSON.parse(text) : {};
	} catch {
		throw new X402FacilitatorError(
			`facilitator ${path} returned non-JSON (status ${res.status})`,
			res.status,
			text,
		);
	}
	if (!res.ok) {
		throw new X402FacilitatorError(
			`facilitator ${path} failed with status ${res.status}`,
			res.status,
			parsed,
		);
	}
	return parsed as T;
}

/** POST the signed payload to the facilitator's `/verify` endpoint. */
export function verifyPayment(
	pp: PaymentPayload,
	opts: FacilitatorCallOptions,
): Promise<VerifyResponse> {
	return facilitatorPost<VerifyResponse>(
		opts.facilitator,
		opts.facilitator.verifyPath ?? "/verify",
		facilitatorRequestBody(pp),
		opts.signal,
	);
}

/** POST the signed payload to the facilitator's `/settle` endpoint. */
export function settlePayment(
	pp: PaymentPayload,
	opts: FacilitatorCallOptions,
): Promise<SettlementResponse> {
	return facilitatorPost<SettlementResponse>(
		opts.facilitator,
		opts.facilitator.settlePath ?? "/settle",
		facilitatorRequestBody(pp),
		opts.signal,
	);
}
