/**
 * x402 facilitator client (payee side) — the SINGLE implementation.
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

import type {
	PaymentPayload,
	PaymentRequirements,
	SettlementResponse,
} from "./types.js";
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

/** Default facilitator request timeout (ms) — matches the Python SDK's 30s. */
export const FACILITATOR_TIMEOUT_MS = 30_000;

/**
 * The standard x402 payload fields a facilitator needs — nothing else is
 * forwarded. `extensions` is deliberately ABSENT: the quote-ref stamp
 * (`extensions[X402_QUOTE_REF_KEY]`) is rine-payee-internal — the payee reads
 * it from its OWN decrypted payment, never the facilitator round-trip — and
 * EIP-3009 signs only the `TransferWithAuthorization` struct, so stripping it
 * cannot invalidate the signature. Facilitators schema-validate `extensions`
 * (PayAI 403s any non-object value, which broke live settlement); sending none
 * is immune to their policies and stops leaking rine metadata to third parties.
 */
const FACILITATOR_PAYLOAD_KEYS = [
	"x402Version",
	"scheme",
	"network",
	"resource",
	"accepted",
	"payload",
] as const;

/**
 * The standard x402 V2 facilitator request body. `paymentRequirements` is the
 * PAYEE-OWNED requirement the caller reconciled the payment against — NEVER the
 * payer-authored `pp.accepted` block. Making `requirement` a mandatory parameter
 * keeps the payee-owned terms (payTo, amount, asset, network) the sole basis for
 * settlement, so a payer's echoed `accepted` never drives the facilitator.
 * Callers derive it from {@link reconcilePayment}. The forwarded payload is
 * whitelisted to {@link FACILITATOR_PAYLOAD_KEYS} — rine-internal `extensions`
 * and unknown keys never leave for a facilitator.
 */
export function facilitatorRequestBody(
	pp: PaymentPayload,
	requirement: PaymentRequirements,
): {
	x402Version: number;
	paymentPayload: PaymentPayload;
	paymentRequirements: PaymentRequirements;
} {
	const forwarded: Record<string, unknown> = {};
	for (const key of FACILITATOR_PAYLOAD_KEYS) {
		if (pp[key] !== undefined) forwarded[key] = pp[key];
	}
	forwarded.x402Version = pp.x402Version ?? X402_VERSION;
	return {
		x402Version: pp.x402Version ?? X402_VERSION,
		paymentPayload: forwarded as PaymentPayload,
		paymentRequirements: requirement,
	};
}

/**
 * Loopback hosts are exempt from the cleartext-credential ban (dev/testnet).
 * `new URL("http://[::1]").hostname` returns the BRACKETED literal `[::1]`, so the
 * brackets are stripped before comparing — otherwise an IPv6 loopback never matched
 * and TS refused `http://[::1]` while Python (`urlsplit().hostname` → `::1`) allowed
 * it. Stripping aligns the two SDKs on the same `{localhost, 127.0.0.1, ::1}` set.
 */
function isLoopbackHost(hostname: string): boolean {
	const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
	return h === "localhost" || h === "127.0.0.1" || h === "::1";
}

/**
 * Enforce a transport allowlist before any bytes leave: `https:`
 * is always fine; `http:` is allowed ONLY to loopback (`127.0.0.1`/`localhost`/
 * `::1`), credentials or not — a facilitator call carries payment terms and often
 * provider auth, and there is no legitimate reason to send it in cleartext to a
 * remote host. Any other scheme is rejected outright.
 */
function assertFacilitatorTransport(cfg: FacilitatorConfig): void {
	let parsed: URL;
	try {
		parsed = new URL(cfg.url);
	} catch {
		throw new X402FacilitatorError(`invalid facilitator URL: ${cfg.url}`);
	}
	if (parsed.protocol === "https:") return;
	if (parsed.protocol !== "http:") {
		throw new X402FacilitatorError(
			`unsupported facilitator URL scheme '${parsed.protocol}' (only https:, or http: to loopback)`,
		);
	}
	if (isLoopbackHost(parsed.hostname)) return;
	throw new X402FacilitatorError(
		`refusing cleartext http:// to non-loopback facilitator host ${parsed.host} — use https:// (loopback is exempt for dev/testnet)`,
	);
}

/**
 * A verify/settle path override must be a single-slash-rooted path — reject a
 * protocol-relative `//host`, an `@` userinfo host-reparent, or an embedded
 * scheme, any of which could redirect the credentialed POST off the base URL.
 */
function assertFacilitatorPath(path: string, label: string): void {
	if (!path.startsWith("/") || path.startsWith("//") || path.includes("@")) {
		throw new X402FacilitatorError(
			`invalid facilitator ${label} '${path}': must start with a single '/' (no '@', '//', or scheme)`,
		);
	}
}

/** Compose the caller's optional signal with a default 30s timeout. */
function withTimeout(signal?: AbortSignal): AbortSignal {
	const timeout = AbortSignal.timeout(FACILITATOR_TIMEOUT_MS);
	return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

async function facilitatorPost<T>(
	cfg: FacilitatorConfig,
	path: string,
	label: string,
	body: unknown,
	signal?: AbortSignal,
): Promise<T> {
	assertFacilitatorTransport(cfg);
	assertFacilitatorPath(path, label);
	const url = cfg.url.replace(/\/+$/, "") + path;
	let res: Response;
	try {
		res = await fetch(url, {
			method: "POST",
			headers: { "content-type": "application/json", ...cfg.headers },
			body: JSON.stringify(body),
			signal: withTimeout(signal),
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

/**
 * POST the signed payload to the facilitator's `/verify` endpoint. `requirement`
 * is the payee-owned terms (from {@link reconcilePayment}); it is what the
 * facilitator validates the authorization against — never `pp.accepted`.
 */
export function verifyPayment(
	pp: PaymentPayload,
	requirement: PaymentRequirements,
	opts: FacilitatorCallOptions,
): Promise<VerifyResponse> {
	return facilitatorPost<VerifyResponse>(
		opts.facilitator,
		opts.facilitator.verifyPath ?? "/verify",
		"verifyPath",
		facilitatorRequestBody(pp, requirement),
		opts.signal,
	);
}

/**
 * POST the signed payload to the facilitator's `/settle` endpoint. `requirement`
 * is the payee-owned terms (from {@link reconcilePayment}) — never `pp.accepted`.
 */
export function settlePayment(
	pp: PaymentPayload,
	requirement: PaymentRequirements,
	opts: FacilitatorCallOptions,
): Promise<SettlementResponse> {
	return facilitatorPost<SettlementResponse>(
		opts.facilitator,
		opts.facilitator.settlePath ?? "/settle",
		"settlePath",
		facilitatorRequestBody(pp, requirement),
		opts.signal,
	);
}
