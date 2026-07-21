/**
 * Shared facilitator-spec resolution (#10 dedup) — the ONE place a surface turns a
 * `--facilitator` spec (a preset key or an explicit `http(s)://` base URL) plus its
 * auth-header/path overrides into a {@link FacilitatorConfig}.
 *
 * CLI (`rine fulfill`) and MCP (`rine_fulfill`) previously each carried a byte-
 * identical resolver; both now import {@link resolveFacilitatorConfig}. Header
 * INPUT differs by surface — the CLI takes repeatable `"Key: Value"` strings, MCP
 * takes an already-parsed object — so the string parsing stays a caller concern via
 * {@link parseFacilitatorHeaders} (the CLI's `"Key: Value"` decoder), and the
 * resolver itself takes the parsed `headers` record.
 */

import { FACILITATOR_PRESET, type FacilitatorConfig } from "./facilitator.js";

/**
 * Parse repeatable `"Key: Value"` header strings (the CLI `--facilitator-header`
 * form) into a headers record, or `undefined` when none. Throws on a malformed
 * entry so a bad `--facilitator-header` fails loudly rather than silently dropping.
 */
export function parseFacilitatorHeaders(
	raw?: string[],
): Record<string, string> | undefined {
	if (!raw || raw.length === 0) return undefined;
	const headers: Record<string, string> = {};
	for (const entry of raw) {
		const idx = entry.indexOf(":");
		if (idx === -1) {
			throw new Error(
				`Malformed facilitator header '${entry}' (expected 'Key: Value').`,
			);
		}
		headers[entry.slice(0, idx).trim()] = entry.slice(idx + 1).trim();
	}
	return headers;
}

/**
 * Resolve a facilitator spec into a config. `spec` is either a preset key
 * (`cdp` / `payai` / `x402-rs`) or an explicit `http(s)://` base URL. Optional
 * pre-parsed auth headers and verify/settle path overrides are merged in. Throws on
 * an unrecognised spec so the caller fails loudly.
 */
export function resolveFacilitatorConfig(
	spec: string,
	opts: {
		headers?: Record<string, string>;
		verifyPath?: string;
		settlePath?: string;
	} = {},
): FacilitatorConfig {
	const preset = (FACILITATOR_PRESET as Record<string, FacilitatorConfig>)[
		spec
	];
	const base =
		preset ?? (/^https?:\/\//.test(spec) ? { url: spec } : undefined);
	if (!base) {
		throw new Error(
			`Unknown facilitator '${spec}'. Use a preset (${Object.keys(
				FACILITATOR_PRESET,
			).join(" | ")}) or an http(s):// base URL.`,
		);
	}
	const cfg: FacilitatorConfig = { url: base.url };
	if (opts.headers && Object.keys(opts.headers).length > 0)
		cfg.headers = opts.headers;
	if (opts.verifyPath) cfg.verifyPath = opts.verifyPath;
	if (opts.settlePath) cfg.settlePath = opts.settlePath;
	return cfg;
}
