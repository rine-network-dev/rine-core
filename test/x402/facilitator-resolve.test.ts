/**
 * Shared facilitator-spec resolution (#10 dedup) — the promoted core helpers CLI
 * and MCP now import instead of each hand-rolling a byte-identical resolver.
 * Tested through the public interface: preset keys, explicit URLs, header parsing.
 */

import { describe, expect, it } from "vitest";
import {
	parseFacilitatorHeaders,
	resolveFacilitatorConfig,
} from "../../src/x402/facilitator-resolve.js";

describe("resolveFacilitatorConfig", () => {
	it("test_resolves_a_preset_key_to_its_base_url", () => {
		expect(resolveFacilitatorConfig("payai").url).toBe(
			"https://facilitator.payai.network",
		);
	});

	it("test_accepts_an_explicit_http_url", () => {
		expect(resolveFacilitatorConfig("https://fac.example.com").url).toBe(
			"https://fac.example.com",
		);
	});

	it("test_merges_headers_and_path_overrides", () => {
		const cfg = resolveFacilitatorConfig("payai", {
			headers: { authorization: "Bearer x" },
			verifyPath: "/v/verify",
			settlePath: "/v/settle",
		});
		expect(cfg.headers).toEqual({ authorization: "Bearer x" });
		expect(cfg.verifyPath).toBe("/v/verify");
		expect(cfg.settlePath).toBe("/v/settle");
	});

	it("test_omits_empty_headers", () => {
		expect(resolveFacilitatorConfig("payai", { headers: {} }).headers).toBe(
			undefined,
		);
	});

	it("test_unknown_spec_throws", () => {
		expect(() => resolveFacilitatorConfig("not-a-facilitator")).toThrow(
			/Unknown facilitator/,
		);
	});
});

describe("parseFacilitatorHeaders", () => {
	it("test_parses_key_value_strings", () => {
		expect(
			parseFacilitatorHeaders(["Authorization: Bearer x", "X-Y: z"]),
		).toEqual({ Authorization: "Bearer x", "X-Y": "z" });
	});

	it("test_returns_undefined_for_none", () => {
		expect(parseFacilitatorHeaders(undefined)).toBe(undefined);
		expect(parseFacilitatorHeaders([])).toBe(undefined);
	});

	it("test_malformed_header_throws", () => {
		expect(() => parseFacilitatorHeaders(["no-colon"])).toThrow(/Malformed/);
	});

	it("test_only_the_first_colon_splits_the_value", () => {
		expect(parseFacilitatorHeaders(["Authorization: Bearer a:b:c"])).toEqual({
			Authorization: "Bearer a:b:c",
		});
	});
});
