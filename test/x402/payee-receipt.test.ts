/**
 * Shared payee receipt-plane helpers (#10 dedup). `matchedQuoteToWire` is the ONE
 * snake_case projection CLI and MCP now import instead of each rebuilding the
 * `matched_quote` literal; tested here through the public interface. (`sendReceipt`
 * is the relocated, behaviour-identical CLI/MCP receipt reply — its message-plane
 * behaviour stays covered by the CLI/MCP fulfill suites that import it.)
 */

import { describe, expect, it } from "vitest";
import { matchedQuoteToWire } from "../../src/x402/payee-receipt.js";
import type { MatchedQuote } from "../../src/x402/payee-settle.js";

describe("matchedQuoteToWire", () => {
	it("test_projects_a_referenced_quote_to_snake_case", () => {
		const match: MatchedQuote = {
			quoteMessageId: "q-123",
			amount: "5000000",
			asset: "0xEURC",
			network: "eip155:8453",
		};
		expect(matchedQuoteToWire(match)).toEqual({
			message_id: "q-123",
			amount: "5000000",
			asset: "0xEURC",
			network: "eip155:8453",
		});
	});

	it("test_operator_override_surfaces_null_message_id", () => {
		const match: MatchedQuote = {
			quoteMessageId: null,
			amount: "1000000",
			asset: "0xUSDC",
			network: "eip155:84532",
		};
		expect(matchedQuoteToWire(match).message_id).toBe(null);
	});
});
