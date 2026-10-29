/**
 * Unknown-decimal assets must FAIL CLOSED. Assuming a default decimal count would
 * misprice a sub-6-decimal token relative to the signed EIP-3009 `value`, so a
 * non-registry asset is denied at pricing time; a registry asset still prices
 * correctly.
 */

import { describe, expect, it } from "vitest";
import {
	requirementCanonicalAmount,
	resolveDecimals,
	resolveTokenExtra,
} from "../../src/x402/assets.js";
import { X402_ERROR } from "../../src/x402/errors.js";
import type { PaymentRequirements } from "../../src/x402/types.js";

const USDC_SEPOLIA = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"; // registry, 6 dp
// Bare-address allow-listed token NOT in the registry — decimals unknown.
const UNKNOWN_ASSET = "0x1111111111111111111111111111111111111111";

function req(over: Partial<PaymentRequirements> = {}): PaymentRequirements {
	return {
		scheme: "exact",
		network: "eip155:84532",
		amount: "1000000",
		asset: USDC_SEPOLIA,
		payTo: "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF",
		maxTimeoutSeconds: 60,
		extra: { name: "USDC", version: "2" },
		...over,
	};
}

function expectCode(fn: () => unknown, code: string): void {
	try {
		fn();
		throw new Error("expected a typed X402Error");
	} catch (err) {
		expect((err as { code?: string }).code).toBe(code);
	}
}

describe("resolveTokenExtra", () => {
	it("test_base_mainnet_usdc_domain_is_the_onchain_name_and_version", () => {
		// Read from the contract on 2026-10-29: name() = "USD Coin", version() = "2".
		// A payment signed over any other domain does not recover on chain.
		expect(
			resolveTokenExtra(
				"eip155:8453",
				"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			),
		).toEqual({ name: "USD Coin", version: "2" });
	});

	it("test_base_sepolia_usdc_domain_is_the_live_proven_one", () => {
		expect(resolveTokenExtra("eip155:84532", USDC_SEPOLIA)).toEqual({
			name: "USDC",
			version: "2",
		});
	});

	it("test_unknown_asset_is_rejected_not_defaulted", () => {
		expectCode(
			() => resolveTokenExtra("eip155:84532", UNKNOWN_ASSET),
			X402_ERROR.UNKNOWN_ASSET_DECIMALS,
		);
	});
});

describe("resolveDecimals (fail closed)", () => {
	it("test_registry_asset_resolves_its_decimals", () => {
		expect(resolveDecimals("eip155:84532", USDC_SEPOLIA)).toBe(6);
	});

	it("test_unknown_asset_is_rejected_not_defaulted", () => {
		expectCode(
			() => resolveDecimals("eip155:84532", UNKNOWN_ASSET),
			X402_ERROR.UNKNOWN_ASSET_DECIMALS,
		);
	});

	it("test_registry_address_on_wrong_network_is_rejected", () => {
		expectCode(
			() => resolveDecimals("eip155:1", USDC_SEPOLIA),
			X402_ERROR.UNKNOWN_ASSET_DECIMALS,
		);
	});
});

describe("requirementCanonicalAmount", () => {
	it("test_registry_6_decimal_asset_prices_correctly", () => {
		expect(requirementCanonicalAmount(req({ amount: "1000000" }))).toBe(
			1_000_000n,
		);
	});

	it("test_non_registry_asset_is_rejected", () => {
		// Previously valued at 10000 canonical ($0.01) — a cap bypass. Now denied.
		expectCode(
			() =>
				requirementCanonicalAmount(
					req({ asset: UNKNOWN_ASSET, amount: "10000" }),
				),
			X402_ERROR.UNKNOWN_ASSET_DECIMALS,
		);
	});
});
