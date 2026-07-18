import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { X402Error, X402_ERROR } from "../../src/x402/errors.js";
import {
	enforcePolicy,
	isAutoPayable,
	loadPolicy,
	savePolicy,
} from "../../src/x402/policy.js";
import type {
	PaymentPolicy,
	PaymentRequirements,
} from "../../src/x402/types.js";

const AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
// USDC on Base Sepolia — a KNOWN_ASSETS registry entry, 6 decimals.
const USDC_SEPOLIA = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";

function makeRequirement(
	over: Partial<PaymentRequirements> = {},
): PaymentRequirements {
	return {
		scheme: "exact",
		network: "eip155:84532",
		amount: "100000", // 0.1 USDC (6 decimals)
		asset: USDC_SEPOLIA,
		payTo: "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF",
		maxTimeoutSeconds: 60,
		extra: { name: "USDC", version: "2" },
		...over,
	};
}

const POLICY: PaymentPolicy = {
	perTxCap: "10.00",
	dailyCap: "20.00",
	allowedAssets: ["USDC"],
	allowedNetworks: ["eip155:84532"],
	autoPayThreshold: "1.00",
};

function expectCode(fn: () => void, code: string): void {
	try {
		fn();
		throw new Error("expected X402Error, none thrown");
	} catch (err) {
		expect(err).toBeInstanceOf(X402Error);
		expect((err as X402Error).code).toBe(code);
	}
}

describe("enforcePolicy", () => {
	it("passes_when_within_all_caps", () => {
		expect(() => enforcePolicy(POLICY, makeRequirement(), 0n)).not.toThrow();
	});

	it("denies_by_default_when_policy_is_null", () => {
		expectCode(
			() => enforcePolicy(null, makeRequirement(), 0n),
			X402_ERROR.NO_POLICY,
		);
	});

	it("refuses_when_scheme_unsupported", () => {
		expectCode(
			() => enforcePolicy(POLICY, makeRequirement({ scheme: "permit2" }), 0n),
			X402_ERROR.SCHEME_UNSUPPORTED,
		);
	});

	it("refuses_when_network_not_allowed", () => {
		expectCode(
			() =>
				enforcePolicy(POLICY, makeRequirement({ network: "eip155:8453" }), 0n),
			X402_ERROR.NETWORK_NOT_ALLOWED,
		);
	});

	it("refuses_when_asset_not_allowed", () => {
		expectCode(
			() =>
				enforcePolicy(
					{ ...POLICY, allowedAssets: ["EURC"] },
					makeRequirement(),
					0n,
				),
			X402_ERROR.ASSET_NOT_ALLOWED,
		);
	});

	it("allows_when_asset_matched_by_raw_address", () => {
		expect(() =>
			enforcePolicy(
				{ ...POLICY, allowedAssets: [USDC_SEPOLIA.toUpperCase()] },
				makeRequirement(),
				0n,
			),
		).not.toThrow();
	});

	it("refuses_when_per_tx_cap_exceeded", () => {
		// 11 USDC > 10.00 cap
		expectCode(
			() => enforcePolicy(POLICY, makeRequirement({ amount: "11000000" }), 0n),
			X402_ERROR.PER_TX_CAP_EXCEEDED,
		);
	});

	it("refuses_when_daily_cap_would_be_exceeded", () => {
		// already spent 19.5 canonical + 1.0 = 20.5 > 20.00
		expectCode(
			() =>
				enforcePolicy(
					POLICY,
					makeRequirement({ amount: "1000000" }),
					19_500_000n,
				),
			X402_ERROR.DAILY_CAP_EXCEEDED,
		);
	});

	it("passes_when_daily_spend_stays_within_cap", () => {
		expect(() =>
			enforcePolicy(
				POLICY,
				makeRequirement({ amount: "1000000" }),
				18_000_000n,
			),
		).not.toThrow();
	});
});

describe("isAutoPayable", () => {
	it("true_when_at_or_below_threshold", () => {
		expect(isAutoPayable(POLICY, makeRequirement({ amount: "500000" }))).toBe(
			true,
		);
	});
	it("false_when_above_threshold", () => {
		expect(isAutoPayable(POLICY, makeRequirement({ amount: "2000000" }))).toBe(
			false,
		);
	});
});

describe("policy persistence", () => {
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-policy-test-"));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
	});

	it("returns_null_when_no_policy_file", () => {
		expect(loadPolicy(dir, AGENT_ID)).toBeNull();
	});

	it("round_trips_when_saved_then_loaded", () => {
		savePolicy(dir, AGENT_ID, POLICY);
		expect(loadPolicy(dir, AGENT_ID)).toEqual(POLICY);
	});

	it("rejects_when_cap_is_not_numeric", () => {
		expectCode(
			() => savePolicy(dir, AGENT_ID, { ...POLICY, perTxCap: "lots" }),
			X402_ERROR.INVALID_AMOUNT,
		);
	});
});
