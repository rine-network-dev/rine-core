import { bytesToHex } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";
import {
	domainSeparator,
	eip3009Digest,
	hashTransferWithAuthorization,
} from "../../src/x402/eip3009.js";
import type { Eip3009Authorization } from "../../src/x402/types.js";

const AUTH: Eip3009Authorization = {
	from: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
	to: "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF",
	value: "100000",
	validAfter: "1740672089",
	validBefore: "1740672154",
	nonce: `0x${"ab".repeat(32)}`,
};

describe("domainSeparator", () => {
	// Canonical EIP-712 spec "Ether Mail" vector — proves type-hash + ABI-word
	// encoding of string/address/uint256 is correct.
	it("matches_eip712_reference_when_domain_is_ether_mail", () => {
		const sep = domainSeparator({
			name: "Ether Mail",
			version: "1",
			chainId: 1,
			verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
		});
		expect(bytesToHex(sep)).toBe(
			"f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
		);
	});
});

describe("eip3009Digest", () => {
	const domain = {
		name: "USD Coin",
		version: "2",
		chainId: 8453,
		verifyingContract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
	};

	it("is_32_bytes_when_computed", () => {
		expect(eip3009Digest(domain, AUTH).length).toBe(32);
	});

	it("is_deterministic_when_inputs_unchanged", () => {
		expect(bytesToHex(eip3009Digest(domain, AUTH))).toBe(
			bytesToHex(eip3009Digest(domain, AUTH)),
		);
	});

	it("changes_when_value_changes", () => {
		const other = eip3009Digest(domain, { ...AUTH, value: "200000" });
		expect(bytesToHex(other)).not.toBe(bytesToHex(eip3009Digest(domain, AUTH)));
	});

	it("changes_when_chain_id_changes", () => {
		const a = eip3009Digest({ ...domain, chainId: 8453 }, AUTH);
		const b = eip3009Digest({ ...domain, chainId: 84532 }, AUTH);
		expect(bytesToHex(a)).not.toBe(bytesToHex(b));
	});
});

describe("hashTransferWithAuthorization", () => {
	it("throws_when_nonce_not_32_bytes", () => {
		expect(() =>
			hashTransferWithAuthorization({ ...AUTH, nonce: "0xdead" }),
		).toThrow(/bytes32/);
	});
});
