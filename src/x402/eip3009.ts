import {
	concatBytes,
	hexToBytes,
	numberToBytesBE,
} from "@noble/curves/utils.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import type { Eip3009Authorization } from "./types.js";

/**
 * EIP-712 typed-data hashing for the EIP-3009 `transferWithAuthorization` used by
 * the x402 `exact` scheme. Verified against the canonical EIP-712 "Ether Mail"
 * domain-separator vector (see test/x402/eip3009.test.ts).
 */

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

const DOMAIN_TYPEHASH = keccak_256(
	utf8(
		"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
	),
);
const TRANSFER_TYPEHASH = keccak_256(
	utf8(
		"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
	),
);

export interface Eip712Domain {
	name: string;
	version: string;
	chainId: number;
	verifyingContract: string; // 0x address
}

/** Left-pad bytes into a 32-byte ABI word. */
function word(bytes: Uint8Array): Uint8Array {
	const out = new Uint8Array(32);
	out.set(bytes, 32 - bytes.length);
	return out;
}

function encodeAddress(addr: string): Uint8Array {
	const bytes = hexToBytes(addr.replace(/^0x/i, ""));
	if (bytes.length !== 20) {
		throw new Error(`Invalid address for EIP-712 encoding: ${addr}`);
	}
	return word(bytes);
}

function encodeUint256(value: string | number | bigint): Uint8Array {
	return numberToBytesBE(BigInt(value), 32);
}

function encodeBytes32(hex: string): Uint8Array {
	const bytes = hexToBytes(hex.replace(/^0x/i, ""));
	if (bytes.length !== 32) {
		throw new Error(`Invalid bytes32 for EIP-712 encoding: ${hex}`);
	}
	return bytes;
}

function hashString(s: string): Uint8Array {
	return keccak_256(utf8(s));
}

export function domainSeparator(domain: Eip712Domain): Uint8Array {
	return keccak_256(
		concatBytes(
			DOMAIN_TYPEHASH,
			hashString(domain.name),
			hashString(domain.version),
			encodeUint256(domain.chainId),
			encodeAddress(domain.verifyingContract),
		),
	);
}

export function hashTransferWithAuthorization(
	auth: Eip3009Authorization,
): Uint8Array {
	return keccak_256(
		concatBytes(
			TRANSFER_TYPEHASH,
			encodeAddress(auth.from),
			encodeAddress(auth.to),
			encodeUint256(auth.value),
			encodeUint256(auth.validAfter),
			encodeUint256(auth.validBefore),
			encodeBytes32(auth.nonce),
		),
	);
}

/** The 32-byte EIP-712 digest to sign: keccak(0x1901 ‖ domainSep ‖ structHash). */
export function eip3009Digest(
	domain: Eip712Domain,
	auth: Eip3009Authorization,
): Uint8Array {
	return keccak_256(
		concatBytes(
			new Uint8Array([0x19, 0x01]),
			domainSeparator(domain),
			hashTransferWithAuthorization(auth),
		),
	);
}
