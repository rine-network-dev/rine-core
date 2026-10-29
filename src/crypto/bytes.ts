import { concatBytes } from "@noble/hashes/utils.js";
export { equalBytes } from "@noble/curves/utils.js";
export { concatBytes as concat };

const encoder = new TextEncoder();

/** ASCII bytes of a string. Callers pass only canonical identifiers and fixed labels. */
export function ascii(text: string): Uint8Array {
	return encoder.encode(text);
}

export function u32be(value: number): Uint8Array {
	const out = new Uint8Array(4);
	new DataView(out.buffer).setUint32(0, value);
	return out;
}

export function u64be(value: number | bigint): Uint8Array {
	const out = new Uint8Array(8);
	new DataView(out.buffer).setBigUint64(0, BigInt(value));
	return out;
}

/** Canonical lowercase 8-4-4-4-12 UUID string of 16 bytes. */
export function bytesToUuid(bytes: Uint8Array): string {
	const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
