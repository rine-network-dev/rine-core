// The org-word encoding. Port of scripts/vectors/lib/words.mjs.
import { sha256 } from "@noble/hashes/sha2.js";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { ascii, concat } from "./bytes.js";

const BITS_PER_WORD = 11n;
const WORD_MASK = 0x7ffn;

/** 8 BIP39 words derived from an org id: SHA-256 → first 88 bits → eight 11-bit indexes. */
export function orgWords(orgId: string): string {
	const hex = orgId.replace(/-/g, "");
	if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new Error("org id must be 16 bytes of hex");
	const digest = sha256(
		concat(
			ascii("rine.v1.org-words"),
			new Uint8Array(1),
			new Uint8Array(Buffer.from(hex, "hex")),
		),
	);
	let value = 0n;
	for (let index = 0; index < 11; index += 1) {
		// biome-ignore lint/style/noNonNullAssertion: the digest is 32 bytes, so 0..10 exist
		value = (value << 8n) | BigInt(digest[index]!);
	}
	const words: string[] = [];
	for (let shift = 77n; shift >= 0n; shift -= BITS_PER_WORD) {
		// biome-ignore lint/style/noNonNullAssertion: an 11-bit mask cannot leave a 2048-word list
		words.push(wordlist[Number((value >> shift) & WORD_MASK)]!);
	}
	return words.join(" ");
}
