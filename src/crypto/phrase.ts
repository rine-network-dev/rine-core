// BIP39 phrases. Port of scripts/vectors/lib/words.mjs.
import {
	entropyToMnemonic,
	mnemonicToEntropy,
	validateMnemonic,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

export type PhraseFault = "word_count" | "unknown_word" | "bad_checksum";

export class PhraseError extends Error {
	readonly fault: PhraseFault;

	constructor(fault: PhraseFault, message: string) {
		super(message);
		this.name = "PhraseError";
		this.fault = fault;
	}
}

const WORD_COUNT = 24;
const ROOT_SIZE = 32;
// The whitespace set of Python's `str.split()`, so both stacks cut a pasted phrase at the same places.
const WHITESPACE =
	/[\t-\r\x1c-\x20\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/u;

export function phraseFromEntropy(root: Uint8Array): string {
	if (root.length !== ROOT_SIZE) {
		throw new Error(`root must be ${ROOT_SIZE} bytes`);
	}
	return entropyToMnemonic(root, wordlist);
}

export function entropyFromPhrase(text: string): Uint8Array {
	const words = text
		.normalize("NFKD")
		.toLowerCase()
		.split(WHITESPACE)
		.filter((word) => word !== "");
	if (words.length !== WORD_COUNT) {
		throw new PhraseError(
			"word_count",
			`wrong word count: expected ${WORD_COUNT}, got ${words.length}`,
		);
	}
	const unknown = words.findIndex((word) => !wordlist.includes(word));
	if (unknown !== -1) {
		throw new PhraseError(
			"unknown_word",
			`unknown word at position ${unknown + 1}`,
		);
	}
	const phrase = words.join(" ");
	if (!validateMnemonic(phrase, wordlist)) {
		throw new PhraseError("bad_checksum", "bad checksum");
	}
	return mnemonicToEntropy(phrase, wordlist);
}
