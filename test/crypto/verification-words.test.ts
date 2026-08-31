import * as fs from "node:fs";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { describe, expect, it } from "vitest";
import { type JWK, fromBase64Url } from "../../src/crypto/keys.js";
import {
	compareVerificationWords,
	verificationWordsForJwk,
	verificationWordsForKey,
} from "../../src/crypto/verification-words.js";

/**
 * The goldens live with the Python SDK's other cross-language vectors and are
 * generated from the server's implementation — see
 * `rine-sdk/tests/fixtures/generate_verification_words_vectors.py`. The server
 * suite and the Python SDK suite replay this same file. If it moves, all three
 * move together; a suite that quietly stops finding it is a suite that has
 * stopped proving byte-compatibility.
 */
const VECTORS_PATH = new URL(
	"../../../rine-sdk/tests/fixtures/verification_words_vectors.json",
	import.meta.url,
);

interface Vector {
	name: string;
	description: string;
	jwk: JWK;
	words: string;
}

const goldens: {
	one_bit_flip: [string, string];
	same_key: [string, string];
	vectors: Vector[];
} = JSON.parse(fs.readFileSync(VECTORS_PATH, "utf8"));

function vector(name: string): Vector {
	const found = goldens.vectors.find((v) => v.name === name);
	if (!found) throw new Error(`no golden vector named ${name}`);
	return found;
}

describe("verification words — cross-language goldens", () => {
	it.each(goldens.vectors)(
		"reproduces the server's words for $name from the JWK",
		({ jwk, words }) => {
			expect(verificationWordsForJwk(jwk)).toBe(words);
		},
	);

	it.each(goldens.vectors)(
		"reproduces the server's words for $name from raw key bytes",
		({ jwk, words }) => {
			expect(verificationWordsForKey(fromBase64Url(jwk.x))).toBe(words);
		},
	);

	it("changes every-word-visible output when one key bit changes", () => {
		const baseline = vector(goldens.one_bit_flip[0]);
		const flipped = vector(goldens.one_bit_flip[1]);
		expect(verificationWordsForJwk(flipped.jwk)).not.toBe(
			verificationWordsForJwk(baseline.jwk),
		);
	});

	it("gives one answer for one key regardless of base64url padding", () => {
		const unpadded = vector(goldens.same_key[0]);
		const padded = vector(goldens.same_key[1]);
		expect(verificationWordsForJwk(padded.jwk)).toBe(
			verificationWordsForJwk(unpadded.jwk),
		);
	});
});

describe("verificationWordsForKey", () => {
	it("returns five words, all from the BIP39 English list", () => {
		const words = verificationWordsForKey(new Uint8Array(32).fill(7)).split(
			" ",
		);
		expect(words).toHaveLength(5);
		for (const word of words) expect(wordlist).toContain(word);
	});

	it("refuses a key that is not 32 bytes", () => {
		expect(() => verificationWordsForKey(new Uint8Array(31))).toThrow(
			/expected 32 bytes/,
		);
	});
});

describe("compareVerificationWords", () => {
	const held = vector("baseline");
	const other = vector("baseline-one-bit");

	it("matches when the server asserts what this client computes", () => {
		expect(compareVerificationWords(held.jwk, held.words)).toEqual({
			status: "match",
			computed: held.words,
			asserted: held.words,
			match: true,
		});
	});

	it("reports a mismatch with both values, and does not throw", () => {
		const result = compareVerificationWords(held.jwk, other.words);
		expect(result.status).toBe("mismatch");
		expect(result.match).toBe(false);
		expect(result.computed).toBe(held.words);
		expect(result.asserted).toBe(other.words);
	});

	it("says it computed nothing when this client holds no key material", () => {
		expect(compareVerificationWords(null, held.words)).toEqual({
			status: "not-computed",
			computed: null,
			asserted: held.words,
			match: null,
		});
	});

	it("says the server asserted nothing when the card carries no words", () => {
		const result = compareVerificationWords(held.jwk, null);
		expect(result.status).toBe("not-asserted");
		expect(result.match).toBeNull();
		expect(result.computed).toBe(held.words);
	});

	it("treats a missing assertion and an undefined one alike", () => {
		expect(compareVerificationWords(held.jwk, undefined).status).toBe(
			"not-asserted",
		);
	});

	it("accepts raw key bytes as well as a JWK", () => {
		expect(
			compareVerificationWords(fromBase64Url(held.jwk.x), held.words).status,
		).toBe("match");
	});

	it("does not call spacing or capitalisation a mismatch", () => {
		const noisy = `  ${held.words.toUpperCase().replace(/ /g, "   ")}\n`;
		const result = compareVerificationWords(held.jwk, noisy);
		expect(result.match).toBe(true);
		// The operator is shown what the server actually sent, not a cleaned copy.
		expect(result.asserted).toBe(noisy);
	});
});
