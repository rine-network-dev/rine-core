/**
 * Verification words, computed here rather than read off the wire.
 *
 * Five BIP39 English words derived from an agent's Ed25519 signing key. They
 * exist so two operators can compare a short human-readable string out of band
 * and see that they are talking about the same key.
 *
 * 🔴 **The words are computed from the key the client holds. Full stop.** A key
 * fetched from `GET /agents/{id}/keys` *is* the key the server asserts, so words
 * recomputed from it agree with the server's by construction and the comparison
 * says nothing at all — while every test still passes. A surface holding no
 * local key material does not recompute and says so: that is what
 * {@link compareVerificationWords} answers `"not-computed"` for.
 *
 * The reference implementation is the server's `compute_verification_words`
 * (`src/rine/auth/service.py`); the Python twin is `rine.verification_words`.
 * All three read the same goldens
 * (`rine-sdk/tests/fixtures/verification_words_vectors.json`), because three
 * implementations of one derivation is exactly the shape that drifts.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { type JWK, jwkToPublicKey } from "./keys.js";

/** How many words a verification string carries. */
const WORD_COUNT = 5;
/** BIP39 indexes are 11 bits, so five of them consume 55 of the digest's bits. */
const BITS_PER_WORD = 11n;
const WORD_MASK = 0x7ffn;

/**
 * Key material this client holds — raw 32 bytes, or the JWK it stores them in.
 *
 * Deliberately never a pre-formatted word string: a function that accepted one
 * could be handed the server's own answer, and the comparison would be vacuous.
 */
export type HeldSigningKey = Uint8Array | JWK;

/** Whether the local computation and the server's assertion agree, and why not. */
export type VerificationWordsStatus =
	| "match"
	| "mismatch"
	/** This client holds no key material for the agent, so it computed nothing. */
	| "not-computed"
	/** The server named no words for this agent, so there is nothing to compare. */
	| "not-asserted";

/** What a surface renders: both values, a boolean, and why either is absent. */
export interface VerificationWordsComparison {
	status: VerificationWordsStatus;
	/** Words this client derived from key material it holds, or `null`. */
	computed: string | null;
	/** Words the server asserted, as received, or `null`. */
	asserted: string | null;
	/** `null` whenever one side is missing — absence is not disagreement. */
	match: boolean | null;
}

/**
 * The derivation itself: SHA-256 → first 55 bits → five 11-bit BIP39 indexes.
 *
 * The most-significant group is the first word. `BigInt` is not a stylistic
 * choice — 56 bits do not fit a JavaScript number without loss.
 */
function wordsFromDigest(digest: Uint8Array): string {
	let bits = 0n;
	for (const byte of digest.subarray(0, 7)) {
		bits = (bits << 8n) | BigInt(byte);
	}
	// Seven bytes are 56 bits; the derivation uses 55 and drops the lowest.
	bits >>= 1n;

	const words: string[] = [];
	for (let i = 0; i < WORD_COUNT; i++) {
		// biome-ignore lint/style/noNonNullAssertion: an 11-bit mask cannot leave a 2048-word list
		words.push(wordlist[Number(bits & WORD_MASK)]!);
		bits >>= BITS_PER_WORD;
	}
	words.reverse();
	return words.join(" ");
}

/**
 * The five words for a raw 32-byte Ed25519 public key.
 *
 * @param publicKey Raw public key bytes — not base64, not a JWK.
 * @throws If the key is not 32 bytes. The server derives words from whatever it
 *   decodes; refusing is the stricter answer and cannot disagree with it about
 *   any real Ed25519 key.
 */
export function verificationWordsForKey(publicKey: Uint8Array): string {
	if (publicKey.length !== 32) {
		throw new Error(
			`Invalid signing public key: expected 32 bytes, got ${publicKey.length}`,
		);
	}
	return wordsFromDigest(sha256(publicKey));
}

/**
 * The five words for an Ed25519 signing key in JWK form.
 *
 * Accepts `x` with or without base64url padding, as the server does.
 *
 * @param jwk The agent's signing public key.
 */
export function verificationWordsForJwk(jwk: JWK): string {
	return verificationWordsForKey(jwkToPublicKey(jwk));
}

/**
 * Two word strings mean the same key if they name the same five words.
 *
 * Whitespace runs are collapsed and case is ignored, because the BIP39 English
 * list is lower-case with no spaces inside a word — so neither normalisation can
 * turn one word into another, and both remove a class of false mismatch that
 * would send an operator looking for an attacker who is not there. The Python
 * twin normalises identically.
 *
 * Exported because it is the ONLY comparison of two word strings rine performs:
 * a second one spelled `a !== b` disagrees with this one on spacing and case,
 * and the surface that raises an alarm is exactly the wrong place to disagree.
 */
export function sameWords(a: string, b: string): boolean {
	const normalise = (s: string) =>
		s.trim().toLowerCase().split(/\s+/).join(" ");
	return normalise(a) === normalise(b);
}

/**
 * Compare the words this client computes against the words the server asserts.
 *
 * A mismatch is a designed state, not an error: it is returned, never thrown,
 * and it never gates sending. Both values come back so a surface can show both.
 *
 * @param heldKey Key material this client holds for the agent, or `null` when it
 *   holds none. 🔴 Never pass a key just fetched from `GET /agents/{id}/keys` —
 *   that is the server's own assertion, and feeding it back in makes the result
 *   `"match"` no matter what is true.
 * @param assertedWords The words the server named, e.g. from an agent card.
 */
export function compareVerificationWords(
	heldKey: HeldSigningKey | null,
	assertedWords: string | null | undefined,
): VerificationWordsComparison {
	const computed =
		heldKey === null
			? null
			: heldKey instanceof Uint8Array
				? verificationWordsForKey(heldKey)
				: verificationWordsForJwk(heldKey);
	const asserted = assertedWords ?? null;

	if (computed === null) {
		return { status: "not-computed", computed, asserted, match: null };
	}
	if (asserted === null) {
		return { status: "not-asserted", computed, asserted, match: null };
	}
	const match = sameWords(computed, asserted);
	return { status: match ? "match" : "mismatch", computed, asserted, match };
}
