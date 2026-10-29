// The fleet's single-use recipient key: one base64url string holding an X25519
// public key followed by an ML-KEM-768 public key. A branch bundle is sealed to
// it so only the holder of the matching private keys can open it.
import { sha256 } from "@noble/hashes/sha2.js";
import type { BranchKeys } from "./derive.js";
import { type SealContext, sealHybrid } from "./hybrid.js";
import { fromBase64Url, toBase64Url } from "./keys.js";
import { verificationWordsForKey } from "./verification-words.js";

const X25519_PUBLIC_KEY_BYTES = 32;
const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;

/** The exact length of a recipient key: X25519 ‖ ML-KEM-768. */
export const RECIPIENT_KEY_BYTES =
	X25519_PUBLIC_KEY_BYTES + ML_KEM_768_PUBLIC_KEY_BYTES;

export interface RecipientKey {
	x25519: Uint8Array;
	mlKem: Uint8Array;
	/** The whole key, in wire order. */
	raw: Uint8Array;
}

/**
 * Parse the fleet's recipient key. The length is checked before anything is
 * sealed to it: a truncated key would otherwise seal to a key nobody holds.
 */
export function parseRecipientKey(text: string): RecipientKey {
	const raw = fromBase64Url(text.trim());
	if (raw.length !== RECIPIENT_KEY_BYTES) {
		throw new Error(
			"recipient key must be 1216 bytes: an X25519 key followed by an ML-KEM-768 key, base64url",
		);
	}
	return {
		x25519: raw.slice(0, X25519_PUBLIC_KEY_BYTES),
		mlKem: raw.slice(X25519_PUBLIC_KEY_BYTES),
		raw,
	};
}

/**
 * The five verification words for a recipient key: the words of its SHA-256,
 * which is 32 bytes like the Ed25519 keys the word function is defined over.
 * The fleet computes the same words on its side, so a partner compares what the
 * dashboard shows with what this prints.
 */
export function recipientKeyWords(key: RecipientKey): string {
	return verificationWordsForKey(sha256(key.raw));
}

/** The plaintext a branch bundle carries, in this exact key order. */
function branchBundleJson(
	orgId: string,
	branch: Pick<BranchKeys, "name" | "bRead" | "bSign">,
): string {
	return JSON.stringify({
		org_id: orgId,
		branch: branch.name,
		read: toBase64Url(branch.bRead),
		sign: toBase64Url(branch.bSign),
		v: 1,
	});
}

/**
 * Seal a branch's delegate secrets to the recipient key. The plaintext is
 * zeroed once it has been sealed, whatever the seal does.
 */
export function sealBranchBundle(
	key: RecipientKey,
	orgId: string,
	branch: Pick<BranchKeys, "name" | "bRead" | "bSign">,
): Uint8Array {
	const plaintext = new TextEncoder().encode(branchBundleJson(orgId, branch));
	const context: SealContext = {
		kind: "BranchBundle",
		orgId,
		branch: branch.name,
	};
	try {
		return sealHybrid(key.x25519, key.mlKem, plaintext, context);
	} finally {
		plaintext.fill(0);
	}
}
