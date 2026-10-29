import { fromBase64Url } from "../crypto/keys.js";

const BASE64URL_RE = /^[A-Za-z0-9_-]*={0,2}$/;

/**
 * The bytes of a base64url string, or undefined when it cannot be one. Trailing `=` padding is accepted as Python's
 * from_base64url accepts it; a stray character is rejected where Python's decoder would discard it (D-25).
 */
export function strictFromBase64Url(encoded: string): Uint8Array | undefined {
	if (!BASE64URL_RE.test(encoded)) return undefined;
	const unpadded = encoded.replace(/=+$/, "");
	if (unpadded.length % 4 === 1) return undefined;
	return fromBase64Url(unpadded);
}
