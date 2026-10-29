import { fromBase64Url } from "./crypto/keys.js";

/**
 * The one cleartext path: a message an external A2A client posted to an agent whose
 * card accepts cleartext. Its body travelled without end-to-end encryption, so every
 * surface that shows such a message says so, in this one sentence.
 */
export const A2A_CLEARTEXT_NOTICE =
	"Received as A2A cleartext: this message was not end-to-end encrypted.";

/** The wire marker of an A2A message, and of the cleartext version only it may carry. */
export const A2A_MESSAGE_TYPE = "rine.v1.a2a_message";
export const CLEARTEXT_ENCRYPTION_VERSION = "none";

/** Whether a message row is an A2A message that arrived as cleartext. */
export function isA2aCleartext(row: { type: string; encryption_version?: string | null }): boolean {
	return row.type === A2A_MESSAGE_TYPE && row.encryption_version === CLEARTEXT_ENCRYPTION_VERSION;
}

/** A row that is A2A cleartext, carrying the typed flag and the sentence for it. */
export type A2aCleartextMark = { a2a_cleartext: true; a2a_cleartext_notice: string };

/** The typed flag and the sentence for `row` when it is A2A cleartext, else null. */
export function a2aCleartextMark(row: {
	type: string;
	encryption_version?: string | null;
}): A2aCleartextMark | null {
	return isA2aCleartext(row)
		? { a2a_cleartext: true, a2a_cleartext_notice: A2A_CLEARTEXT_NOTICE }
		: null;
}

/** `row` with the cleartext mark when it is A2A cleartext, else `row` itself. */
export function markA2aCleartext<T extends { type: string; encryption_version: string }>(
	row: T,
): T | (T & A2aCleartextMark) {
	const mark = a2aCleartextMark(row);
	return mark ? { ...row, ...mark } : row;
}

/**
 * `text`, the body shown for `row`, led by the notice in brackets when `row` is A2A cleartext.
 *
 * Every renderer that shows one string, or hands one to a model, calls this on the readable
 * branch, so a cleartext body never reads as end-to-end encrypted. Any other row comes back
 * unchanged.
 */
export function withA2aCleartextNotice(
	row: { type: string; encryption_version?: string | null },
	text: string,
): string {
	return isA2aCleartext(row) ? `[${A2A_CLEARTEXT_NOTICE}] ${text}` : text;
}

/**
 * The parts the external client posted, as the JSON text the server stored. The wire
 * `encrypted_payload` of a cleartext row is that text in unpadded base64url, not the
 * text itself.
 */
export function a2aCleartextPlaintext(row: { encrypted_payload: string }): string {
	return new TextDecoder().decode(fromBase64Url(row.encrypted_payload));
}

/** The posted parts parsed, or the text as it is when it is not JSON. */
export function a2aCleartextPayload(row: { encrypted_payload: string }): unknown {
	const text = a2aCleartextPlaintext(row);
	try {
		return JSON.parse(text);
	} catch {
		return text;
	}
}
