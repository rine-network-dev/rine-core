/**
 * Decrypted plaintext → the body a transcript shows. Split out of `thread.ts`
 * for that module's file-size budget; it is the one piece of the thread render
 * that touches no keys, no rows and no state.
 */

/**
 * Render a decrypted plaintext string to the human-readable body, mirroring the
 * ts-sdk `decryptEnvelope`→`autoParsePlaintext` + `renderText` chain byte-for-byte
 * so every surface renders the same transcript.
 *
 * Parsing is content-type-gated, exactly like the SDK: only an
 * `application/json` body (the default when `content_type` is null/undefined) is
 * `JSON.parse`d; any other content type (e.g. `text/plain`) is surfaced verbatim,
 * even if it happens to look like JSON. Connectors wrap the body as
 * `{ "text": "…" }`; that string is surfaced directly. Any other JSON shape is
 * re-`JSON.stringify`d (normalizing whitespace) to match the SDK's `renderText`.
 */
export function renderThreadText(
	plaintext: string,
	contentType?: string | null,
): string {
	const ct = contentType ?? "application/json";
	if (ct !== "application/json") return plaintext;
	let parsed: unknown;
	try {
		parsed = JSON.parse(plaintext);
	} catch {
		// Bytes claimed JSON but didn't parse — surface the raw string, like the SDK.
		return plaintext;
	}
	if (typeof parsed === "string") return parsed;
	if (
		parsed != null &&
		typeof parsed === "object" &&
		typeof (parsed as { text?: unknown }).text === "string"
	) {
		return (parsed as { text: string }).text;
	}
	return JSON.stringify(parsed);
}
