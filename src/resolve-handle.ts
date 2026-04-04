import { HttpClient } from "./http.js";

const UUID_ALIAS_RE =
	/\/agents\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

const UUID_RE =
	/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Resolves a handle (e.g. "agent@org.rine.network") to a UUID
 * via WebFinger (RFC 7033).
 *
 * Returns the UUID string on success, or the original input unchanged
 * on failure (caller validates UUID format and reports the error).
 */
export async function resolveHandleViaWebFinger(
	apiUrl: string,
	handle: string,
): Promise<string> {
	try {
		const params = new URLSearchParams({
			resource: `acct:${handle}`,
		});
		const data = (await HttpClient.publicGet(
			apiUrl,
			"/.well-known/webfinger",
			params,
		)) as { aliases?: string[] };
		for (const alias of data.aliases ?? []) {
			const match = UUID_ALIAS_RE.exec(alias);
			if (match?.[1]) return match[1];
		}
	} catch {
		// WebFinger lookup failed — fall through
	}
	return handle;
}

export { UUID_RE };
