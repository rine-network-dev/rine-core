import { HttpClient } from "./http.js";
import { UUID_PATTERN, UUID_RE_ANY_CASE } from "./uuid.js";

const DEFAULT_DOMAIN = ".rine.network";

export function normalizeHandle(handle: string): string {
	const atIdx = handle.lastIndexOf("@");
	if (atIdx === -1) return handle;
	const domain = handle.slice(atIdx + 1);
	if (domain.includes(".")) return handle;
	return handle + DEFAULT_DOMAIN;
}

const UUID_ALIAS_RE = new RegExp(`/agents/(${UUID_PATTERN})$`, "i");

const UUID_HEX_RE = /^[0-9a-f]{32}$/i;

/**
 * Whether the **wire** reads this spelling as a UUID, as written.
 *
 * Python's `uuid.UUID` — which is what every server slot typed that way runs,
 * `GET /conversations/{conversation_id}/messages` included — parses four
 * spellings, not one: the canonical dashed form, the dashless 32 hex digits,
 * the `urn:uuid:` form and the braced form. It reaches that answer by stripping
 * the `urn:`/`uuid:` prefixes and the braces, dropping every dash, and
 * requiring 32 hex digits; this restates exactly that.
 *
 * 🔴 This is the predicate a client-side pre-flight must ask, and
 * {@link UUID_RE} is not. A pre-flight is only ever allowed to refuse what the
 * wire would have refused anyway — its value is *when* it refuses, not *what* —
 * so refusing a dashless id the product has always accepted would be a
 * capability removal wearing a validation fix. `UUID_RE` stays strict on
 * purpose: it decides recipient and group resolution, where a UUID means "skip
 * the lookup" rather than "the wire will cope".
 *
 * Twin of `rine._resolve.parses_as_uuid` in the Python SDK; the two stacks
 * share no module, so they are bound by their tests.
 *
 * ⚠️ Marginally STRICTER than CPython, in one direction that is safe and is
 * recorded rather than chased: `int(hex, 16)` also tolerates underscores
 * (`"1234_5678…"`), surrounding whitespace and a leading sign, and this does
 * not. Those spellings are refused here and would have been accepted on the
 * wire — a pre-flight refusing something real, which is the failure direction
 * a pre-flight is not allowed to have. It is left as is because every such
 * spelling is pathological: no product surface emits one, and the alternative
 * is restating CPython's integer parser in a regex. If one ever shows up, this
 * is the sentence that explains it.
 */
export function parsesAsUuid(value: string): boolean {
	// Case-sensitive on the two prefixes, and in this order, because the twin is
	// a restatement of CPython's own steps — not an improvement on them. A
	// pre-flight that accepted MORE than the wire would hand the caller back the
	// framework 422 this whole module exists to keep them away from.
	const stripped = value
		.replace(/urn:/g, "")
		.replace(/uuid:/g, "")
		.replace(/^[{}]+|[{}]+$/g, "")
		.replace(/-/g, "");
	return UUID_HEX_RE.test(stripped);
}

/**
 * Resolves a handle (e.g. "agent@org") to a UUID
 * via WebFinger (RFC 7033).
 *
 * Returns the UUID string on success, or the original input unchanged
 * on failure (caller validates UUID format and reports the error).
 */
export async function resolveHandleViaWebFinger(
	apiUrl: string,
	handle: string,
): Promise<string> {
	const normalized = normalizeHandle(handle);
	try {
		const params = new URLSearchParams({
			resource: `acct:${normalized}`,
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

export { UUID_RE_ANY_CASE as UUID_RE };
