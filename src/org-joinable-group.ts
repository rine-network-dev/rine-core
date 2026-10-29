import type { HttpClient } from "./http.js";
import { sigiledGroupRef } from "./group-ref.js";
import { normalizeHandle } from "./resolve-handle.js";

/**
 * The id of the OPEN or VOTED group of that handle in which an agent of the caller's org
 * holds a seat, or `undefined`.
 *
 * Existence only: an agent's own `GET /groups` is scoped to its own seats, so a
 * kit agent could not find an own-org open or voted group a sibling sits in. The route
 * answers the id and nothing else; joining by that id is the ordinary join.
 */
export async function orgJoinableGroupIdByHandle(
	client: HttpClient,
	handle: string,
	extraHeaders?: Record<string, string>,
): Promise<string | undefined> {
	const answer = (await client.get(
		"/groups/org-joinable",
		{ handle: normalizeHandle(sigiledGroupRef(handle)) },
		extraHeaders,
	)) as { id?: string | null };
	return answer.id ?? undefined;
}
