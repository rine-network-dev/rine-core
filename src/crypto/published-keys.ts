import type { HttpClient } from "../http.js";
import { canonicalUuid } from "./derive-read.js";
import type { PublishedKeys } from "./key-chain.js";

/**
 * The one place a key response is read off the wire. Callers pass ids taken
 * from untrusted rows, so the id must be a canonical UUID before it enters the
 * path: anything else could retarget the GET to another route.
 */
export function getPublishedKeys(
	client: Pick<HttpClient, "get">,
	agentId: string,
	gen?: number,
): Promise<PublishedKeys> {
	return client.get(
		`/agents/${canonicalUuid(agentId, "agent id")}/keys`,
		gen === undefined ? undefined : { gen },
	) as Promise<PublishedKeys>;
}
