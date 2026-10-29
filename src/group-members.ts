/**
 * A group's roster as the server states it: `GET /groups/{id}/members`.
 *
 * One typed read rather than a cast at every call site. The sender-key send,
 * the sender-key read's retirement lift and the MLS admission tree all ask
 * this route the same question, and three hand-written response shapes are
 * three places for the answer to drift.
 *
 * A member row is the server's record, not a ratchet-tree leaf: a seated
 * member can still hold no MLS state. Callers that need the tree ask the tree.
 */
import type { GroupMemberRead, ListResponse } from "./api-types.js";
import type { HttpClient } from "./http.js";

/**
 * Every member row the server returns for one group.
 *
 * A page that carries no `items` reads as an empty roster, never as an error.
 * A refused or failed read throws, as the client raises it, so a caller that
 * answers an eviction on the refusal still sees the refusal.
 */
export async function fetchGroupMembers(
	client: Pick<HttpClient, "get">,
	groupId: string,
	extraHeaders?: Record<string, string>,
): Promise<GroupMemberRead[]> {
	const page = (await client.get(
		`/groups/${groupId}/members`,
		undefined,
		extraHeaders,
	)) as Partial<ListResponse<GroupMemberRead>>;
	return page.items ?? [];
}
