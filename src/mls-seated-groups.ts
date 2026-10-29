// The read recovery's reseat is built on: which MLS groups the server lists with
// a given agent seated.
import { ACTING_AGENT_HEADER } from "./actor.js";
import type { GroupRead } from "./api-types.js";
import { groupIsMls } from "./crypto/group-predicates.js";
import type { HttpClient } from "./http.js";

/**
 * The MLS groups the server lists with `agentId` seated, in listing order.
 *
 * The list is read AS the agent — the acting-agent header is what makes
 * `member_agent_ids` answer "which of the caller's own agents hold a seat" for
 * this one agent rather than for the caller's whole org — and filtered to the
 * groups that both carry MLS state and name the agent. A group that is MLS but
 * does not list the agent is one the agent cannot act in, and a group that lists
 * the agent without MLS state has no ratchet tree to re-enter.
 *
 * A failed listing is NOT caught: the caller decides what an unreadable group
 * list means for its own outcome, and swallowing the error here would turn a
 * transport failure into "the agent is in no groups".
 */
export async function seatedMlsGroups(
	client: HttpClient,
	agentId: string,
): Promise<GroupRead[]> {
	const page = (await client.get("/groups", undefined, {
		[ACTING_AGENT_HEADER]: agentId,
	})) as { items?: GroupRead[] };
	return (page.items ?? []).filter(
		(group) => groupIsMls(group) && group.member_agent_ids?.includes(agentId),
	);
}
