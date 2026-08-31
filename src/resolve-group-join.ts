/**
 * What a group reference resolves to when the verb is JOIN, and nothing else.
 *
 * 🔴 **Join is the one group verb whose target is, by definition, a group the
 * caller is NOT in.** Every other verb — read, send, invite, vote, leave — asks
 * about a group this org already holds a seat in, so `resolveGroupUuid`
 * (`resolve-group.ts`) is right for them: every rung it takes is scoped to a
 * group the org owns or is seated in — `GET /groups/{id}` for a UUID,
 * `GET /groups` for a handle or a name — and a stranger's reference
 * answering nothing there is the server's answer rather than a defect in the
 * lookup.
 *
 * For join that same ladder is exactly backwards. It searches the one set that
 * cannot contain the target, so a handle a caller had just read off
 * `discoverGroups()` came back `Group not found` with the server never having
 * refused anything. This module is the join-scoped ladder that replaces it; the
 * matchers and every sentence it refuses with are `group-join-words.ts`.
 *
 * **A handle walks three rungs.**
 *
 * 1. `GET /groups?handle=` — the group this org is already seated in. It
 *    resolves so the server can answer the honest `409 Agent is already a
 *    member` instead of a client-side "not found" about a group the caller is
 *    standing in.
 * 2. `GET /groups/invites` — the group that invited or nominated this agent. An
 *    invitation mints no membership row, so rung 1 structurally cannot see it.
 * 3. `GET /directory/groups?q=` — a public group with no relationship at all.
 *
 * **A bare name walks one, and only one.** It is looked for among this agent's
 * pending invitations and nowhere else — see
 * {@link BARE_NAME_IS_ONLY_AN_INVITATION} for why that rung is admissible and a
 * directory search for a bare name is not.
 *
 * A UUID is already the answer and costs no request at all.
 *
 * 🔴 **Why the directory rung is not the widening that was refused.** The
 * directory filter is `name ILIKE` OR `description ILIKE`, and a fuzzy match
 * feeding an irreversible verb is what killed bare-name resolution.
 * Here the ILIKE is a **candidate generator only**: every row it returns
 * is put through {@link isExactGroupHandle}, and group handles are `UNIQUE` on
 * the server, so at most one row can survive and it is by definition the group
 * the caller named. A wrong match is not reachable. The identifier is resolved;
 * a different group is never joined.
 *
 * The limitations are real and are said in the refusals rather than hidden: the
 * directory is filtered to `visibility == "public"`, and it is read under a page
 * budget, so a refusal states which of those two it ran into.
 */

import {
	DIRECTORY_PAGES_FOR_A_JOIN,
	DIRECTORY_PAGE_LIMIT,
	ambiguousInvitationJoinRefusal,
	bareNameJoinRefusal,
	directoryQueryForHandle,
	isExactGroupHandle,
	isInvitationOfThatName,
	unresolvedHandleJoinRefusal,
} from "./group-join-words.js";
import { listMyInvites } from "./group-invite-ops.js";
import type { HttpClient } from "./http.js";
import { seatedGroupByHandle } from "./resolve-group.js";
import { UUID_RE } from "./resolve-handle.js";

/** The fields a directory row has to carry for a handle to resolve off it. */
interface DirectoryGroupRow {
	id: string;
	handle?: string;
}

/** What one directory page carries that this scan reads. */
interface DirectoryPage {
	items?: DirectoryGroupRow[];
	next_cursor?: string;
	/**
	 * Every public group the filter matched, not just this page's worth —
	 * `src/rine/api/directory_groups.py` computes it with a `COUNT` beside the
	 * page query. It is what turns "the budget ran out" into an exact number.
	 */
	total_estimate?: number;
}

/** What the directory rung found, and how much of it went unread. */
interface DirectorySearch {
	id?: string;
	/**
	 * Matching rows this pass never looked at — `0` when the search ran to the
	 * end, and `0` again when the server sent no total to subtract from. A
	 * shortfall invented out of a missing field is worse than none.
	 */
	unread: number;
}

/**
 * The PUBLIC group of that handle, and what the search did not cover.
 *
 * The one rung that can see a group this caller has no relationship with. It is
 * bounded to {@link DIRECTORY_PAGES_FOR_A_JOIN} pages, and it reports the bound
 * rather than swallowing it: the directory orders by recency, not by match
 * quality, so a crowded substring can leave the named group unread however
 * exact the handle was. `unread` is what lets the refusal say so.
 *
 * ⚠️ It goes out over the caller's `HttpClient`, which sends the org's bearer
 * token and — on the SDK path — `X-Rine-Agent`, even though the route itself
 * takes no identity (`src/rine/api/directory_groups.py` declares no auth
 * dependency) and rate-limits on the client IP. **Both stacks do this**: the
 * Python twin used to reach the rung through the anonymous `discover_groups()`
 * verb, so one join disclosed the caller on eve and mastra and nothing on the
 * three Python connectors; round 9 pointed it at the clients' authenticated
 * page reader instead (`_directory_groups_page`,
 * `rine-sdk/src/rine/_sync_client.py` and its async twin). Same rows, same
 * `total_estimate`, same bucket either way — what is now the same is what the
 * two stacks disclose. `discover_groups()` itself stays anonymous on both
 * stacks; it is the public discovery verb, and this rung is not it.
 */
async function searchPublicDirectory(
	client: HttpClient,
	handle: string,
): Promise<DirectorySearch> {
	let cursor: string | undefined;
	let read = 0;
	let total: number | undefined;
	for (let page = 0; page < DIRECTORY_PAGES_FOR_A_JOIN; page++) {
		const params: Record<string, string | number> = {
			q: directoryQueryForHandle(handle),
			limit: DIRECTORY_PAGE_LIMIT,
		};
		if (cursor) params.cursor = cursor;
		const answer = (await client.get(
			"/directory/groups",
			params,
		)) as DirectoryPage;
		const rows = answer.items ?? [];
		read += rows.length;
		if (typeof answer.total_estimate === "number") total = answer.total_estimate;
		const match = rows.find((row) => isExactGroupHandle(row.handle, handle));
		if (match) return { id: match.id, unread: 0 };
		cursor = answer.next_cursor;
		if (!cursor) break;
	}
	return { unread: typeof total === "number" ? Math.max(0, total - read) : 0 };
}

/**
 * The group id one of this agent's pending invitations answers a bare name with.
 *
 * 🔴 **Two matches is a refusal, never a pick.** A bare name carries no org, so
 * two orgs inviting this agent to a group called `ops` are indistinguishable in
 * the reference — and seating an agent in the wrong one cannot be undone. The
 * candidates are printed instead.
 *
 * @throws {Error} No invitation answers to the name, or more than one does.
 */
function invitedGroupByBareName(
	invites: readonly { group_id: string; group_handle?: string; group_name?: string }[],
	name: string,
): string {
	const matched = invites.filter((row) =>
		isInvitationOfThatName(row.group_handle, row.group_name, name),
	);
	if (matched.length === 1 && matched[0]) return matched[0].group_id;
	if (matched.length > 1) {
		throw new Error(
			ambiguousInvitationJoinRefusal(
				name,
				matched.map((row) => row.group_handle ?? row.group_name ?? row.group_id),
			),
		);
	}
	throw new Error(bareNameJoinRefusal(name));
}

/**
 * Resolve a group reference for JOIN — the one verb aimed outside the org.
 *
 * 🔴 Deliberately **not** `resolveGroupUuid`. The rungs, the bounds and every
 * refusal are this module's and `group-join-words.ts`'s; the header is where
 * the reasons live.
 *
 * `extraHeaders` carries `X-Rine-Agent` where the caller has one. It selects
 * whose invitations are read, which on this ladder is more than attribution: it
 * is the whole of what a bare name is resolved against.
 *
 * @throws {Error} No rung resolved the reference.
 */
export async function resolveGroupUuidForJoin(
	client: HttpClient,
	ref: string,
	extraHeaders?: Record<string, string>,
): Promise<string> {
	if (UUID_RE.test(ref)) return ref;
	if (!ref.includes("@")) {
		return invitedGroupByBareName(await listMyInvites(client, extraHeaders), ref);
	}

	const seated = await seatedGroupByHandle(client, ref, extraHeaders);
	if (seated) return seated.id;

	const invites = await listMyInvites(client, extraHeaders);
	const invited = invites.find((row) =>
		isExactGroupHandle(row.group_handle, ref),
	);
	if (invited) return invited.group_id;

	const listed = await searchPublicDirectory(client, ref);
	if (listed.id) return listed.id;

	throw new Error(unresolvedHandleJoinRefusal(ref, listed.unread));
}
