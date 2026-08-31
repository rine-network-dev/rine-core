/**
 * A group reference — a handle, a bare name, or a UUID — resolved to the group
 * the server knows, in the one place the TypeScript stack does it.
 *
 * The handle lookup is four lines and it had three copies: the CLI's send path,
 * the TypeScript SDK's send path, and `sender-key-ops.ts`. All three asked
 * `GET /groups?handle=` and all three refused with `Group not found: …`, which
 * is exactly the shape a fourth copy grows in without anyone noticing — and the
 * fourth was about to be the transcript read.
 *
 * 🔴 The three rungs are the Python SDK's `_resolve_group_async`, restated: the
 * two stacks share no module, so they are two implementations of one contract.
 * That contract is what every group verb's *"Group handle (e.g. #logistics@acme.rine.network), name or
 * UUID"* promises, and a refusal on this stack may only advertise a spelling
 * this stack accepts — which is why the bare-name rung is here and not left as
 * a sentence that is true elsewhere. What that rung DECIDES, once the list is
 * in hand, lives in `group-ref.ts` alongside its Python twin.
 *
 * 🔴 The path literals live here because
 * `tests/test_client-server-contract_group0.py` extracts
 * `client.<verb>(<literal>)` out of `rine-core/src` and resolves every one
 * against the real FastAPI routes. A resolver that built its path from a
 * variable would be invisible to that gate — and so is a route asked from any
 * other module, which is why `group-ref.ts` holds no path of its own.
 */

import type { AgentRead, GroupRead } from "./api-types.js";
import { GroupIdentityMismatchError, RineApiError } from "./errors.js";
import {
	groupLocalPart,
	matchGroupByName,
	recipientGroupForBareName,
	refuseIfABareAgentName,
	sigiledGroupRef,
	unknownGroupRefusal,
} from "./group-ref.js";
import type { HttpClient } from "./http.js";
import type {
	ResolveOptions,
	SeatedGroupTarget,
} from "./recipient-target.js";
import { fetchAgents } from "./resolve-agent.js";
import { UUID_RE, normalizeHandle } from "./resolve-handle.js";

/**
 * Resolve a group handle to the group row, through the server's own lookup.
 *
 * `GET /groups?handle=` is scoped to the groups the caller's ORG is already in
 * — a stranger resolving a handle they found in the directory gets nothing
 * here, and that is the server's answer, not a defect in this function.
 *
 * 🔴 **A stranger's UUID is not the way round it either.**
 * {@link resolveGroup} reads an id from `GET /groups/{id}`
 * and refuses what that route will not serve this caller, so every spelling
 * this entry point's ladder takes is scoped to a group the org owns or is
 * seated in. {@link resolveGroupForJoin} (`recipient-resolution.ts`) is the
 * entry aimed at a group this org holds neither in, and its UUID rung is
 * deliberately still a passthrough.
 *
 * The handle is normalised first, so the short form (`#ops@acme`) and the full
 * one (`#ops@acme.rine.network`) name the same group.
 *
 * ⚠️ That normalisation reaches the SEND path too, not just the read this round
 * added: `getOrCreateSenderKey` and the CLI's group send both resolve through
 * here and used to pass the handle to `?handle=` verbatim. It is idempotent —
 * the server normalises the same way, so a full handle produces a byte-identical
 * query and a short one now resolves where it used to find nothing — but a send
 * path changed under a read's brief, and that is worth saying out loud rather
 * than leaving for a bisect to find.
 *
 * @throws {Error} No group of that handle is visible to this caller.
 */
export async function resolveGroupByHandle(
	client: HttpClient,
	handle: string,
	extraHeaders?: Record<string, string>,
): Promise<GroupRead> {
	const group = await seatedGroupByHandle(client, handle, extraHeaders);
	if (group) return group;
	// `?handle=` is an equality test, so a handle whose ORG half is wrong
	// fails harder than no org at all: the `@` is the whole reason the reference
	// took this branch instead of the ladder, and `heron-count` would have
	// matched where `#heron-count@acme.rine.network` could not. That spelling is
	// what three live-model runs actually produced — the local part learned from
	// the conversation, the domain copied out of the shipped examples — so the
	// local part is put through the same four tiers a bare name already gets.
	//
	// 🔴 One level ABOVE `seatedGroupByHandle` on purpose: the join ladder
	// (`resolve-group-join.ts`) takes that function's empty answer as its first
	// rung, and a group the caller is not yet in is precisely what join is for.
	// Widening it there would collapse the rung into the answer.
	//
	// Bounded by the route, not by trust: `GET /groups` is org-scoped, so this
	// can only ever reach a group the caller already holds a seat in, and the
	// server refuses a post to a group the acting agent is not seated in
	// regardless. The refusal quotes `handle`, never the local part.
	return resolveGroupByName(client, groupLocalPart(handle), extraHeaders, handle);
}

/**
 * The same lookup, answering `undefined` instead of throwing.
 *
 * 🔴 **Named for its scope, because the scope is the whole point.** The route
 * joins `GroupMember` to the caller's org, so it answers for a group this org
 * already holds a seat in and for no other. Every group verb but one wants
 * exactly that, and for them an empty page IS the refusal — which is why
 * {@link resolveGroupByHandle} keeps the throw and stays the function they call.
 *
 * `join` is the one verb aimed at a group the caller is by definition NOT in, so
 * for it an empty page is the first rung of a ladder rather than the end of one.
 * It takes this shape; see `resolve-group-join.ts`. The Python twin of the split
 * is `_seated_group_row_by_handle` on both clients, with
 * `_seated_group_id_by_handle` over it for the join rung that wants only to know
 * WHETHER the org is seated.
 *
 * 🔴 The sigil is put back before the handle is normalised. `?handle=` is an
 * equality test against a stored handle that always carries `#`, so a caller
 * who writes `ops@acme.rine.network` — which `isExactGroupHandle` and every
 * other comparison on this stack read as the same reference — matched nothing
 * here while its Python twin resolved it. On the join ladder that miss reads as
 * "no group of that handle", said to a caller standing inside the group.
 */
export async function seatedGroupByHandle(
	client: HttpClient,
	handle: string,
	extraHeaders?: Record<string, string>,
): Promise<GroupRead | undefined> {
	const normalized = normalizeHandle(sigiledGroupRef(handle));
	const page = (await client.get(
		"/groups",
		{ handle: normalized },
		extraHeaders,
	)) as { items?: GroupRead[] };
	return page.items?.[0];
}

/**
 * Every group the caller's org belongs to, unfiltered.
 *
 * The one rung that cannot be pushed down into the server: `?handle=` matches a
 * FULL `#name@org` handle only, so a bare `ops` returns nothing there however
 * many groups are called that. What is done with the list — which spellings
 * count, what one match, several or none mean — is `group-ref.ts`'s, so this
 * stays what it looks like: the fetch, and nothing else.
 *
 * `extraHeaders` carries `X-Rine-Agent` where the caller has one. Attribution,
 * not selection — the route is org-scoped either way.
 */
async function fetchOwnGroups(
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<GroupRead[]> {
	const page = (await client.get("/groups", undefined, extraHeaders)) as {
		items?: GroupRead[];
	};
	return page.items ?? [];
}

/**
 * The group one id names, or `undefined` when this caller may not read it.
 *
 * 🔴 **The whole content of this rung: one indexed row, and the roster only
 * when the answer is no.** It first shipped as a `GET /groups` list read, and
 * *"pay the list only on the refusal path"* was unbuildable that way — the
 * roster WAS how a resolved id was told from a refused one, so every UUID verb
 * paid an unpaginated list on the SUCCESS path, and that list is N+1 in the
 * route (`list_groups` counts members per row). This asks for the one row
 * instead, and {@link resolveGroup} fetches the roster afterwards, for the
 * sentence and for nothing else.
 *
 * 🔴 **404 and 403 answer the same, and that is a disclosure rule rather than
 * a simplification.** `GET /groups/{id}` 404s an id no group carries and 403s
 * one belonging to an org this caller is neither owner of nor seated in
 * (`has_read_access`, `src/rine/api/group_helpers.py`). Separating them would
 * tell a stranger which unknown ids EXIST, which is a non-member lookup rine
 * does not offer. Both become `undefined` here, so one refusal is
 * composed for both.
 *
 * ⚠️ Every other status is rethrown untouched. A 500, a 429 or a network fault
 * is not "no group of that id", and swallowing it into a roster refusal would
 * tell a caller their reference was wrong about an outage.
 *
 * ✅ It also restores one case outright: `has_read_access`'s FIRST clause
 * is `group.org_id == org_id`, so a group this org created and then vacated is
 * readable by id while being invisible to `GET /groups`. The list read refused
 * it locally.
 *
 * The caller's own spelling goes on the wire: `UUID_RE` has already passed, so
 * `id` is `[0-9a-fA-F-]` and nothing else, and every group route types its path
 * parameter `group_id: uuid.UUID`, which parses an upper-cased id to the same
 * value. That is why this rung needs no case fold on the REQUEST — there is no
 * client-side spelling comparison left to get wrong on the way out.
 *
 * 🔴 **The answer is checked, and that is not defensive tidiness.**
 * This rung was once a passthrough, so no server answer could stand in
 * for the group the caller named. Now the body is what every group verb acts
 * on — and `resolveGroup` is the seam five more surfaces are being routed
 * through — so a row naming another group would make every one of them act on
 * that group while the caller believed it addressed its own. It is a
 * {@link GroupIdentityMismatchError} and NOT the roster refusal: the fault is
 * the server's, and answering it with *"Group not found"* would send a caller
 * off to re-spell a reference that was right. The Python twin is
 * `rine._recipient_reads.refuse_a_substituted_group`, and `GroupsResource.get`
 * (`rine-ts-sdk`) refuses the same body one layer up with the same sentence.
 *
 * The comparison folds case — the request did not, so the row comes back in the
 * server's spelling whatever the caller wrote — and a body carrying no usable
 * `id` is a mismatch rather than a crash.
 *
 * 🔴 **A group id is a JSON string or it is absent, and this is the only place
 * on this stack that decides which.** `String(x)` and Python's `str(x)` agree
 * on strings and on nothing else — `false`/`False`, `[object Object]`/`{}`,
 * `x`/`['x']` — so coercing whatever arrived would make the two stacks compose
 * different sentences for the same body, which the two stacks' byte-symmetry
 * rules out, and the producer here is a server answering badly. Anything that
 * is not a string is therefore reported as *no id* rather than rendered, on
 * both stacks; the twin is `rine._recipient_reads.answered_group_id`.
 */
async function readableGroupById(
	client: HttpClient,
	id: string,
	extraHeaders?: Record<string, string>,
): Promise<GroupRead | undefined> {
	let row: GroupRead;
	try {
		row = (await client.get(`/groups/${id}`, undefined, extraHeaders)) as GroupRead;
	} catch (error) {
		const refused =
			error instanceof RineApiError && (error.status === 404 || error.status === 403);
		if (refused) return undefined;
		throw error;
	}
	const answered = typeof row?.id === "string" ? row.id : null;
	if (answered === null || answered.toLowerCase() !== id.toLowerCase()) {
		throw new GroupIdentityMismatchError(id, answered);
	}
	return row;
}

/**
 * Resolve the two references the server's own lookup cannot answer — a bare
 * `ops` and the sigiled `#ops` — to the group row, through the org's own list.
 *
 * `?handle=` matches a FULL `#name@org` handle only, so both spellings are a
 * guaranteed empty page there however many groups carry the name. The sigil is
 * stripped by `matchGroupByName` (`/^#+/`), which is why one function answers
 * both: `#ops` says which NAMESPACE the caller means and nothing more, and the
 * name it carries is the same name.
 *
 * The row and not the id, because a caller about to send needs the handle the
 * wire takes and the encryption the group runs. {@link resolveGroupUuid} is
 * this rung with the row thrown away, and delegates here rather than restating
 * the fetch beside it.
 *
 * @throws {Error} No group of the caller's answers to that reference, or more
 *   than one does.
 */
export async function resolveGroupByName(
	client: HttpClient,
	ref: string,
	extraHeaders?: Record<string, string>,
	spelling?: string,
): Promise<GroupRead> {
	return matchGroupByName(await fetchOwnGroups(client, extraHeaders), ref, spelling);
}

/**
 * The member entry point: a group reference — UUID, bare name, or handle —
 * resolved to the group, the handle the wire takes, and the row the ladder was
 * already holding.
 *
 * The "one ladder": the three spellings a group answers to, resolved in
 * one place, so a verb that needs the row and a verb that needs only the id
 * cannot disagree about which group a reference names. Every group verb but
 * `join` comes here; `resolveGroupForJoin` (`recipient-resolution.ts`) is the
 * one aimed at a group the caller is by definition not seated in, and its rungs
 * are deliberately not these.
 *
 * The UUID arm is the one that is not a spelling at all — it names the group by
 * identity, so it is read from the group's own route and has no tier to fall
 * through into ({@link readableGroupById}).
 *
 * ⚠️ Scoped by the route: `GET /groups/{id}` answers for a group this ORG owns
 * or holds a seat in, so a UUID that names a real group elsewhere is refused
 * here with the caller's own roster — the same sentence a name miss gets, and
 * the honest answer for every verb but join.
 *
 * 🔴 It lives here, beside its rungs and the path literals they ask, rather
 * than in `recipient-resolution.ts` with the other two entry points: that
 * module imports this one, and a ladder that called back into it would make the
 * two modules circular. `recipient-resolution.ts` exports this name, so the
 * three entry points are still imported from one place.
 *
 * `spelling` on the answer is the caller's own `ref`, never the local part the
 * handle fallback matched on.
 *
 * @throws {Error} No group of the caller's answers to that reference, or more
 *   than one does.
 */
export async function resolveGroup(
	client: HttpClient,
	ref: string,
	opts: ResolveOptions = {},
): Promise<SeatedGroupTarget> {
	const { extraHeaders } = opts;
	if (UUID_RE.test(ref)) {
		const found = await readableGroupById(client, ref, extraHeaders);
		if (found) return seatedGroupTarget(found, ref);
		// The roster is fetched HERE and not above it, which is the whole point:
		// a resolved id costs one indexed row, and the unpaginated list is
		// paid only to say which groups there were instead.
		throw new Error(unknownGroupRefusal(await fetchOwnGroups(client, extraHeaders), ref));
	}
	if (!ref.includes("@")) {
		return seatedGroupTarget(await resolveGroupByName(client, ref, extraHeaders), ref);
	}
	return seatedGroupTarget(await resolveGroupByHandle(client, ref, extraHeaders), ref);
}

/** The row a member rung answered with, as the record the contract returns. */
function seatedGroupTarget(row: GroupRead, spelling: string): SeatedGroupTarget {
	return { id: row.id, handle: row.handle, spelling, row };
}

/**
 * The same reference, resolved to the group ROW.
 *
 * {@link resolveGroup} with the record thrown away, kept for the call sites
 * that predate it. The ladder is not restated here — a second copy of the three
 * arms is exactly the drift the one ladder closed.
 *
 * @throws {Error} No group of the caller's answers to that reference, or more
 *   than one does.
 */
export async function resolveGroupRef(
	client: HttpClient,
	ref: string,
	extraHeaders?: Record<string, string>,
): Promise<GroupRead> {
	return (await resolveGroup(client, ref, { extraHeaders })).row;
}

/**
 * The same reference, resolved to the group's UUID.
 *
 * {@link resolveGroup} with everything but the id thrown away — all three
 * spellings, including a UUID, walk the same ladder.
 *
 * 🔴 **A UUID used to pass straight through here, and no longer does.** This
 * entry answered an id nobody had checked while {@link resolveGroup} refused
 * the same unknown id with the caller's own roster, so one reference got two
 * answers depending on which entry a verb happened to reach. The roster refusal
 * won: what a bare server 404 buys is a measured
 * 0/6 recovery rate, and the id is the one spelling a model most often invents.
 * It is priced properly — a resolved id costs one indexed
 * `GET /groups/{id}` and the unpaginated roster is read only to compose the
 * refusal. `resolveGroupForJoin` is untouched and must stay so: a join targets
 * a group this org is neither owner of nor seated in by definition, so neither
 * of those two reads can describe it.
 *
 * `extraHeaders` carries `X-Rine-Agent` where the caller has one. It is
 * attribution, not selection: `GET /groups` is org-scoped, so a bare name
 * resolves against every group an agent of the org belongs to either way.
 */
export async function resolveGroupUuid(
	client: HttpClient,
	ref: string,
	extraHeaders?: Record<string, string>,
): Promise<string> {
	return (await resolveGroup(client, ref, { extraHeaders })).id;
}

/**
 * Resolve a bare send recipient — no `@`, not a UUID — to the group it names.
 *
 * 🔴 **This does not widen recipient resolution; it catches what the agent
 * namespace has already declined.** `resolveToUuid` accepts a UUID or something
 * containing `@` and refuses everything else *on syntax, before any request*,
 * so a bare recipient is a guaranteed failure today. Routing it here can only
 * turn a certain refusal into a correct group send or a better refusal. Call it
 * with exactly what `resolveToUuid` would have refused — never with a spelling
 * that could still name an agent — and the guarantee holds.
 *
 * **The collision guard, and why it refuses rather than picks.** The one real
 * risk is a caller who meant an agent and dropped the `@org`: `send("ops")`
 * meaning `ops@acme`, silently posting to a group called `ops` instead. So the
 * org's own agents are asked first, and `refuseIfABareAgentName` refuses a name
 * that is one of them, printing the handle that would have sent the DM. Not a
 * silent DM either — recipient resolution requires a handle by design, and
 * widening the agent side is a separate decision nobody has taken. Only a name
 * that matches no agent at all reaches the group ladder.
 *
 * `preFetchedAgents` is how the guard normally costs no request at all: every
 * caller of this function has just resolved an acting agent off the same
 * `GET /agents`, and `fetchAgents` is deliberately uncached, so a caller that
 * does not hand its list over pays for the same page twice. The Python twin
 * gets this from `_fetch_agents`'s memo (`rine-sdk/src/rine/_client.py`); on
 * this stack the list is passed, because caching inside `rine-core` would
 * outlive a request it has no way to scope. The group fetch is the one round
 * trip this path genuinely adds, and it is paid only for a spelling that had no
 * answer at all before this function existed.
 *
 * @throws {Error} The name is an agent's, or no group of the caller's answers
 *   to it.
 */
export async function resolveBareRecipientGroup(
	client: HttpClient,
	name: string,
	extraHeaders?: Record<string, string>,
	preFetchedAgents?: AgentRead[],
): Promise<GroupRead> {
	refuseIfABareAgentName(preFetchedAgents ?? (await fetchAgents(client)), name);
	return recipientGroupForBareName(await fetchOwnGroups(client, extraHeaders), name);
}
