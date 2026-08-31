/**
 * The entry points every surface resolves a reference through.
 *
 * 🔴 **Three doors, and the caller picks by SLOT, never by guessing.** A group
 * verb's argument goes to {@link resolveGroup}; `join`'s goes to
 * {@link resolveGroupForJoin}, whose rungs look outside the org and are
 * deliberately not the member ladder's; a `send`'s recipient goes to
 * {@link resolveRecipient}, the only one of the three allowed to answer in
 * either namespace. Nothing here falls back from one door to another.
 *
 * The ladders themselves are not restated here — they are `resolve-group.ts`,
 * `resolve-group-join.ts` and `group-ref.ts`, each already the one place its
 * rungs and refusals live. What this module adds is the shape of the ANSWER
 * (`recipient-target.ts`) and the dispatch that used to be inline in
 * `rine-ts-sdk`'s private `resolveRecipient`, where three other surfaces could
 * not reach it — which is why the same bare word resolves as a group on three
 * surfaces and refuses on three others today.
 *
 * 🔴 Twin of `rine-sdk/src/rine/_recipient.py`. Same names, same order, same
 * refusals; the two stacks share no module and are bound by their tests.
 */

import type { GroupRead } from "./api-types.js";
import { isSigilGroupReference } from "./group-ref.js";
import type { HttpClient } from "./http.js";
import {
	REF_CLASS,
	type GroupTarget,
	type RecipientTarget,
	type ResolveOptions,
	classifyReference,
} from "./recipient-target.js";
import { resolveToUuid } from "./resolve-agent.js";
import {
	resolveBareRecipientGroup,
	resolveGroup,
	resolveGroupByHandle,
	resolveGroupByName,
} from "./resolve-group.js";
import { resolveGroupUuidForJoin } from "./resolve-group-join.js";
import { normalizeHandle } from "./resolve-handle.js";

export * from "./recipient-target.js";

/**
 * The member ladder, exported from here so all three entry points are imported
 * from one module.
 *
 * It is DEFINED in `resolve-group.ts`, beside its rungs and the `/groups` path
 * literals they ask, because this module imports that one: a ladder that called
 * back into here would make the two circular, and the existing tests import
 * `resolveGroupUuid` and `seatedGroupByHandle` from there by path.
 */
export { resolveGroup } from "./resolve-group.js";

/**
 * Resolve a group reference for JOIN — the one verb aimed outside the org.
 *
 * 🔴 The rungs are `resolve-group-join.ts`'s and are neither touched nor merged
 * with the member ladder: `join` is aimed at a group the caller is by
 * definition not seated in, so `GET /groups` answering nothing is its FIRST
 * rung rather than its refusal. {@link resolveGroupUuidForJoin}'s header is
 * where the reasons live.
 *
 * 🔴 It answers with `handle` and `row` UNSET, and that is the whole reason
 * `GroupTarget` has the loose shape `SeatedGroupTarget` narrows: the
 * directory rung resolves an id out of a public listing with no group row
 * behind it, and inventing one here would be a client asserting membership
 * facts it has not been told. A caller that needs the row asks for it after the
 * join lands.
 *
 * `extraHeaders` selects whose invitations are read, which on this ladder is
 * more than attribution — it is the whole of what a bare name resolves against.
 *
 * @throws {Error} No rung resolved the reference.
 */
export async function resolveGroupForJoin(
	client: HttpClient,
	ref: string,
	opts: ResolveOptions = {},
): Promise<GroupTarget> {
	const id = await resolveGroupUuidForJoin(client, ref, opts.extraHeaders);
	return { id, handle: undefined, spelling: ref, row: undefined };
}

/**
 * Resolve a `send`'s recipient, in whichever namespace its spelling names.
 *
 * The dispatch, by {@link classifyReference} and nothing else:
 *
 * | class | resolved by | answers |
 * |---|---|---|
 * | `group`, no `@` | `resolveGroupByName` | the group |
 * | `group`, with `@` | `resolveGroupByHandle` | the group |
 * | `bare` | `resolveBareRecipientGroup` | the group |
 * | `agent`, `id` | `resolveToUuid` | the agent |
 * | `empty` | `resolveToUuid` | refuses, on syntax, before any request |
 *
 * 🔴 **This widens nothing, and the argument is the classifier's.**
 * `resolveToUuid` accepts a UUID or something containing `@` and refuses
 * everything else on syntax, before any request — so `bare` and sigiled `group`
 * are exactly the spellings that were a certain refusal one line later, and the
 * worst a group ladder can do for them is replace that refusal with a better
 * one. Widen a class and that argument stops being true without a test going
 * red.
 *
 * **Why the sigil arm skips the collision guard** is `isSigilGroupReference`'s
 * to argue and is not restated here. What belongs to this call site is the dead
 * zone it closes: `#ops` used to reach neither ladder and landed on the AGENT
 * resolver's *"expected a UUID or handle …"* — a sentence that sends a model to
 * retry as `ops@…`, the misdelivery the guard exists to prevent. That sentence
 * no longer prints a domain to copy, which narrows the harm and does not
 * remove it: it still answers a group reference in the agent namespace.
 *
 * `opts.agents` is the org's agent list the caller has already fetched to
 * resolve its acting agent, handed over rather than fetched again: `fetchAgents`
 * is uncached by design, so the collision guard would otherwise pay for a page
 * the same call just read.
 *
 * 🔴 The group arms answer with the row's OWN handle, never the caller's
 * spelling: `POST /messages` looks `to_handle` up by exact equality, and the
 * handle fallback exists precisely because the two can differ. Posting the
 * spelling sends a fabricated org half, sealed for the right group and refused
 * with a bare `Group not found` (`71c2759b`).
 *
 * 🔴 **Item 18 is discharged here by the RETURN VALUE, not by a message.** The
 * agent arm completes a short handle — `kofi@acme` is looked up as
 * `kofi@acme.rine.network` — and every other call site of `resolveToUuid` had to
 * grow a printed notice because that function answers with a UUID and drops the
 * spelling it resolved. This one does not: `RecipientTarget` carries `spelling`
 * (what the caller typed) beside `handle` (what was actually addressed), so the
 * substitution is `handle !== spelling` and the caller has both strings without
 * asking. Do not "widen the notice" onto this function — a library that writes
 * to stderr has taken a decision that belongs to whoever is holding the
 * terminal. What a consumer does with the pair is the consumer's to decide;
 * `rine-cli/src/handle-completion.ts` is one such decision.
 *
 * @throws {Error} The spelling names no agent and no group of the caller's, or
 *   names an agent where a group was expected.
 */
export async function resolveRecipient(
	client: HttpClient,
	apiUrl: string,
	to: string,
	opts: ResolveOptions = {},
): Promise<RecipientTarget> {
	const { extraHeaders, agents } = opts;
	switch (classifyReference(to)) {
		case REF_CLASS.group:
			return groupRecipient(
				isSigilGroupReference(to)
					? await resolveGroupByName(client, to, extraHeaders)
					: await resolveGroupByHandle(client, to, extraHeaders),
				to,
			);
		case REF_CLASS.bare:
			return groupRecipient(
				await resolveBareRecipientGroup(client, to, extraHeaders, agents),
				to,
			);
		default:
			return agentRecipient(await resolveToUuid(apiUrl, to), to);
	}
}

/** A resolved group, as the record a `send` reads. */
function groupRecipient(row: GroupRead, spelling: string): RecipientTarget {
	return { kind: "group", id: row.id, handle: row.handle, spelling, row };
}

/**
 * A resolved agent, as the same record.
 *
 * `handle` is the normalised spelling the caller used, and is unset for a UUID
 * because there is nothing to normalise — the agent resolver answers with an id
 * and this stack does not read a handle back off the wire to fill a field.
 */
function agentRecipient(id: string, spelling: string): RecipientTarget {
	return {
		kind: "agent",
		id,
		handle: spelling.includes("@") ? normalizeHandle(spelling) : undefined,
		spelling,
		row: undefined,
	};
}
