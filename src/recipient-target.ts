/**
 * What a caller's string names, and what a resolver answers with.
 *
 * 🔴 **One classification table, two implementations.** The Python twin is
 * `rine-sdk/src/rine/_recipient.py`; the table below is derived from the
 * server's own discriminator — `POST /messages` branches on
 * `to_handle.startswith("#")` before it touches the database
 * (`src/rine/api/messages.py`) — so a client that classified differently would
 * be describing a routing rule the server does not run.
 *
 * The two records live here rather than beside the resolvers because both
 * stacks' resolvers are spread over several modules and a record declared next
 * to one of them is a record the others re-declare. Nothing here performs I/O
 * or holds a path literal.
 */

import type { AgentRead, GroupRead } from "./api-types.js";
import { UUID_RE } from "./resolve-handle.js";

/**
 * The five things a caller-supplied reference can be, by spelling alone.
 *
 * An object rather than a bare union so the five names exist as VALUES a
 * `switch` can be written against and a test can enumerate — a union of string
 * literals is invisible at runtime, and the measured failure this contract
 * exists for is a caller inventing a sixth spelling nobody can grep for.
 */
export const REF_CLASS = {
	empty: "empty",
	group: "group",
	id: "id",
	agent: "agent",
	bare: "bare",
} as const;

/** One of {@link REF_CLASS}'s five values. */
export type RefClass = (typeof REF_CLASS)[keyof typeof REF_CLASS];

/**
 * Which namespace a reference names, on syntax alone, before any request.
 *
 * 🔴 **The order of the tests is the contract, not an implementation detail.**
 * `id` is asked BEFORE `@` and AFTER `#`. A UUID carries no `@`, so the second
 * of those is not observable today — it is pinned so the two stacks cannot
 * drift the day `UUID_RE` widens on one of them. Both stacks already carry a
 * LOOSER uuid predicate than this one asks — `parsesAsUuid`
 * (`resolve-handle.js`) and its twin `rine._resolve.parses_as_uuid`, which
 * accept the dashless, `urn:` and braced spellings the wire accepts — and
 * classification deliberately does not use it. Whether it should is an open
 * question; do not widen this test to close it.
 *
 * 🔴 **It never crosses namespaces.** There is no "try agent, then try group":
 * the caller declares the namespace by choosing a verb or a slot, and this
 * answers only what the string looks like. A wrong group resolution is refused
 * by the server's seat gate; a wrong agent resolution DELIVERS
 * (`src/rine/api/messages.py::_enforce_send_policies`), which is why the two
 * halves are never allowed to guess about each other.
 *
 * Empty is a class rather than a refusal because the refusal belongs to the
 * slot: a blank recipient is answered by the agent resolver's *"expected a UUID
 * or handle"*, and a blank group reference by the group ladder. One classifier,
 * two sentences, neither of them written here.
 */
export function classifyReference(value: string): RefClass {
	if (value.trim() === "") return REF_CLASS.empty;
	if (value.startsWith("#")) return REF_CLASS.group;
	if (UUID_RE.test(value)) return REF_CLASS.id;
	if (value.includes("@")) return REF_CLASS.agent;
	return REF_CLASS.bare;
}

/**
 * A group a reference resolved to, and the spelling it was reached by.
 *
 * `handle` is what goes on the wire: `POST /messages` looks `to_handle` up by
 * exact equality, so a resolver that answered with an id alone re-opens the
 * hole `71c2759b` closed — the caller seals for the group the ladder found and
 * then posts the spelling it typed.
 *
 * `spelling` is the caller's own argument, byte for byte — never the local part
 * a fallback matched on, never a normalised form. It is the only string a
 * refusal may quote back.
 *
 * `row` exists so a renderer never re-reads what the resolve already fetched.
 */
export interface GroupTarget {
	readonly id: string;
	/** Absent only where the ladder never had a row to read it from. */
	readonly handle: string | undefined;
	readonly spelling: string;
	/** Absent only where no row was fetched. */
	readonly row: GroupRead | undefined;
}

/**
 * The narrower record every rung of the MEMBER ladder can answer with.
 *
 * The guarantee `GroupTarget` cannot state on its own — *"`resolveGroup`
 * returns `handle` and `row` always"* — written as a type rather than as a
 * comment, so a caller that needs the handle does not carry a non-null
 * assertion and a future rung cannot quietly stop supplying one. The join
 * ladder is why the loose shape exists at all: its directory rung answers with
 * an id and nothing else.
 */
export interface SeatedGroupTarget extends GroupTarget {
	readonly handle: string;
	readonly row: GroupRead;
}

/**
 * What a `send`'s recipient slot resolved to, in either namespace.
 *
 * `kind` is the answer to the question no entry point on this stack used to
 * ask: the same bare word resolves as a group on three surfaces and refuses on
 * three others, decided by which package the caller happens to be wired to.
 */
export interface RecipientTarget {
	readonly kind: "agent" | "group";
	readonly id: string;
	readonly handle: string | undefined;
	readonly spelling: string;
	readonly row: GroupRead | undefined;
}

/**
 * What a resolve may be given besides the reference itself.
 *
 * One object rather than three positional parameters: today's call sites pass
 * `extraHeaders` in three different slots, and a fourth optional positional
 * would be the one a caller fills with the wrong value.
 *
 * `agents` is the org's agent list the caller has already fetched to resolve
 * its acting agent. `fetchAgents` is uncached by design, so a bare recipient's
 * collision guard would otherwise pay for a page the same call just read. Where
 * a surface gets it: `ResolvedActor.agents` (`actor.ts`), which is the same
 * page `resolveActor` read one step earlier — never a second fetch, and never a
 * list assembled at the call site.
 */
export interface ResolveOptions {
	/** Carries `X-Rine-Agent`. Attribution — the group routes are org-scoped. */
	readonly extraHeaders?: Record<string, string>;
	/** The org's agents, already fetched, for the bare-recipient guard. */
	readonly agents?: AgentRead[];
}
