/**
 * What a group refusal says when the acting agent simply is not seated — the
 * one clause every TypeScript surface can discriminate the SERVER's refusal by,
 * and the sentence this stack refuses with before it ever asks.
 *
 * The server's group-membership gate refuses with a sentence that names the
 * acting agent and then whichever of the caller's own agents *is* a member — a
 * remedy an operator can act on. A surface that wants to say anything other
 * than the server's own words has to recognise the refusal first, and the only
 * thing on the wire to recognise it by is the sentence: the server emits a
 * machine-readable `code` on exactly one route today, and an error-code
 * vocabulary is a protocol change nobody asked for.
 *
 * So the clause is pinned, on the model `vote-words.ts` already sets. It lives
 * in `rine-core` and not in the TypeScript SDK for that module's stated reason:
 * the CLI and the MCP server depend on core and not on the SDK, so a constant
 * that lived only in the SDK is one they could only re-declare.
 *
 * {@link unseatedGroupSendRefusal} is the other direction: a refusal this stack
 * WRITES rather than reads, for the one seat check a client makes on its own
 * (`sender-key-ops.ts`). It is here because this is where the vocabulary lives
 * and, more sharply, because it is the one sentence in the package that must
 * NOT satisfy {@link namesASeatedSibling} — a constraint that is only obvious
 * beside the predicate it would otherwise claim.
 */

import { ACTOR_SURFACES } from "./actor.js";

/**
 * The clause every arm of the not-a-member refusal opens with.
 *
 * 🔴 Byte-identical to the Python twin `rine.group_words.NOT_A_MEMBER_CLAUSE`
 * and to the server's own `rine.api.group_member_words`, which
 * `tests/test_client-server-contract_group0.py` pins all three against. A
 * second wording is how a surface comes to miss a refusal it was written to
 * recognise, so this changes in every stack or in none.
 *
 * It is a SUBSTRING of a refusal, not a wire enum — match it with `includes`,
 * never with equality, and never reconstruct the whole sentence from it. The
 * rest of the sentence names agents and is therefore different on every call.
 *
 * What it is for: telling "your acting agent holds no seat here, but another of
 * your agents does" apart from "you were removed from this group". Both are
 * `403`s on a group route, they are opposite facts, and a surface that reads
 * the first as the second tells an operator its keys are dead when the fix is
 * one header.
 */
export const NOT_A_MEMBER_CLAUSE = "is not a member of this group";

/**
 * The clause the two arms that name a seated sibling carry, and the third does
 * not.
 *
 * {@link NOT_A_MEMBER_CLAUSE} identifies the refusal FAMILY; this identifies
 * the ARM. The server writes three: one of your agents is seated (act as it),
 * several are (pick one), or none is. The first two end in this instruction —
 * "retry with `X-Rine-Agent`: …" — and the third cannot, because there is
 * nobody to retry as.
 *
 * That distinction is the whole reason a surface reads the sentence at all. An
 * agent holding local MLS state for a group it may no longer read was evicted
 * from it; an agent whose sibling holds the seat never was. Both are `403`s in
 * one family, and a surface that only matched the family would answer one with
 * the other's remedy.
 *
 * 🔴 One string literal, byte-identical to the server's
 * `rine.api.group_member_words.SEATED_SIBLING_CLAUSE` (composed there from the
 * header constant) and pinned against it by
 * `tests/test_client-server-contract_group0.py`. The header spelling inside it
 * is bound to {@link ACTING_AGENT_HEADER} by this package's own test rather
 * than by interpolation, because the gate reads a plain literal.
 */
export const SEATED_SIBLING_CLAUSE = "retry with X-Rine-Agent";

/**
 * Whether a refusal is "your acting agent holds no seat, but another of your
 * agents does".
 *
 * Both clauses, never one: the family alone matches the arm that says no agent
 * of the org is seated, which is what a genuinely evicted agent reads.
 *
 * @param detail - A `RineApiError`'s `detail`, forwarded whole.
 */
export function namesASeatedSibling(detail: string): boolean {
	return (
		detail.includes(NOT_A_MEMBER_CLAUSE) && detail.includes(SEATED_SIBLING_CLAUSE)
	);
}

/**
 * The spellings that name the acting agent, each ATTRIBUTED to the surface that
 * takes it.
 *
 * Composed from {@link ACTOR_SURFACES} rather than typed out, on the model the
 * server sets by composing `SEATED_SIBLING_CLAUSE` from its header constant: a
 * refusal that names a lever renames itself when the lever is renamed.
 *
 * 🔴 `RINE_AGENT` is deliberately absent, and that is the rule `actor.ts`
 * states — a refusal may only advertise a rung the caller can reach. Two of the
 * five surfaces this sentence reaches (the TypeScript SDK, and `rine-mastra`
 * through it) read no environment by design, so naming the variable would send
 * those readers to a lever that does nothing at all.
 *
 * 🔴 The attribution is that same rule, applied in the direction it was first
 * missed. This sentence is composed in `rine-core`, which every surface reaches
 * through `getOrCreateSenderKey`, so it has no surface to branch on and
 * must name them all — and an unattributed union (`--agent or agent`) offered
 * `--agent` to the TypeScript SDK, `rine-mastra` and `rine-eve`, none of which
 * has a flag at all, while leaving the reader to guess which of the two was
 * theirs. Naming the owner of each spelling costs four words and takes the
 * guess away. The non-CLI half stays a deduplicated set rather than one
 * surface's constant, so a day when `rine-mcp` and the TypeScript SDK stop
 * agreeing prints both instead of quietly printing one.
 */
const NON_CLI_ACTOR_SPELLINGS = [
	...new Set(
		Object.entries(ACTOR_SURFACES)
			.filter(([surface]) => surface !== "cli")
			.map(([, s]) => s.canonical),
	),
].join(" or ");

const ACTOR_SPELLINGS =
	`${ACTOR_SURFACES.cli.canonical} on the rine CLI, ` +
	`${NON_CLI_ACTOR_SPELLINGS} on every other surface`;

/**
 * Which of the caller's own agents hold a seat, as one clause.
 *
 * Three arms, on the model of the server's own three, because the remedy
 * differs and a sentence promising the wrong one is worse than no sentence.
 * `null` is the arm the server has no twin for: this refusal is composed by a
 * CLIENT, so "your org has no seat here" and "this client could not find out"
 * are genuinely different answers, and only the first may claim there is
 * nobody to act as.
 */
function seatedClause(seated: readonly string[] | null): string {
	if (seated === null) {
		return (
			"rine could not read your org's agent list, so it cannot say which of " +
			"your agents is seated there: read the group's members and send again " +
			"as one of yours that is listed."
		);
	}
	if (seated.length === 0) {
		return (
			"No agent of your org holds a seat there either, so there is nobody to " +
			"send as: a member must invite one of your agents before this org can " +
			"post to the group."
		);
	}
	return (
		`Agents of your org seated there: ${seated.join(", ")}. Send this message ` +
		`again as one of them: the acting agent is chosen with ${ACTOR_SPELLINGS}.`
	);
}

/**
 * What a Sender Keys group send says when the acting agent holds no seat.
 *
 * The refusal a client makes for itself, before the first write. It replaced
 * eight words — *"You are not a member of this group"* — that named no group,
 * no seated sibling and no remedy, on the same path where the Python SDK's
 * `refuse_if_not_seated` names all three. Four clauses in the order
 * `sender-key-words.ts` set: what was refused, the fact behind it, what to do
 * instead, and what did and did not happen to the world. The last one is not
 * decoration — this throw is what stops a sender key being fanned out to every
 * member of a group the caller cannot post to, so "nothing was sent" is a
 * property of where it is raised.
 *
 * 🔴 **It may not contain {@link NOT_A_MEMBER_CLAUSE}, and it does not.** That
 * phrase is a PREDICATE on two stacks — `rine-mcp`'s eviction re-wording reads
 * it through {@link namesASeatedSibling}, and the three Python wrappers read it
 * through `rine.group_words.is_not_a_member` — so a client sentence that
 * adopted it would silently claim a branch written about the server's refusal,
 * with every suite green. `holds no seat` says the same fact in the vocabulary
 * the rest of the product already uses for it.
 *
 * @param refusal.group - The group as the caller addressed it, never its UUID:
 * a handle is the value that can be re-sent to.
 * @param refusal.agent - The acting agent's id, as this call resolved it.
 * @param refusal.seated - The caller's own seated agents, spelled as
 * `X-Rine-Agent` accepts them, or `null` when this client could not find out.
 * An empty array is an answer; `null` is the absence of one.
 */
export function unseatedGroupSendRefusal(refusal: {
	group: string;
	agent: string;
	seated: readonly string[] | null;
}): string {
	return [
		`Refusing to send to ${refusal.group}: agent ${refusal.agent} holds no` +
			" seat in that group.",
		seatedClause(refusal.seated),
		"Nothing was sent, and no sender key was distributed.",
	].join(" ");
}
