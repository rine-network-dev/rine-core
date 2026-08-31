import type { AgentRead } from "./api-types.js";
import {
	type RefusalCandidates,
	type RefusalLead,
	composeGroupRefusal,
} from "./recipient-refusal.js";

/**
 * The acting-agent contract, in the one place every TypeScript surface reads it.
 *
 * Before this module the wire header was retyped at ~50 sites across four
 * packages, the env var was read raw at five more, and two refusals in
 * `resolve-agent.ts` disagreed about which two columns of an agent to print. A
 * name that is spelled in fifty places is a name nobody can change; a refusal
 * that prints UUIDs in one arm and names in the other teaches the reader a
 * remedy the other arm does not accept.
 *
 * It lives in `rine-core` for the reason `vote-words.ts` does: the CLI and the
 * MCP server depend on core and not on the SDK, so a constant that lived only
 * in the SDK is one they could only re-declare.
 *
 * 🔴 **Reading `RINE_AGENT` is opt-in, and that is a correctness property.**
 * `actorFromEnv()` is the only environment read on this stack, and only a
 * *surface* calls it. `resolveAgent()` never does. `rine-mastra` builds a bare
 * SDK client for an operator-fixed actor, so an ambient `RINE_AGENT` reaching
 * it would silently re-actor every call it makes — a regression that was
 * written once and reverted. Keep the read here, and keep it opt-in.
 */

/** The wire header naming which of an org's agents a request acts as. */
export const ACTING_AGENT_HEADER = "X-Rine-Agent";

/** The environment variable naming the acting agent, on every surface. */
export const ACTING_AGENT_ENV = "RINE_AGENT";

/**
 * How one surface spells the acting agent, for the sentences it has to print.
 *
 * Three fields rather than one because a refusal uses them in different slots:
 * `canonical`/`alias` label the two values in a disagreement, `flagHint` tells
 * a caller how to choose.
 */
export interface ActorSurface {
	/** The canonical spelling, as the caller types it: `--agent`, `agent`. */
	readonly canonical: string;
	/**
	 * The retired spelling this surface still tolerates: `--as`, `as`.
	 *
	 * Absent on a surface that never had one. That absence records a fact rather
	 * than changing a sentence: {@link singleActorValue} still falls back to
	 * `canonical` so the refusal is never malformed, but a surface with no
	 * retired spelling passes no second value either, so the pairwise refusal is
	 * unreachable there and the fallback never renders.
	 */
	readonly alias?: string;
	/** How the refusal says to choose one. */
	readonly flagHint: string;
	/**
	 * Whether this surface reads `RINE_AGENT` (rung 3).
	 *
	 * 🔴 A refusal may only advertise a rung the caller can actually reach. The
	 * TypeScript SDK reads no environment by design (see the header comment), so
	 * telling its callers to "set RINE_AGENT" sends them to a lever that does
	 * nothing — they export it, re-run, and get the identical refusal.
	 */
	readonly readsEnv: boolean;
}

/**
 * The spellings of the three TypeScript surfaces.
 *
 * `send --from` is `cli` with `alias` overridden — spread it, do not mint a
 * fourth entry. The Python stack holds its own (`rine-sdk/_resolve.py`).
 */
export const ACTOR_SURFACES = {
	cli: {
		canonical: "--agent",
		alias: "--as",
		flagHint: "--agent",
		readsEnv: true,
	},
	mcp: {
		canonical: "agent",
		alias: "as",
		flagHint: "the agent parameter",
		readsEnv: true,
	},
	ts: { canonical: "agent", flagHint: "agent", readsEnv: false },
} as const satisfies Record<string, ActorSurface>;

/**
 * The one normalisation rule for an actor value, applied once per rung.
 *
 * Trims, and treats empty-after-trim as *absent* so the rung falls through
 * rather than refusing: `rine-eve`'s scaffolder writes a bare `RINE_AGENT=`
 * line into every generated project, so an empty value is the shipped shape of
 * "no actor set". No case folding — bare names already match
 * case-insensitively and handles normalise in `normalizeHandle`, so a third
 * rule here could only disagree with them.
 *
 * A non-string that is not null/undefined refuses rather than stringifying:
 * `String({})` is `"[object Object]"`, and hunting for an agent by that name
 * either finds nobody or, worse, finds somebody.
 */
export function normalizeActor(value: unknown): string | undefined {
	if (value === undefined || value === null) return undefined;
	if (typeof value !== "string") {
		throw new Error(
			`The acting agent must be a name, handle or UUID (got ${typeof value}).`,
		);
	}
	const trimmed = value.trim();
	return trimmed === "" ? undefined : trimmed;
}

/**
 * Rung 3 of the ladder: the acting agent named by the environment.
 *
 * 🔴 The only `RINE_AGENT` read on the TypeScript stack. Call it from a
 * surface, never from a library path an SDK client can reach.
 */
export function actorFromEnv(): string | undefined {
	return normalizeActor(process.env[ACTING_AGENT_ENV]);
}

/**
 * Which rung an actor value came off — the lever the caller can actually move.
 *
 * 🔴 It exists because {@link ignoredActorWarning} tells a caller what to do
 * next, and rungs 1 and 3 have different answers: "omit the parameter" is
 * unfollowable advice for somebody who passed no parameter, and on a one-agent
 * org that warning is the ONLY channel a stale `RINE_AGENT` has — the refusal
 * that used to carry it no longer happens. Typed rather than a string
 * prefix stitched on by the caller, so the two arms are one sentence each,
 * written once, and a third rung has to declare itself.
 */
export type ActorOrigin = "argument" | "environment";

/**
 * A resolved acting agent, and anything the caller has to be told about how it
 * was reached.
 *
 * 🔴 **A per-call value, never a mutable attribute on a shared client.** One
 * `AsyncRineClient` serves a whole eve/mastra process handling concurrent
 * inbound webhooks, and a `lastActorWarning` written while resolving one call
 * is read by whichever call happens to finish next — the warning then names the
 * wrong send, or is overwritten and lost. `AsyncLocalStorage` is the same shape
 * with the failure hidden, and eve runs on runtimes where it is not dependable.
 * So the warning rides the return value, and a surface that wants it resolves
 * once, explicitly, before the operation.
 *
 * The twin of the Python stack's `rine-sdk/src/rine/_actor.py::ResolvedActor`;
 * `agentId`/`agent_id` are deliberate twins the way `ACTING_AGENT_HEADER` is.
 */
export interface ResolvedActor {
	readonly agentId: string;
	readonly warning?: string;
	/**
	 * The org's agent list this answer was read off, when the resolver fetched
	 * one — the seam a caller hands on as `ResolveOptions.agents`.
	 *
	 * 🔴 It is here so a surface that resolves an ACTOR and then resolves a bare
	 * RECIPIENT pays `GET /agents` once instead of twice: `fetchAgents` is
	 * uncached by design, and `refuseIfABareAgentName`'s collision guard reads the
	 * very same org-scoped page the actor ladder just read. A memo inside
	 * `rine-core` is not the alternative — it would outlive a request this package
	 * has no way to scope — so the list rides the value the caller already holds.
	 *
	 * 🔴 **Set by `resolveActor` alone, and only on the rung that fetched.** Its
	 * UUID rung answers without reading a roster at all, and `resolveAgent` is
	 * handed the list by its own caller, who therefore already has it. So absent
	 * means *"this resolver read no list for you"*, never *"this org has no
	 * agents"* — a reader fetches for itself and is never handed a list that was
	 * invented, stale, or another org's.
	 *
	 * The Python twin (`rine-sdk/src/rine/_actor.py`) carries no such field and
	 * needs none: both clients memoise `_fetch_agents` per client, so the second
	 * read is already free there.
	 */
	readonly agents?: AgentRead[];
}

/**
 * The warning as the key a JSON tool result carries it under, or nothing.
 *
 * Spread into a result object (`{ ...actorNote(acting), ...body }`) so the
 * successful answer is unchanged when there is nothing to say — an empty
 * `warning: undefined` key would show a model a field that means nothing.
 */
export function actorNote(resolved: ResolvedActor): { warning?: string } {
	return resolved.warning === undefined ? {} : { warning: resolved.warning };
}

/**
 * One agent, in the one column set every refusal on both stacks prints.
 *
 * Extracted from {@link formatActorList} because the one-agent warning names a
 * single agent inline and must not mint a second column set beside the list's.
 *
 * `handle` is nullable on the wire (`POST /agents` only mints one when the org
 * has a slug), and a refusal that names an agent by `null` names it by nothing
 * the wire accepts. The UUID is the other value `X-Rine-Agent` takes, which is
 * why the server's twin falls back to exactly it.
 */
export function actorLabel(agent: AgentRead): string {
	return `${agent.name} (${agent.handle ?? agent.id})`;
}

/**
 * The org's agents, one per line, in the one column set every stack prints.
 *
 * Module-private on purpose: the four refusals below are the only ways this
 * list reaches a user, and a caller outside this file would mint a fifth
 * wording beside them — the drift this module exists to stop.
 */
function formatActorList(agents: readonly AgentRead[]): string {
	return agents.map((a) => `  - ${actorLabel(a)}`).join("\n");
}

/**
 * How a refusal tells the caller to choose, in the one place both refusals that
 * say it read from.
 *
 * 🔴 A refusal may only advertise a rung the caller can actually reach, so the
 * `RINE_AGENT` half drops on a surface that reads no environment
 * ({@link ActorSurface.readsEnv}).
 */
export function nameOneOfThem(surface: ActorSurface): string {
	const env = surface.readsEnv ? `, or set ${ACTING_AGENT_ENV}` : "";
	return `Name one of them with ${surface.flagHint}${env}.`;
}

/**
 * What a refusal says instead of the roster when the org has no agent at all.
 *
 * One constant because two refusals end on it, and a caller comparing them is
 * comparing this stack against a Python twin that reads the same sentence out
 * of one place too (`rine-sdk/src/rine/_actor.py`).
 */
const NO_AGENTS_IN_ORG = "No active agents in this org.";

/**
 * One refusal's tail: the org's agents, or the reason there are none.
 *
 * 🔴 The zero-agent branch is the half a hand-rolled copy always drops.
 * {@link formatActorList} renders an empty org as the empty string, so a
 * refusal that appends it unconditionally ends *"Available agents:"* and then
 * simply stops — a sentence that trails off exactly where the caller most needs
 * to be told there is nothing to choose from. Every refusal that names a
 * spelling and then the roster ends here, so no spelling can lose it again.
 *
 * 🔴 The roster this renders over is **0 or ≥2 agents, never 1**, and that is a
 * property of {@link ResolvedActor}'s resolver rather than of this function: a
 * one-agent org resolves any value to that agent and warns, so it never reaches
 * a refusal. That is what makes the multi-agent clause below unconditionally
 * true. A caller that hand-rolls a one-agent roster into here gets a sentence
 * that is false; there is no such caller, and no arm is written for one.
 *
 * Word-for-word the Python twin's `_and_the_agents_there_are`
 * (`rine-sdk/src/rine/_actor.py`).
 *
 * The sentences are this module's; the JOINS are {@link composeGroupRefusal}'s,
 * shared with the group roster so the two cannot drift apart in the one place
 * they were never compared — their punctuation.
 */
function actorCandidates(
	agents: readonly AgentRead[],
	surface: ActorSurface,
	rosterLead: string,
): RefusalCandidates {
	return {
		rows: formatActorList(agents),
		rosterLead,
		whenEmpty: NO_AGENTS_IN_ORG,
		after: nameOneOfThem(surface),
	};
}

function andTheAgentsThereAre(
	lead: RefusalLead,
	spelling: string,
	agents: readonly AgentRead[],
	surface: ActorSurface,
): string {
	return composeGroupRefusal({
		lead,
		spelling,
		candidates: actorCandidates(
			agents,
			surface,
			"This org has more than one agent, so a call has to name one. Available agents:",
		),
	});
}

/**
 * Told to a caller whose named actor was ignored because the org has exactly
 * one agent — on an otherwise **successful** result, never as a refusal.
 *
 * 🔴 It fires only when the value did *not* name that agent. That is automatic
 * rather than checked: the fallback lives on the resolver's failure path, so a
 * value that resolved never reaches it. Warning on a correct call would teach a
 * model that correct behaviour produces complaints.
 *
 * It echoes the value it was given because the caller cannot see their own typo
 * otherwise — and the measured defect was a model filling this slot with the
 * schema's own placeholder text, which only reads as a mistake once it is
 * quoted back.
 *
 * 🔴 `origin` decides which lever the closing clause names, and it is not
 * cosmetic: a value that came off rung 3 was never in the call at all, so
 * "omit the parameter" names something the caller did not do and withholds the
 * only actionable fact there is — that `RINE_AGENT` is stale. See
 * {@link ActorOrigin}.
 */
export function ignoredActorWarning(
	given: string,
	agent: AgentRead,
	surface: ActorSurface = ACTOR_SURFACES.cli,
	origin: ActorOrigin = "argument",
): string {
	const lever =
		origin === "environment"
			? `${ACTING_AGENT_ENV}='${given}'`
			: `${surface.canonical} '${given}'`;
	const next =
		origin === "environment"
			? `${ACTING_AGENT_ENV} names no agent this org has — unset it, or point ` +
				`it at one that exists.`
			: `Omit ${surface.canonical} for a one-agent org.`;
	return `Ignored ${lever}: this org has one agent, so ${actorLabel(agent)} acted. ${next}`;
}

/**
 * Told to a caller who named no agent in an org that has more than one.
 *
 * 🔴 The one refusal here with no spelling to quote — the caller named nothing,
 * which is what it is refusing — so it carries no lead and its whole first
 * sentence introduces the roster. That is also why the empty-org arm is a
 * complete sentence on its own rather than a tail: there is no opening for it
 * to hang off.
 */
export function actorRefusal(
	agents: readonly AgentRead[],
	surface: ActorSurface,
): string {
	return composeGroupRefusal({
		lead: () => "",
		spelling: "",
		candidates: actorCandidates(
			agents,
			surface,
			"This org has more than one agent. Say which one is acting:",
		),
	});
}

/**
 * Told to a caller who named an agent this org does not have.
 *
 * 🔴 **The same sentence whether the value was `null` or a misspelled
 * colleague.** A hardcoded bogus-word list decided nothing here and was
 * deleted: on a one-agent org the value is resolved to that agent before any
 * refusal is reachable, and on a multi-agent org the caller named something
 * this org does not have either way. The value is echoed so the caller can see
 * their own typo; what changes the outcome is the roster, never the vocabulary.
 */
export function unknownActorRefusal(
	agents: readonly AgentRead[],
	name: string,
	surface: ActorSurface = ACTOR_SURFACES.cli,
): string {
	return andTheAgentsThereAre(
		(said) => `No agent named '${said}'.`,
		name,
		agents,
		surface,
	);
}

/**
 * Told to a caller whose *handle*-spelled actor this org does not own.
 *
 * The twin of {@link unknownActorRefusal}, and it exists because an acting
 * agent must be an agent the caller owns: a handle is looked up in the caller's
 * own agent list exactly as a bare name is, so a handle that is nobody here
 * gets the same sentence with the spelling the caller actually used. Before
 * this, a handle went to WebFinger and a miss answered *"Ensure WebFinger is
 * available or use a UUID"* — infrastructure advice for a typo, naming no
 * agent, and a WebFinger *hit* was worse: it returned a foreign org's agent id.
 *
 * Word-for-word the sentence the Python stack raises from
 * `_refuse_unresolved_actor`'s handle arm (`rine-sdk/src/rine/_resolve.py`), so
 * one mistake gets one sentence on both stacks — including the empty-org arm,
 * which is {@link andTheAgentsThereAre}'s on this side and
 * `_and_the_agents_there_are`'s on that one.
 */
export function unknownHandleRefusal(
	agents: readonly AgentRead[],
	handle: string,
	surface: ActorSurface = ACTOR_SURFACES.cli,
): string {
	return andTheAgentsThereAre(
		(said) => `No agent with handle '${said}'.`,
		handle,
		agents,
		surface,
	);
}

/**
 * Told to a caller whose bare name names more than one agent.
 *
 * A bare name is **not** unique in an org, and nothing on the server makes it
 * so: `agents.name` carries no unique index (`src/rine/db/models.py` indexes
 * `handle`, never `name`), `POST /agents`' duplicate check is a case-sensitive
 * count-then-insert, `PATCH /agents/{id}` renames with no duplicate check at all
 * in a slugless org, and `GET /agents` has no `ORDER BY`. So the list this
 * matched against is unordered and can hold two agents whose names differ only
 * in case — which the matcher folds together.
 *
 * Taking the first match would name an identity the caller did not choose,
 * silently and non-deterministically, on a request that acts as it. The
 * candidates print in the one column set every refusal here uses, whose
 * fallback is the UUID — the spelling that still tells two agents apart when
 * the org has no slug and neither of them has a handle.
 */
export function ambiguousActorRefusal(
	matches: readonly AgentRead[],
	name: string,
): string {
	return composeGroupRefusal({
		lead: (said) => `More than one agent is named '${said}'`,
		spelling: name,
		candidates: {
			rows: formatActorList(matches),
			rosterLead: "Say which one is acting:",
			// 🔴 No `whenEmpty`, and it is not an omission. `matches` is what
			// `resolveAgent` found for one name behind `matches.length > 1`
			// (`resolve-agent.ts`), so this refusal has never had an empty-roster
			// arm — and `@rine-network/core` exports it, so giving it one moved a
			// byte of published output for an input our own callers cannot make.
			// Rule 3 has nothing to suppress either: the line below says how to
			// tell the candidates apart, it names no verb that would list them.
			after: "A name is not unique in an org — name it by handle or UUID.",
		},
	});
}

/**
 * The conflict rule, whole: two actor values on the *same rung* must agree.
 *
 * Returns the one value both spellings name, or `undefined` when neither was
 * given. Refuses when they disagree, naming both — no precedence rule silently
 * picks a winner, because the loser is an identity the caller believed they
 * were acting as.
 *
 * Only same-rung pairs reach here. A flag beating `RINE_AGENT`, or a per-call
 * agent beating a client default, is *precedence* and stays silent.
 *
 * Disagreement is a literal comparison after {@link normalizeActor},
 * case-insensitive — never resolve-then-compare. Resolving first would spend up
 * to two network round trips before it could decide to refuse, could fail on
 * the second value with a different error entirely, and would make the refusal
 * non-deterministic offline. The cost is that naming one agent twice, once by
 * name and once by handle, is refused; the refusal says exactly that happened.
 */
export function singleActorValue(
	explicit: unknown,
	alias: unknown,
	surface: ActorSurface = ACTOR_SURFACES.cli,
): string | undefined {
	const first = normalizeActor(explicit);
	const second = normalizeActor(alias);
	if (first === undefined) return second;
	if (second === undefined) return first;
	if (first.toLowerCase() !== second.toLowerCase()) {
		throw new Error(
			`You named the acting agent twice: ${surface.canonical} ${first} and ` +
				`${surface.alias ?? surface.canonical} ${second}.\nName it once.`,
		);
	}
	return first;
}
