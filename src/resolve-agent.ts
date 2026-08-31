import {
	ACTOR_SURFACES,
	type ActorOrigin,
	type ActorSurface,
	type ResolvedActor,
	actorFromEnv,
	actorRefusal,
	ambiguousActorRefusal,
	ignoredActorWarning,
	singleActorValue,
	unknownActorRefusal,
	unknownHandleRefusal,
} from "./actor.js";
import type { AgentRead, ListResponse } from "./api-types.js";
import type { HttpClient } from "./http.js";
import { UUID_RE, normalizeHandle, resolveHandleViaWebFinger } from "./resolve-handle.js";

/**
 * What {@link resolveToUuid} says to a spelling that is neither a UUID nor a handle.
 *
 * A function rather than an inline template for one reason, and it is the gate
 * and not taxonomy: the cross-stack gate's fixture takes pure input → sentence,
 * and {@link resolveToUuid} is async and reaches WebFinger on its other arm, so
 * an inline literal here can be compared across the two stacks by nothing. That
 * is exactly how a one-byte divergence — this sentence terminated on TypeScript
 * and unterminated on Python — survived with every suite green. The Python
 * twin is `invalid_agent_identifier` (`rine-sdk/src/rine/_resolve.py`), which
 * is also where the two raise sites of one sentence stop being two copies of
 * it.
 *
 * 🔴 A placeholder domain may teach a spelling in a tool DESCRIPTION and
 * may never appear in a REFUSAL. `kofi@acme.rine.network` used to stand here,
 * and what a model does with it was measured: the local part moved
 * with the conversation, the domain did not move at all. A `<slot>` is not the
 * alternative — `check-model-facing-examples.mjs`'s `template-org` rule forbids
 * it for the same reason, one measurement earlier. So the sentence names the
 * three PARTS of a handle instead of printing one, which is the only form that
 * can be neither copied nor filled in wrong. `expected a UUID or handle` is
 * preserved verbatim because four assertions read it as a substring; the tail
 * is what moved.
 */
export function invalidAgentIdentifierRefusal(value: string): string {
	return `Invalid agent identifier '${value}': expected a UUID or handle written in full — an agent's name, an at sign, and its org's domain.`;
}

/**
 * Resolve a value that may be a UUID or a handle (containing @) to a UUID.
 * Handles are resolved via WebFinger.
 *
 * 🔴 **The recipient / invitee / target resolver, and nothing else.** WebFinger
 * asks the world *who owns this handle* — a question about somebody else's org,
 * which is the point for a DM recipient, an invitee or a directory lookup. It is
 * the wrong question for the *acting* agent, which must be an agent the caller
 * owns: {@link resolveAgent} answers that one against the caller's own agent
 * list and never comes here. Mixing the two was the shipped bug — a miss blamed
 * the caller's WebFinger for a typo, and a hit acted as a foreign org's agent.
 */
export async function resolveToUuid(apiUrl: string, value: string): Promise<string> {
	if (!value.includes("@")) {
		if (UUID_RE.test(value)) return value;
		throw new Error(invalidAgentIdentifierRefusal(value));
	}
	const normalized = normalizeHandle(value);
	const resolved = await resolveHandleViaWebFinger(apiUrl, normalized);
	if (!UUID_RE.test(resolved)) {
		throw new Error(
			`Cannot resolve handle "${normalized}" to agent ID. Ensure WebFinger is available or use a UUID.`,
		);
	}
	return resolved;
}

/** Fetch the org's agent list. Pure function — no caching. */
export async function fetchAgents(client: HttpClient): Promise<AgentRead[]> {
	const data = (await client.get("/agents")) as ListResponse<AgentRead>;
	return data.items;
}

/**
 * The agent one actor value names, under whichever spelling it used, or `null`
 * when this org has nobody by that name or handle.
 *
 * 🔴 **The one matcher, and it answers rather than refusing.** A miss is a
 * verdict {@link resolveAgent} owns — on a one-agent org it falls back to that
 * agent, on any other roster it refuses — so wrapping a raiser in a `try` to
 * discover "no match" would make the fallback exception-driven control flow and
 * would swallow the ambiguity refusal below with it. The Python twin is
 * `rine-sdk/src/rine/_resolve.py::_find_in_agents`.
 *
 * A bare name collects **every** match and refuses on more than one. A bare
 * name is not unique in an org — {@link ambiguousActorRefusal} documents the
 * four ways a duplicate is reachable on today's server — and this answer decides
 * which identity a request *acts as*, so a silent pick between two candidates is
 * a wrong identity rather than a slow one. That refusal is the one miss this
 * function still raises, because "two agents answer to this" is not a miss.
 *
 * Both spellings of a short-form handle match the stored one: the wanted handle
 * and each candidate go through {@link normalizeHandle} (`bot@acme` →
 * `bot@acme.rine.network`) before they are compared, so widening that rung did
 * not make the short form the one spelling that refuses. `handle` is nullable on
 * the wire — `POST /agents` mints one only when the org has a slug — and an
 * agent with no handle matches no handle.
 */
function findInAgents(agents: AgentRead[], target: string): string | null {
	if (target.includes("@")) {
		const want = normalizeHandle(target).toLowerCase();
		const match = agents.find(
			(a) => a.handle && normalizeHandle(a.handle).toLowerCase() === want,
		);
		return match ? match.id : null;
	}
	const lower = target.toLowerCase();
	const matches = agents.filter((a) => a.name.toLowerCase() === lower);
	const first = matches[0];
	if (first === undefined) return null;
	if (matches.length > 1) throw new Error(ambiguousActorRefusal(matches, target));
	return first.id;
}

/**
 * The refusal for an actor value that named nobody, in the caller's own
 * spelling.
 *
 * 🔴 Reachable only over a roster of **0 or ≥2** agents — a one-agent org falls
 * back before it gets here — which is exactly what makes the multi-agent clause
 * inside those two sentences true.
 */
function refuseUnresolvedActor(
	agents: AgentRead[],
	target: string,
	surface: ActorSurface,
): never {
	throw new Error(
		target.includes("@")
			? unknownHandleRefusal(agents, target, surface)
			: unknownActorRefusal(agents, target, surface),
	);
}

/**
 * Resolve which agent ID to use, against an already-fetched agent list.
 *
 * Rungs 1, 4 and 5 of the ladder: a named actor, then the org's only agent,
 * then a refusal that names them all. `explicit` and `asFlag` are the *same*
 * rung — two spellings of one value — so two disagreeing values refuse
 * rather than one silently winning.
 *
 * Kept for the call sites that already hold the agent list. A surface that
 * holds a client and not a list wants {@link resolveActor}, which adds the
 * `RINE_AGENT` rung and fetches only when a fetch can change the answer.
 *
 * Accepts UUIDs, handles, or bare names. Reads no environment — see the header
 * comment of `actor.ts` for why that is a correctness property and not a style.
 *
 * 🔴 **Every spelling resolves against the agents passed in — the caller's own.**
 * An acting agent must be an agent the caller owns, so there is no WebFinger
 * fallback here and this function takes no `apiUrl` to reach one with. A handle
 * this org does not own is refused by name, listing the agents there are,
 * rather than resolved to a stranger's id the server then answers 422 about.
 * The UUID short-circuit is the one spelling that costs no lookup, and it is
 * unvalidated on purpose: a caller that also needs "and it is mine" checks
 * membership against the same list (`rine-ts-sdk`'s `resolveSenderId`).
 *
 * 🔴 **On a one-agent org a value that names nobody does not refuse** — that
 * agent acts, and {@link ResolvedActor.warning} says so. The parameter cannot
 * carry information where there is nothing to choose between, and a model that
 * has no answer for it fills it with the schema's own placeholder text; refusing
 * there spent a turn on a slot that had one legal value all along. `origin`
 * says which rung that value came off, because the warning tells the caller
 * what to change and a rung-3 value is not in the call to be changed
 * ({@link ActorOrigin}). A surface that applies the environment rung above this
 * function — `rine-cli`'s ladder, `rine-eve`'s webhook — passes it; one that
 * lets {@link resolveActor} apply it does not have to.
 *
 * 🔴 **The UUID rung never falls back**, deliberately, and it is the one case
 * this does not fix. Acting as somebody else because a caller-supplied UUID did
 * not resolve is a silent identity substitution — in `rine-ts-sdk` it would
 * re-open the hole `resolveSenderId`'s membership check closed — and it is also
 * the one spelling that costs no `GET /agents`, which a fallback would put on
 * every call. A bogus UUID on a one-agent org still fails, locally there and
 * with a server 422 everywhere else.
 */
export async function resolveAgent(
	agents: AgentRead[],
	explicit?: string,
	asFlag?: string,
	surface: ActorSurface = ACTOR_SURFACES.cli,
	origin: ActorOrigin = "argument",
): Promise<ResolvedActor> {
	const target = singleActorValue(explicit, asFlag, surface);
	const sole = agents.length === 1 ? agents[0] : undefined;
	if (target !== undefined) {
		if (UUID_RE.test(target)) return { agentId: target };
		const found = findInAgents(agents, target);
		if (found !== null) return { agentId: found };
		// The value named nobody. On a one-agent org the slot had one legal
		// answer, so it is not load-bearing and the warning rides the success.
		if (sole) {
			return {
				agentId: sole.id,
				warning: ignoredActorWarning(target, sole, surface, origin),
			};
		}
		refuseUnresolvedActor(agents, target, surface);
	}

	if (sole) return { agentId: sole.id };

	throw new Error(actorRefusal(agents, surface));
}

/**
 * The acting-agent ladder, over a client that can fetch its own agent list.
 *
 * ⚠️ Not yet the only implementation of these rungs: `rine-cli`'s
 * `actorLadder` climbs the same three because it needs the agent list itself
 * (for the provenance line and for the commands that print handles), and
 * `rine-eve`/`rine-ts-sdk` reach `resolveAgent` directly with a list they
 * already hold. Converging them wants an optional pre-fetched list and an
 * env-provenance callback here; until that lands, a rung added below reaches
 * `rine-mcp` and `rine-openclaw` only.
 *
 * In order, stopping at the first rung that answers: the caller's own value
 * (`explicit`, with `alias` as its retired spelling — same rung, so they must
 * agree), then `RINE_AGENT`, then the org's only active agent, then a refusal
 * naming the org's agents and this surface's way of choosing one.
 *
 * Rung 2 — surface configuration, such as openclaw's `agentId` or an SDK
 * constructor — belongs to the surface, which passes `perCall ?? config` as
 * `explicit`. That keeps configuration ahead of the environment without this
 * function having to know what configuration means on six surfaces.
 *
 * The agent list is fetched only when it can change the answer: a UUID is
 * already the value the wire wants, so it alone costs no round trip. A handle
 * costs one, because it is resolved against the caller's own agents like every
 * other spelling of this slot — see {@link resolveAgent}.
 *
 * 🔴 `origin` is for the caller that already climbed rung 3 and hands the
 * result down as `explicit` — `rine-mcp`'s `namedActingAgent` does, because it
 * has to answer "did anything name an agent at all?" before it decides whether
 * to send a header. Without it this function sees a value in the argument slot
 * and the one-agent warning tells a model to omit a parameter no call carried.
 * Left unset, the rung is derived here, which is right for everybody else.
 *
 * 🔴 The fetched roster rides the answer ({@link ResolvedActor.agents}) rather
 * than being dropped on the floor. A surface that resolves an actor here and
 * then resolves a bare RECIPIENT used to pay `GET /agents` twice per send — the
 * collision guard in `resolveBareRecipientGroup` reads the very same page — and
 * `ResolveOptions.agents`, the seam built for exactly that hand-off, had no
 * caller on either stack because nothing gave a surface the list to pass. Only
 * the rung that FETCHED sets it; the UUID rung above reads no list and says so
 * by leaving it unset.
 */
export async function resolveActor(
	client: HttpClient,
	explicit?: unknown,
	alias?: unknown,
	surface: ActorSurface = ACTOR_SURFACES.cli,
	origin?: ActorOrigin,
): Promise<ResolvedActor> {
	// The two rungs are read apart rather than in one `??` chain, because which
	// of them answered is what the one-agent warning has to name (`ActorOrigin`).
	const argued = singleActorValue(explicit, alias, surface);
	const named = argued ?? actorFromEnv();
	if (named !== undefined && UUID_RE.test(named)) return { agentId: named };
	const agents = await fetchAgents(client);
	const resolved = await resolveAgent(
		agents,
		named,
		undefined,
		surface,
		origin ?? (argued === undefined ? "environment" : "argument"),
	);
	return { ...resolved, agents };
}
