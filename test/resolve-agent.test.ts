import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentRead } from "../src/api-types.js";

const mockResolveHandle = vi.fn();
vi.mock("../src/resolve-handle.js", async (importOriginal) => {
	const orig = await importOriginal<typeof import("../src/resolve-handle.js")>();
	return {
		...orig,
		resolveHandleViaWebFinger: (...args: unknown[]) => mockResolveHandle(...args),
	};
});

const { resolveToUuid, fetchAgents, resolveAgent, resolveActor } = await import(
	"../src/resolve-agent.js"
);
const { ACTING_AGENT_ENV, ACTOR_SURFACES } = await import("../src/actor.js");

const UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const BETA_UUID = "b1b2c3d4-e5f6-7890-abcd-ef1234567890";

function makeAgent(id: string, name: string, handle: string): AgentRead {
	return {
		id,
		name,
		handle,
		human_oversight: false,
		incoming_policy: "open",
		outgoing_policy: "open",
		created_at: "2026-01-01T00:00:00Z",
	};
}

describe("resolveToUuid", () => {
	beforeEach(() => mockResolveHandle.mockReset());

	it("returns UUID directly when input is a UUID", async () => {
		const result = await resolveToUuid("https://api", UUID);
		expect(result).toBe(UUID);
		expect(mockResolveHandle).not.toHaveBeenCalled();
	});

	it("resolves handle via WebFinger", async () => {
		mockResolveHandle.mockResolvedValue(UUID);
		const result = await resolveToUuid("https://api", "bot@org.rine.network");
		expect(result).toBe(UUID);
		expect(mockResolveHandle).toHaveBeenCalledWith("https://api", "bot@org.rine.network");
	});

	it("throws when UUID format is invalid (no @)", async () => {
		await expect(resolveToUuid("https://api", "not-a-uuid"))
			.rejects.toThrow("Invalid agent identifier");
	});

	it("names the parts of a handle in that refusal, and prints no domain at all", async () => {
		// 🔴 This test used to assert the opposite — that the refusal names
		// a COMPLETE handle, `kofi@acme.rine.network`, because `agent@org` reads
		// as a form and came back filled in half-way. Both halves of that argument
		// were measured, and a later run measured the other end of it: with a
		// whole handle printed, the local part moved with the conversation and the
		// domain did not move at all. A slot invites a placeholder and an example
		// supplies one, so a refusal may print neither — the rule keeps the
		// example in tool DESCRIPTIONS, where the model is being taught rather
		// than corrected, and bans it here.
		const message = await resolveToUuid("https://api", "not-a-uuid").catch(
			(e: Error) => e.message,
		);
		expect(message).toContain("expected a UUID or handle written in full");
		expect(message).toContain("an agent's name, an at sign, and its org's domain");
		expect(message).not.toContain("@");
	});

	it("throws when WebFinger cannot resolve to UUID", async () => {
		mockResolveHandle.mockResolvedValue("still-a-handle@org");
		await expect(resolveToUuid("https://api", "bad@org.rine.network"))
			.rejects.toThrow("Cannot resolve handle");
	});
});

describe("fetchAgents", () => {
	it("returns items from client.get", async () => {
		const agents = [makeAgent(UUID, "bot", "bot@org.rine.network")];
		const mockClient = { get: vi.fn().mockResolvedValue({ items: agents, total: 1 }) };
		const result = await fetchAgents(mockClient as never);
		expect(result).toEqual(agents);
		expect(mockClient.get).toHaveBeenCalledWith("/agents");
	});
});

describe("resolveAgent", () => {
	beforeEach(() => mockResolveHandle.mockReset());

	const agents = [
		makeAgent(UUID, "alpha", "alpha@org.rine.network"),
		makeAgent(BETA_UUID, "beta", "beta@org.rine.network"),
	];

	it("uses explicit flag when provided (UUID)", async () => {
		expect(await resolveAgent(agents, UUID)).toEqual({ agentId: UUID });
	});

	it("uses explicit flag when provided (bare name)", async () => {
		expect(await resolveAgent(agents, "alpha")).toEqual({ agentId: UUID });
	});

	it("resolves a handle against the org's own agents, never WebFinger", async () => {
		// The actor slot's whole rule: an acting agent is an agent the caller
		// owns, so the answer comes from the list that was passed in. A
		// WebFinger call here would be asking the world who owns the handle —
		// a question about somebody else's org.
		const result = await resolveAgent(agents, "alpha@org.rine.network");
		expect(result.agentId).toBe(UUID);
		expect(mockResolveHandle).not.toHaveBeenCalled();
	});

	it("matches a short-form handle against the stored one", async () => {
		expect((await resolveAgent(agents, "alpha@org")).agentId).toBe(UUID);
		expect(mockResolveHandle).not.toHaveBeenCalled();
	});

	it("matches a handle case-insensitively", async () => {
		expect((await resolveAgent(agents, "ALPHA@ORG.rine.network")).agentId).toBe(UUID);
	});

	it("falls back to asFlag", async () => {
		expect((await resolveAgent(agents, undefined, "beta")).agentId).toBe(BETA_UUID);
	});

	it("auto-resolves single agent", async () => {
		const single = [agents[0]!];
		expect(await resolveAgent(single)).toEqual({ agentId: UUID });
	});

	it("refuses for multiple agents without flag, naming them", async () => {
		await expect(resolveAgent(agents)).rejects.toThrow(
			"This org has more than one agent. Say which one is acting:\n" +
				"  - alpha (alpha@org.rine.network)\n" +
				"  - beta (beta@org.rine.network)\n" +
				"Name one of them with --agent, or set RINE_AGENT.",
		);
	});

	it("names the calling surface's own spelling in the refusal", async () => {
		await expect(
			resolveAgent(agents, undefined, undefined, ACTOR_SURFACES.mcp),
		).rejects.toThrow("Name one of them with the agent parameter, or set RINE_AGENT.");
	});

	it("throws for no agents", async () => {
		await expect(resolveAgent([])).rejects.toThrow("No active agents in this org.");
	});

	it("throws for unknown bare name, listing agents by name and handle", async () => {
		await expect(resolveAgent(agents, "unknown")).rejects.toThrow(
			"No agent named 'unknown'. This org has more than one agent, so a call has to name one. " +
				"Available agents:\n" +
				"  - alpha (alpha@org.rine.network)",
		);
	});

	it("refuses an unknown handle by name, listing the org's own agents", async () => {
		// The other half of the same mistake. It used to reach WebFinger and
		// come back "Ensure WebFinger is available or use a UUID" — a sentence
		// about infrastructure, naming no agent, for a typo.
		await expect(resolveAgent(agents, "unknown@org.rine.network")).rejects.toThrow(
			"No agent with handle 'unknown@org.rine.network'. " +
				"This org has more than one agent, so a call has to name one. " +
				"Available agents:\n" +
				"  - alpha (alpha@org.rine.network)\n" +
				"  - beta (beta@org.rine.network)",
		);
		expect(mockResolveHandle).not.toHaveBeenCalled();
	});

	it("refuses a handle this org does not own rather than acting as it", async () => {
		// WebFinger would have RESOLVED this one — it is a real agent, in
		// somebody else's org — and the caller would have acted as an id their
		// keys cannot sign for. Ownership is decided here, not by the server's
		// 422 two round trips later.
		mockResolveHandle.mockResolvedValue("cccccccc-e5f6-7890-abcd-ef1234567890");
		await expect(resolveAgent(agents, "someone@other-org.rine.network")).rejects.toThrow(
			"No agent with handle 'someone@other-org.rine.network'.",
		);
		expect(mockResolveHandle).not.toHaveBeenCalled();
	});

	it("refuses an unknown actor the same way under both spellings", async () => {
		// One mistake, one sentence, whichever way the caller spelled it: both
		// name the agent that does not exist and list the ones that do.
		const bare = await resolveAgent(agents, "ghost").catch((e: Error) => e.message);
		const handle = await resolveAgent(agents, "ghost@org.rine.network").catch(
			(e: Error) => e.message,
		);
		const tail =
			" This org has more than one agent, so a call has to name one. Available agents:\n" +
			"  - alpha (alpha@org.rine.network)\n" +
			"  - beta (beta@org.rine.network)\n" +
			"Name one of them with --agent, or set RINE_AGENT.";
		expect(bare).toBe(`No agent named 'ghost'.${tail}`);
		expect(handle).toBe(`No agent with handle 'ghost@org.rine.network'.${tail}`);
	});

	it("refuses an ambiguous bare name, naming the candidates", async () => {
		// A bare name is not unique in an org: `agents.name` has no unique
		// index, so two agents can carry one name and the list has no ORDER BY.
		// Taking the first would act as an identity the caller never chose.
		const twin = makeAgent(
			"c1b2c3d4-e5f6-7890-abcd-ef1234567890",
			"Alpha",
			"alpha-2@org.rine.network",
		);
		await expect(resolveAgent([...agents, twin], "alpha")).rejects.toThrow(
			"More than one agent is named 'alpha'. Say which one is acting:\n" +
				"  - alpha (alpha@org.rine.network)\n" +
				"  - Alpha (alpha-2@org.rine.network)\n" +
				"A name is not unique in an org — name it by handle or UUID.",
		);
	});

	it("still resolves a duplicated name by handle, which is what the refusal asks for", async () => {
		const twin = makeAgent(
			"c1b2c3d4-e5f6-7890-abcd-ef1234567890",
			"Alpha",
			"alpha-2@org.rine.network",
		);
		expect(
			(await resolveAgent([...agents, twin], "alpha-2@org.rine.network")).agentId,
		).toBe("c1b2c3d4-e5f6-7890-abcd-ef1234567890");
	});

	it("refuses when the explicit and retired spellings disagree", async () => {
		await expect(resolveAgent(agents, "alpha", "beta")).rejects.toThrow(
			"You named the acting agent twice: --agent alpha and --as beta.",
		);
	});

	it("accepts both spellings when they agree", async () => {
		expect((await resolveAgent(agents, "alpha", "ALPHA")).agentId).toBe(UUID);
	});

	it("trims before resolving", async () => {
		expect((await resolveAgent(agents, " alpha ")).agentId).toBe(UUID);
	});

	it("ignores RINE_AGENT — a bare SDK client must never inherit an ambient actor", async () => {
		process.env[ACTING_AGENT_ENV] = "alpha";
		try {
			await expect(resolveAgent(agents)).rejects.toThrow(
				"This org has more than one agent",
			);
		} finally {
			delete process.env[ACTING_AGENT_ENV];
		}
	});
});

describe("an org with one agent, where the actor slot carries no information", () => {
	// The measured defect was a model filling this slot with the schema's
	// own placeholder text; refusing over a parameter that had one legal answer
	// all along spent the turn and taught nothing.
	const kofi = makeAgent(UUID, "kofi", "kofi@acme.rine.network");
	const bob = makeAgent(BETA_UUID, "bob", "bob@acme.rine.network");

	it("acts as its only agent when the value named nobody", async () => {
		const result = await resolveAgent([kofi], "null");
		expect(result.agentId).toBe(UUID);
	});

	it("says what was passed, who acted, and that the slot can be omitted", async () => {
		const result = await resolveAgent([kofi], "null", undefined, ACTOR_SURFACES.mcp);
		expect(result.warning).toBe(
			"Ignored agent 'null': this org has one agent, so kofi (kofi@acme.rine.network) acted. " +
				"Omit agent for a one-agent org.",
		);
	});

	it("does the same for a handle nobody here owns", async () => {
		const result = await resolveAgent([kofi], "kofi@other.rine.network");
		expect(result.agentId).toBe(UUID);
		expect(result.warning).toContain("Ignored --agent 'kofi@other.rine.network'");
	});

	it("stays silent when the value named that very agent", async () => {
		// A value that agreed with the outcome was not ignored, and warning on a
		// correct call would teach a model that correct behaviour complains.
		expect(await resolveAgent([kofi], "kofi")).toEqual({ agentId: UUID });
		expect(await resolveAgent([kofi], "kofi@acme.rine.network")).toEqual({
			agentId: UUID,
		});
	});

	it("stays silent when no value was given at all", async () => {
		expect(await resolveAgent([kofi])).toEqual({ agentId: UUID });
	});

	it("never falls back for a UUID — that would be a silent identity swap", async () => {
		// The one case this deliberately does not fix: a caller-supplied UUID is
		// returned as written and fails downstream (locally in rine-ts-sdk's
		// ownership check, otherwise with a server 422). Acting as somebody else
		// because the id did not resolve is a substitution nobody asked for.
		const foreign = "cccccccc-e5f6-7890-abcd-ef1234567890";
		expect(await resolveAgent([kofi], foreign)).toEqual({ agentId: foreign });
	});

	it("resolves an agent genuinely named 'none' rather than treating it as a non-answer", async () => {
		const none = makeAgent(UUID, "none", "none@org.rine.network");
		expect((await resolveAgent([none, bob], "none")).agentId).toBe(UUID);
	});

	it("answers a multi-agent org identically for a placeholder and for a typo", async () => {
		// The bogus-word list is deleted: the roster decides the outcome, and
		// the sentence echoes whatever the caller named.
		const refusalFor = async (named: string): Promise<string> => {
			try {
				await resolveAgent([kofi, bob], named);
			} catch (err) {
				return (err as Error).message;
			}
			throw new Error(`expected a refusal for ${named}`);
		};
		const placeholder = await refusalFor("null");
		const typo = await refusalFor("kofy");
		expect(placeholder).toBe(typo.replace("kofy", "null"));
		expect(placeholder).not.toContain("placeholder");
	});
});

describe("resolveActor", () => {
	const agents = [
		makeAgent(UUID, "alpha", "alpha@org.rine.network"),
		makeAgent(BETA_UUID, "beta", "beta@org.rine.network"),
	];

	function stubClient(items = agents) {
		return { get: vi.fn().mockResolvedValue({ items, total: items.length }) };
	}

	beforeEach(() => {
		mockResolveHandle.mockReset();
		delete process.env[ACTING_AGENT_ENV];
	});

	afterEach(() => {
		delete process.env[ACTING_AGENT_ENV];
	});

	it("rung 1: resolves the caller's own bare name", async () => {
		const client = stubClient();
		expect((await resolveActor(client as never, "beta")).agentId).toBe(BETA_UUID);
	});

	it("rung 1: resolves the retired spelling too", async () => {
		const client = stubClient();
		expect((await resolveActor(client as never, undefined, "alpha")).agentId).toBe(
			UUID,
		);
	});

	it("rung 1: a UUID costs no round trip", async () => {
		const client = stubClient();
		expect(await resolveActor(client as never, UUID)).toEqual({ agentId: UUID });
		expect(client.get).not.toHaveBeenCalled();
	});

	it("rung 1: a handle buys the org's own list, not a WebFinger lookup", async () => {
		// It used to spend a WebFinger round trip instead, which asks who owns
		// the handle anywhere. The list costs the same one request and answers
		// the question this slot is actually about: is it one of ours?
		const client = stubClient();
		expect((await resolveActor(client as never, "beta@org.rine.network")).agentId).toBe(
			BETA_UUID,
		);
		expect(client.get).toHaveBeenCalledWith("/agents");
		expect(mockResolveHandle).not.toHaveBeenCalled();
	});

	it("rung 1: a handle this org does not own is refused by name", async () => {
		mockResolveHandle.mockResolvedValue("cccccccc-e5f6-7890-abcd-ef1234567890");
		const client = stubClient();
		await expect(
			resolveActor(client as never, "someone@other-org.rine.network"),
		).rejects.toThrow("No agent with handle 'someone@other-org.rine.network'.");
	});

	it("rung 3: an unknown RINE_AGENT handle is refused by name too", async () => {
		process.env[ACTING_AGENT_ENV] = "ghost@org.rine.network";
		const client = stubClient();
		await expect(resolveActor(client as never)).rejects.toThrow(
			"No agent with handle 'ghost@org.rine.network'.",
		);
	});

	it("rung 3: a stale RINE_AGENT on a one-agent org warns instead of refusing", async () => {
		// The one-agent org is exactly where the CLI's `blameEnvActor` used to
		// name this rung; there is no throw to decorate now, so the warning is
		// the only thing that reports it.
		process.env[ACTING_AGENT_ENV] = "ghost";
		const client = stubClient([agents[0]!]);
		const result = await resolveActor(client as never);
		expect(result.agentId).toBe(UUID);
		// And it names the ENVIRONMENT, because that is where the value came
		// from: the caller passed no flag, so "omit --agent" would send them
		// looking for something they never typed.
		expect(result.warning).toContain("Ignored RINE_AGENT='ghost'");
		expect(result.warning).toContain("unset it, or point it at one that exists");
	});

	it("refuses two disagreeing values before it fetches anything", async () => {
		const client = stubClient();
		await expect(
			resolveActor(client as never, "alpha", "beta"),
		).rejects.toThrow("You named the acting agent twice");
		expect(client.get).not.toHaveBeenCalled();
	});

	it("rung 3: falls through to RINE_AGENT", async () => {
		process.env[ACTING_AGENT_ENV] = " beta ";
		const client = stubClient();
		expect((await resolveActor(client as never)).agentId).toBe(BETA_UUID);
	});

	it("rung 1 beats rung 3, silently — precedence is not disagreement", async () => {
		process.env[ACTING_AGENT_ENV] = "beta";
		const client = stubClient();
		expect((await resolveActor(client as never, "alpha")).agentId).toBe(UUID);
	});

	it("an empty RINE_AGENT falls through rather than refusing", async () => {
		process.env[ACTING_AGENT_ENV] = "";
		const sole = [agents[0]!];
		const client = stubClient(sole);
		expect(await resolveActor(client as never)).toEqual({
			agentId: UUID,
			agents: sole,
		});
	});

	it("rung 4: takes the org's only agent", async () => {
		const sole = [agents[0]!];
		const client = stubClient(sole);
		expect(await resolveActor(client as never)).toEqual({
			agentId: UUID,
			agents: sole,
		});
	});

	it("rung 5: refuses naming the agents and this surface's spelling", async () => {
		const client = stubClient();
		await expect(
			resolveActor(client as never, undefined, undefined, ACTOR_SURFACES.mcp),
		).rejects.toThrow(
			"This org has more than one agent. Say which one is acting:\n" +
				"  - alpha (alpha@org.rine.network)\n" +
				"  - beta (beta@org.rine.network)\n" +
				"Name one of them with the agent parameter, or set RINE_AGENT.",
		);
	});

	it("refuses a non-string actor rather than hunting for '[object Object]'", async () => {
		const client = stubClient();
		await expect(
			resolveActor(client as never, { name: "alpha" }),
		).rejects.toThrow("The acting agent must be a name, handle or UUID (got object).");
		expect(client.get).not.toHaveBeenCalled();
	});

	it("hands the fetched roster back, so the next resolve need not buy it again", async () => {
		// R-B2: `ResolveOptions.agents` had no caller on either stack because
		// nothing gave a surface the list to pass, so every bare-name send paid
		// `GET /agents` twice — once here, once inside the recipient guard. The
		// list is the SAME array, not a copy: a copy is a second answer that can
		// disagree with the first about which agents this org has.
		const client = stubClient();
		const resolved = await resolveActor(client as never, "beta");
		expect(resolved.agentId).toBe(BETA_UUID);
		expect(resolved.agents).toBe(agents);
		expect(client.get).toHaveBeenCalledTimes(1);
	});

	it("rung 1: a UUID reads no roster, so it hands none back", async () => {
		// 🔴 The field says what was READ. Answering with a list this rung never
		// fetched would be an invention, and answering with an empty one would
		// tell the recipient guard this org has no agents — which is the guard
		// that stops `send('ops')` from silently posting to a group called `ops`.
		const client = stubClient();
		const resolved = await resolveActor(client as never, UUID);
		expect(resolved.agents).toBeUndefined();
		expect(client.get).not.toHaveBeenCalled();
	});
});
