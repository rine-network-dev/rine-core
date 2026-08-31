import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	ACTING_AGENT_ENV,
	ACTING_AGENT_HEADER,
	ACTOR_SURFACES,
	actorFromEnv,
	actorLabel,
	actorNote,
	actorRefusal,
	ambiguousActorRefusal,
	ignoredActorWarning,
	nameOneOfThem,
	normalizeActor,
	singleActorValue,
	unknownActorRefusal,
	unknownHandleRefusal,
} from "../src/actor.js";
import type { AgentRead } from "../src/api-types.js";

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

const KOFI = makeAgent("k-1", "kofi", "kofi@acme.rine.network");
const BOB = makeAgent("b-1", "bob", "bob@acme.rine.network");

describe("ACTING_AGENT_HEADER", () => {
	it("is the wire header the server reads", () => {
		// Pinned as a literal: a constant compared against itself proves nothing,
		// and this name is a wire contract with src/rine/api/agent_identity.py.
		expect(ACTING_AGENT_HEADER).toBe("X-Rine-Agent");
		expect(ACTING_AGENT_ENV).toBe("RINE_AGENT");
	});
});

describe("normalizeActor", () => {
	it("trims a padded value", () => {
		expect(normalizeActor(" bob ")).toBe("bob");
	});

	it("treats empty-after-trim as absent, so the rung falls through", () => {
		expect(normalizeActor("")).toBeUndefined();
		expect(normalizeActor("   ")).toBeUndefined();
	});

	it("treats null and undefined as absent", () => {
		expect(normalizeActor(undefined)).toBeUndefined();
		expect(normalizeActor(null)).toBeUndefined();
	});

	it("does not fold case", () => {
		expect(normalizeActor("Kofi")).toBe("Kofi");
	});

	it("refuses a non-string rather than stringifying it", () => {
		expect(() => normalizeActor(123)).toThrow(
			"The acting agent must be a name, handle or UUID (got number).",
		);
		expect(() => normalizeActor({})).toThrow("(got object).");
		expect(() => normalizeActor(["bob"])).toThrow("(got object).");
	});
});

describe("actorFromEnv", () => {
	const before = process.env[ACTING_AGENT_ENV];
	afterEach(() => {
		if (before === undefined) delete process.env[ACTING_AGENT_ENV];
		else process.env[ACTING_AGENT_ENV] = before;
	});

	it("reads RINE_AGENT, trimmed", () => {
		process.env[ACTING_AGENT_ENV] = "  kofi  ";
		expect(actorFromEnv()).toBe("kofi");
	});

	it("is absent when RINE_AGENT is unset", () => {
		delete process.env[ACTING_AGENT_ENV];
		expect(actorFromEnv()).toBeUndefined();
	});

	it("is absent when RINE_AGENT is empty — rine-eve scaffolds a bare RINE_AGENT= line", () => {
		process.env[ACTING_AGENT_ENV] = "";
		expect(actorFromEnv()).toBeUndefined();
	});
});

describe("actorRefusal", () => {
	it("names the org's agents by name and handle, and how to choose one", () => {
		const text = actorRefusal([KOFI, BOB], ACTOR_SURFACES.cli);
		expect(text).toBe(
			[
				"This org has more than one agent. Say which one is acting:",
				"  - kofi (kofi@acme.rine.network)",
				"  - bob (bob@acme.rine.network)",
				"Name one of them with --agent, or set RINE_AGENT.",
			].join("\n"),
		);
	});

	it("invites the retry without naming an agent to retry with", () => {
		// `GET /agents` has no `ORDER BY` (see `ambiguousActorRefusal`), so a
		// refusal that said "retry with agent=kofi" would name a different agent
		// run to run and be irreproducible.
		const text = actorRefusal([KOFI, BOB], ACTOR_SURFACES.cli);
		expect(text).not.toContain("<name>");
		expect(text.split("\n").at(-1)).toBe(
			"Name one of them with --agent, or set RINE_AGENT.",
		);
	});

	it("names the surface's own spelling, not the CLI's", () => {
		expect(actorRefusal([KOFI, BOB], ACTOR_SURFACES.mcp)).toContain(
			"Name one of them with the agent parameter, or set RINE_AGENT.",
		);
	});

	it("does not send a caller to a rung their surface does not read", () => {
		// The TypeScript SDK reads no environment, by design.
		// A refusal that told its callers to set RINE_AGENT would send them to a
		// lever that does nothing: they export it, re-run, and read the identical
		// refusal.
		const text = actorRefusal([KOFI, BOB], ACTOR_SURFACES.ts);
		expect(text).toContain("Name one of them with agent.");
		expect(text).not.toContain("RINE_AGENT");
	});

	it("names an agent by its UUID when it has claimed no handle", () => {
		// `handle` is null until the org has a slug; naming an agent `(null)`
		// names it by nothing `X-Rine-Agent` accepts.
		const nameless = { ...KOFI, handle: null } as unknown as AgentRead;
		expect(actorRefusal([nameless, BOB], ACTOR_SURFACES.cli)).toContain(
			"  - kofi (k-1)",
		);
	});

	it("says so when the org has no active agents", () => {
		expect(actorRefusal([], ACTOR_SURFACES.cli)).toBe(
			"No active agents in this org.",
		);
	});
});

describe("unknownActorRefusal", () => {
	// Every roster here has two agents: a one-agent org resolves any value to
	// its only agent and warns, so it can no longer reach this sentence at all.
	it("lists the org's agents in the same column set", () => {
		expect(unknownActorRefusal([KOFI, BOB], "zed", ACTOR_SURFACES.cli)).toBe(
			"No agent named 'zed'. This org has more than one agent, so a call has to name one. " +
				"Available agents:\n" +
				"  - kofi (kofi@acme.rine.network)\n" +
				"  - bob (bob@acme.rine.network)\n" +
				"Name one of them with --agent, or set RINE_AGENT.",
		);
	});

	it("says the same thing about a placeholder as about a misspelled colleague", () => {
		// The bogus-word list is gone: what the caller named is echoed, and the
		// roster decides the outcome — not the vocabulary.
		const placeholder = unknownActorRefusal([KOFI, BOB], "null");
		const typo = unknownActorRefusal([KOFI, BOB], "kofy");
		expect(placeholder).toBe(typo.replace("kofy", "null"));
		expect(placeholder).toContain("No agent named 'null'.");
		expect(placeholder).not.toContain("placeholder");
	});

	it("does not offer a list it does not have", () => {
		expect(unknownActorRefusal([], "zed")).toBe(
			"No agent named 'zed'. No active agents in this org.",
		);
	});

	it("keeps the opening substring three wrapper packages branch on", () => {
		// `rine-hermes`, `rine-crewai` and `rine-langchain` decide whether a 404
		// gets the "try rine_discover" tail by testing these two leads. A lead
		// that "improves" sends every actor refusal to the agent directory
		// instead, with every suite green.
		expect(unknownActorRefusal([KOFI, BOB], "zed")).toContain(
			"No agent named '",
		);
		expect(unknownHandleRefusal([KOFI, BOB], "zed@acme.rine.network")).toContain(
			"No agent with handle '",
		);
	});
});

describe("unknownHandleRefusal", () => {
	it("names the handle that is nobody here, and the agents that are", () => {
		expect(
			unknownHandleRefusal([KOFI, BOB], "zed@acme.rine.network", ACTOR_SURFACES.mcp),
		).toBe(
			"No agent with handle 'zed@acme.rine.network'. " +
				"This org has more than one agent, so a call has to name one. " +
				"Available agents:\n" +
				"  - kofi (kofi@acme.rine.network)\n" +
				"  - bob (bob@acme.rine.network)\n" +
				"Name one of them with the agent parameter, or set RINE_AGENT.",
		);
	});

	it("answers the same question its bare-name twin does", () => {
		// One mistake, two spellings, one shape of sentence — the divergence
		// this pair exists to close was a handle being answered by WebFinger
		// availability advice instead of by the org's own roster.
		const bare = unknownActorRefusal([KOFI, BOB], "zed");
		const handle = unknownHandleRefusal([KOFI, BOB], "zed@acme.rine.network");
		const columns = "  - kofi (kofi@acme.rine.network)\n  - bob (bob@acme.rine.network)";
		expect(bare).toContain(columns);
		expect(handle).toContain(columns);
	});

	it("does not offer a list it does not have", () => {
		expect(unknownHandleRefusal([], "zed@acme.rine.network")).toBe(
			"No agent with handle 'zed@acme.rine.network'. No active agents in this org.",
		);
	});
});

describe("ambiguousActorRefusal", () => {
	it("names every candidate and the spellings that tell them apart", () => {
		const twin = makeAgent("k-2", "Kofi", "kofi-2@acme.rine.network");
		expect(ambiguousActorRefusal([KOFI, twin], "kofi")).toBe(
			"More than one agent is named 'kofi'. Say which one is acting:\n" +
				"  - kofi (kofi@acme.rine.network)\n" +
				"  - Kofi (kofi-2@acme.rine.network)\n" +
				"A name is not unique in an org — name it by handle or UUID.",
		);
	});

	it("falls back to the UUID when a candidate has no handle", () => {
		// A slugless org mints no handles, and that is exactly the org where two
		// agents can share a name with nothing else to tell them apart.
		const noHandle: AgentRead = { ...KOFI, handle: null };
		expect(ambiguousActorRefusal([noHandle], "kofi")).toContain("  - kofi (k-1)");
	});
});

describe("ignoredActorWarning", () => {
	it("says what was passed, who acted, and that the slot can be omitted", () => {
		expect(ignoredActorWarning("null", KOFI, ACTOR_SURFACES.mcp)).toBe(
			"Ignored agent 'null': this org has one agent, so kofi (kofi@acme.rine.network) acted. " +
				"Omit agent for a one-agent org.",
		);
	});

	it("spells the slot the way the caller's own surface does", () => {
		expect(ignoredActorWarning("null", KOFI, ACTOR_SURFACES.cli)).toBe(
			"Ignored --agent 'null': this org has one agent, so kofi (kofi@acme.rine.network) acted. " +
				"Omit --agent for a one-agent org.",
		);
	});

	it("names RINE_AGENT when that is where the value came from", () => {
		// The lever the reader can actually move. On a one-agent org this warning is
		// the only channel a stale export has left — the refusal that used to
		// carry it no longer happens — so "omit --agent" would end the one sentence
		// that could fix it by naming a flag nobody passed.
		expect(ignoredActorWarning("zed", KOFI, ACTOR_SURFACES.cli, "environment")).toBe(
			"Ignored RINE_AGENT='zed': this org has one agent, so kofi (kofi@acme.rine.network) acted. " +
				"RINE_AGENT names no agent this org has — unset it, or point it at one that exists.",
		);
	});

	it("names the acted agent in the same column set every refusal prints", () => {
		const nameless: AgentRead = { ...KOFI, handle: null };
		expect(ignoredActorWarning("null", nameless)).toContain("so kofi (k-1) acted.");
	});
});

describe("actorNote", () => {
	it("carries the warning under the one key a tool result uses", () => {
		expect(actorNote({ agentId: "k-1", warning: "careful" })).toEqual({
			warning: "careful",
		});
	});

	it("adds no key at all when there is nothing to say", () => {
		// Spread into a successful result, so an `undefined` warning key would
		// show a model a field that means nothing.
		const note = actorNote({ agentId: "k-1" });
		expect(note).toEqual({});
		expect(Object.hasOwn(note, "warning")).toBe(false);
	});
});

describe("nameOneOfThem", () => {
	it("advertises only the rungs the caller's surface can reach", () => {
		expect(nameOneOfThem(ACTOR_SURFACES.cli)).toBe(
			"Name one of them with --agent, or set RINE_AGENT.",
		);
		expect(nameOneOfThem(ACTOR_SURFACES.ts)).toBe(
			"Name one of them with agent.",
		);
	});
});

describe("actorLabel", () => {
	it("is the one column set, name then handle", () => {
		expect(actorLabel(KOFI)).toBe("kofi (kofi@acme.rine.network)");
	});

	it("falls back to the UUID when the org minted no handle", () => {
		expect(actorLabel({ ...KOFI, handle: null })).toBe("kofi (k-1)");
	});
});

describe("the agent list every refusal prints", () => {
	it("is one column set, reached only through the refusals", () => {
		const columns = "  - kofi (kofi@acme.rine.network)\n  - bob (bob@acme.rine.network)";
		expect(actorRefusal([KOFI, BOB], ACTOR_SURFACES.cli)).toContain(columns);
		expect(unknownActorRefusal([KOFI, BOB], "zed")).toContain(columns);
		expect(unknownHandleRefusal([KOFI, BOB], "zed@acme")).toContain(columns);
		expect(ambiguousActorRefusal([KOFI, BOB], "zed")).toContain(columns);
	});
});

describe("singleActorValue", () => {
	it("returns the only value given, under either spelling", () => {
		expect(singleActorValue("bob", undefined)).toBe("bob");
		expect(singleActorValue(undefined, "bob")).toBe("bob");
		expect(singleActorValue(undefined, undefined)).toBeUndefined();
	});

	it("normalizes before comparing, so padding and case agree", () => {
		expect(singleActorValue(" bob ", "BOB")).toBe("bob");
	});

	it("refuses two disagreeing values, naming both and both spellings", () => {
		expect(() => singleActorValue("bob", "kofi")).toThrow(
			"You named the acting agent twice: --agent bob and --as kofi.\nName it once.",
		);
	});

	it("names the surface's own spellings", () => {
		expect(() => singleActorValue("bob", "kofi", ACTOR_SURFACES.mcp)).toThrow(
			"You named the acting agent twice: agent bob and as kofi.",
		);
		expect(() =>
			singleActorValue("bob", "kofi", {
				...ACTOR_SURFACES.cli,
				alias: "--from",
			}),
		).toThrow("--agent bob and --from kofi");
	});

	it("refuses a name and a handle for the same agent, rather than resolving to compare", () => {
		expect(() => singleActorValue("bob", "bob@acme.rine.network")).toThrow(
			"You named the acting agent twice",
		);
	});

	it("treats an empty second value as absent, not as a disagreement", () => {
		expect(singleActorValue("bob", "   ")).toBe("bob");
	});
});

describe("the RINE_AGENT read is opt-in — the regression cannot come back", () => {
	// rine-mastra builds a BARE ts-sdk client for an operator-fixed actor. An
	// ambient RINE_AGENT that reached a library path would silently re-actor
	// every call it makes. That was written once and reverted; this guard is
	// what makes "surfaces only" structural rather than a comment.
	function sources(dir: string): string[] {
		return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
			const p = join(dir, e.name);
			if (e.isDirectory()) return sources(p);
			return e.isFile() && p.endsWith(".ts") ? [p] : [];
		});
	}

	const files = sources(new URL("../src", import.meta.url).pathname).map(
		(p) => [p.split("/src/")[1] as string, readFileSync(p, "utf8")] as const,
	);

	it("names the variable in exactly one rine-core source file", () => {
		// Quoted, so prose mentioning `RINE_AGENT` in a doc comment does not count.
		const named = files.filter(([, src]) => /["']RINE_AGENT["']/.test(src));
		expect(named.map(([name]) => name)).toEqual(["actor.ts"]);
	});

	it("reaches process.env for it in exactly one place", () => {
		const readers = files.filter(
			([, src]) => src.includes("process.env") && src.includes("ACTING_AGENT_ENV"),
		);
		expect(readers.map(([name]) => name)).toEqual(["actor.ts"]);
		expect(readers[0]?.[1].match(/process\.env/g)).toHaveLength(1);
	});
});
