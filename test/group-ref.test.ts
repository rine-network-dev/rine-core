/**
 * The group-reference ladder, and the two refusals it ends in.
 *
 * These pin the ladder itself — that an exact match beats a normalised one,
 * that a tier matching twice refuses instead of falling through, that a prefix
 * must land on a segment boundary, and that both misses hand back the list the
 * resolver was already holding. Nothing here is a group any harness runs
 * against: the property under test is the ordering, not any one name.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import type { AgentRead, GroupRead } from "../src/api-types.js";
import {
	GROUP_NOT_FOUND_LEAD,
	GROUP_ROSTER_LEAD,
	MAX_LISTED_GROUPS,
	NEITHER_NAMESPACE_LEAD,
	NO_GROUPS_IN_ORG,
	isBareReference,
	matchGroupByName,
	normalizeGroupRef,
	recipientGroupForBareName,
	refuseIfABareAgentName,
} from "../src/group-ref.js";
import type { HttpClient } from "../src/http.js";
import { composeGroupRefusal } from "../src/recipient-refusal.js";
import { resolveBareRecipientGroup } from "../src/resolve-group.js";

function makeGroup(id: string, name: string, handle: string): GroupRead {
	return {
		id,
		name,
		handle,
		description: null,
		enrollment_policy: "closed",
		visibility: "private",
		isolated: false,
		vote_duration_hours: 48,
		member_count: 1,
		created_at: "2026-01-01T00:00:00Z",
		conversation_id: null,
	};
}

const PLANNING = makeGroup(
	"g-1",
	"Quarterly planning",
	"#quarterly-planning-401@acme.rine.network",
);
const LABELS = makeGroup(
	"g-2",
	"Shipping labels",
	"#shipping-labels@acme.rine.network",
);

describe("normalizeGroupRef", () => {
	it("folds case and collapses every non-alphanumeric run to one dash", () => {
		expect(normalizeGroupRef("Quarterly  Planning")).toBe("quarterly-planning");
		expect(normalizeGroupRef("quarterly_planning")).toBe("quarterly-planning");
		expect(normalizeGroupRef("#quarterly-planning!")).toBe("quarterly-planning");
	});

	it("keeps letters and digits the wire never sees as separators", () => {
		// A handle is `[a-zA-Z0-9_-]` on the server, but `name` is free text, so
		// the rule has to be alphanumeric-aware rather than ASCII-aware.
		expect(normalizeGroupRef("Équipe 2")).toBe("équipe-2");
	});
});

describe("matchGroupByName tiers", () => {
	it("resolves the exact local part, unchanged", () => {
		const found = matchGroupByName([PLANNING, LABELS], "shipping-labels");
		expect(found.id).toBe("g-2");
	});

	it("tolerates the leading # a caller may or may not type", () => {
		expect(matchGroupByName([PLANNING], "#quarterly-planning-401").id).toBe("g-1");
	});

	it("resolves a normalised spelling of the local part", () => {
		expect(matchGroupByName([PLANNING], "Quarterly Planning 401").id).toBe("g-1");
	});

	it("resolves the group's name, not only its handle", () => {
		expect(matchGroupByName([PLANNING, LABELS], "Shipping Labels").id).toBe("g-2");
	});

	it("resolves a whole-segment prefix of a longer handle", () => {
		expect(matchGroupByName([PLANNING, LABELS], "quarterly planning").id).toBe(
			"g-1",
		);
	});

	it("refuses a prefix that stops inside a segment", () => {
		// `quart` names no whole leading segment. Refusing it is what keeps the
		// boundary something a caller can point at in the handle they were shown.
		expect(() => matchGroupByName([PLANNING], "quart")).toThrow(
			/Group not found/,
		);
	});

	it("lets an exact match win a normalised one", () => {
		// Two groups, one named exactly what was typed and one that only
		// normalises to it. The exact tier decides alone — a looser tier never
		// gets to make an ambiguity out of a reference that was not ambiguous.
		const exact = makeGroup("g-3", "Ops", "#ops@acme.rine.network");
		const loose = makeGroup("g-4", "Ops", "#Ops@beta.rine.network");
		expect(matchGroupByName([loose, exact], "ops").id).toBe("g-3");
	});

	it("refuses a tier that matches twice, naming both candidates", () => {
		const north = makeGroup("g-5", "Ops north", "#ops-north@acme.rine.network");
		const northAlias = makeGroup("g-6", "Ops North", "#ops_north@acme.rine.network");
		expect(() => matchGroupByName([north, northAlias], "Ops North")).toThrow(
			/is ambiguous/,
		);
		try {
			matchGroupByName([north, northAlias], "Ops North");
		} catch (e) {
			const message = (e as Error).message;
			expect(message).toContain("#ops-north@acme.rine.network");
			expect(message).toContain("#ops_north@acme.rine.network");
		}
	});

	it("never falls through from an ambiguous tier to a looser one", () => {
		// Both groups match the prefix tier; a third, longer group would match
		// nothing. If the ambiguity fell through, the refusal would disappear.
		const a = makeGroup("g-7", "Ops one", "#ops-one@acme.rine.network");
		const b = makeGroup("g-8", "Ops two", "#ops-two@acme.rine.network");
		expect(() => matchGroupByName([a, b], "ops")).toThrow(/is ambiguous/);
	});
});

describe("matchGroupByName tier 4", () => {
	// The rung that peels a word naming the KIND of thing a group is. It fires
	// only when tiers 1–3 matched NOTHING, so every test here has to prove two
	// things at once: that the peel happens, and that it never gets to overrule
	// a group that answered on a stricter rung.
	const OPS = makeGroup("g-ops", "Ops", "#ops@acme.rine.network");

	it("resolves a reference whose trailing classifier is the only mismatch", () => {
		expect(matchGroupByName([OPS, LABELS], "ops group").id).toBe("g-ops");
		expect(matchGroupByName([OPS, LABELS], "ops channel").id).toBe("g-ops");
		expect(matchGroupByName([OPS, LABELS], "the ops room").id).toBe("g-ops");
	});

	it("lets a group that legitimately ends in a classifier win on tier 2", () => {
		// `#ops-group` answers to `ops group` outright. If tier 4 could be reached
		// while a stricter rung had a match, the peel would hand the reference to
		// `#ops` instead — a different group, in the same org, for a reference
		// that was never ambiguous.
		const opsGroup = makeGroup("g-og", "Ops group", "#ops-group@acme.rine.network");
		expect(matchGroupByName([OPS, opsGroup], "ops group").id).toBe("g-og");
	});

	it("lets a longer group win on tier 3 rather than peeling to a shorter one", () => {
		const opsGroupB = makeGroup("g-ogb", "Ops group b", "#ops-group-b@acme.rine.network");
		expect(matchGroupByName([OPS, opsGroupB], "ops group").id).toBe("g-ogb");
	});

	it("peels one segment at a time, so the longest surviving reference decides", () => {
		// 🔴 `ops-chat-room` → `ops-chat` → `ops`, re-running the ladder between
		// each step. A single whole-run strip would yield `ops` immediately and
		// steal the answer from the group that answers to more of what was typed.
		const opsChat = makeGroup("g-oc", "Ops chat", "#ops-chat@acme.rine.network");
		expect(matchGroupByName([OPS, opsChat], "ops chat room").id).toBe("g-oc");
	});

	it("keeps peeling when the first remainder answers to nothing", () => {
		// Same reference, and now nothing answers to `ops-chat`: the walk goes on
		// to `ops`. The other group is a content word this set will never peel.
		const opsTeam = makeGroup("g-ot", "Ops team", "#ops-team@acme.rine.network");
		expect(matchGroupByName([OPS, opsTeam], "ops chat room").id).toBe("g-ops");
	});

	it("does not peel a trailing word the set leaves out", () => {
		// The twin of `test_a_word_outside_the_set_when_trailing_then_is_not_peeled`
		// on the Python side, and the bound the word-set binder cannot give: that
		// pin drives TS from the PYTHON-declared set, so it proves every declared
		// word IS peeled and nothing about words that are not declared. Without
		// this, widening the set on one stack alone fails one suite and passes the
		// other, and a one-sided red reads as the wrong test rather than the wrong
		// word. `team` is the likeliest content segment of a real handle of the
		// ones considered (`#platform-team`), which is why it is the one excluded
		// word worth pinning.
		expect(() => matchGroupByName([OPS], "ops team")).toThrow(/Group not found/);
	});

	it("drops the leading article before it drops any trailing noun", () => {
		const opsGroup = makeGroup("g-og", "Ops group", "#ops-group@acme.rine.network");
		// `the-ops-group-chat` → `ops-group-chat` → `ops-group`, which answers.
		expect(matchGroupByName([OPS, opsGroup], "the ops group chat").id).toBe("g-og");
	});

	it("refuses a reference that is nothing but classifiers", () => {
		// The peel stops while one segment is left, so none of these can reduce to
		// an empty reference and prefix-match the whole org.
		for (const nothing of ["the group", "groups", "the", "chat room"]) {
			expect(() => matchGroupByName([PLANNING, LABELS], nothing)).toThrow(
				/Group not found/,
			);
		}
	});

	it("still refuses a reference that normalises to nothing", () => {
		// The empty-normalisation guard sits in front of tier 4, and `"".split("-")`
		// is one segment, so nothing is peeled from it either.
		expect(() => matchGroupByName([PLANNING], "#")).toThrow(/Group not found/);
		expect(() => matchGroupByName([PLANNING], "---")).toThrow(/Group not found/);
	});

	it("refuses when the peeled reference answers to two groups, naming both", () => {
		const one = makeGroup("g-1a", "Ops one", "#ops-one@acme.rine.network");
		const two = makeGroup("g-1b", "Ops two", "#ops-two@acme.rine.network");
		try {
			matchGroupByName([one, two], "ops group");
			expect.unreachable("a peel landing on two groups must refuse");
		} catch (e) {
			const message = (e as Error).message;
			expect(message).toContain("#ops-one@acme.rine.network");
			expect(message).toContain("#ops-two@acme.rine.network");
			// 🔴 The caller's OWN spelling, never the peeled remainder: both entry
			// points pass the original `name` beside the prepared reference, so a
			// tier-4 refusal still quotes what was actually written.
			expect(message).toContain("Group name 'ops group' is ambiguous");
			expect(message).not.toContain("'ops' is ambiguous");
		}
	});

	it("quotes the caller's own spelling when the peel resolves nothing either", () => {
		expect(() => matchGroupByName([PLANNING], "invoices group")).toThrow(
			"Group not found: invoices group.",
		);
	});

	it("reaches the bare-recipient entry point too", () => {
		// One ladder, both entry points — the reason tier 4 lives inside
		// `groupReferenceMatches` and not at either door.
		expect(recipientGroupForBareName([OPS, LABELS], "the ops channel").id).toBe(
			"g-ops",
		);
	});
});

describe("matchGroupByName refusals", () => {
	it("lists the caller's groups when nothing matches", () => {
		try {
			matchGroupByName([PLANNING, LABELS], "invoices");
			expect.unreachable("a reference matching nothing must refuse");
		} catch (e) {
			const message = (e as Error).message;
			expect(message.startsWith("Group not found")).toBe(true);
			expect(message).toContain("Quarterly planning");
			expect(message).toContain("#shipping-labels@acme.rine.network");
		}
	});

	it("says so when the org is in no groups at all", () => {
		// The half a hand-rolled refusal keeps dropping: without it the sentence
		// ends "Name one of these groups:" and then simply stops.
		expect(() => matchGroupByName([], "invoices")).toThrow(
			"Group not found: invoices. This org is in no groups yet.",
		);
	});

	it("caps the roster instead of printing every group", () => {
		const many = Array.from({ length: MAX_LISTED_GROUPS + 5 }, (_, i) =>
			makeGroup(`g-${i}`, `Team ${i}`, `#team-${i}@acme.rine.network`),
		);
		try {
			matchGroupByName(many, "invoices");
			expect.unreachable("a reference matching nothing must refuse");
		} catch (e) {
			const message = (e as Error).message;
			expect(message).toContain("… and 5 more");
			expect(message.split("\n")).toHaveLength(MAX_LISTED_GROUPS + 2);
		}
	});

	it("prints no empty parentheses for a group carrying no name", () => {
		// No row `POST /groups` can mint reaches this — `groups.name` is
		// `nullable=False` and `GroupRead` types it `string`, which is why the
		// fixture has to be cast into existence. It is asserted anyway because
		// the branch is a guard against a WIRE that contradicts its own type,
		// and the alternative output is `  - #… (undefined)`: a refusal naming
		// a group nobody can name back. `bob (null)` is the actor-side
		// precedent for the shape, not for the nullability — `agents.handle`
		// really is nullable and `groups.handle` is not.
		const unnamed = { ...LABELS, name: "" } as GroupRead;
		try {
			matchGroupByName([unnamed], "invoices");
			expect.unreachable("a reference matching nothing must refuse");
		} catch (e) {
			expect((e as Error).message).toContain(
				"  - #shipping-labels@acme.rine.network",
			);
			expect((e as Error).message).not.toContain("()");
		}
	});
});

describe("isBareReference", () => {
	it("claims exactly what the agent namespace refuses on syntax", () => {
		expect(isBareReference("quarterly planning")).toBe(true);
		expect(isBareReference("bot@acme.rine.network")).toBe(false);
		expect(isBareReference("#quarterly-planning-401@acme")).toBe(false);
		expect(isBareReference("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")).toBe(false);
	});

	it("leaves a blank recipient to the agent resolver", () => {
		// "Expected a UUID or handle" answers an empty recipient far better than
		// a hunt through the caller's groups ending in "no group is called ''".
		expect(isBareReference("   ")).toBe(false);
	});
});

function clientReturning(agents: AgentRead[], groups: GroupRead[]) {
	const calls: unknown[][] = [];
	const get = vi.fn(async (...args: unknown[]) => {
		calls.push(args);
		return args[0] === "/agents" ? { items: agents } : { items: groups };
	});
	return { client: { get } as unknown as HttpClient, calls };
}

const OPS_AGENT: AgentRead = {
	id: "a-1",
	name: "ops",
	handle: "ops@acme.rine.network",
	human_oversight: false,
	incoming_policy: "open",
	outgoing_policy: "open",
	created_at: "2026-01-01T00:00:00Z",
};

describe("resolveBareRecipientGroup", () => {
	it("resolves a bare recipient to the group it names", async () => {
		const { client } = clientReturning([], [PLANNING, LABELS]);
		const group = await resolveBareRecipientGroup(client, "shipping labels");
		expect(group.handle).toBe("#shipping-labels@acme.rine.network");
	});

	it("refuses a name that is an agent's, printing the handle that would work", async () => {
		// The dropped-`@org` case: `send("ops")` meaning `ops@acme`. Posting that
		// to a group called `ops` would be a silent misdelivery on an E2EE
		// product, so it refuses and names the spelling the caller meant.
		const groupCalledOps = makeGroup("g-9", "Ops", "#ops@acme.rine.network");
		const { client } = clientReturning([OPS_AGENT], [groupCalledOps]);
		await expect(resolveBareRecipientGroup(client, "ops")).rejects.toThrow(
			/ops@acme\.rine\.network/,
		);
	});

	it("names the group in the caller's own org, not in a slot to fill in", () => {
		// Derived from the handle the sentence before it printed, so the caller
		// can paste it. `#name@org` read as a form and came back half-filled.
		expect(() => refuseIfABareAgentName([OPS_AGENT], "ops")).toThrow(
			"To post to a group of that name, write it as #ops@acme.rine.network.",
		);
	});

	it("folds the caller's own case into a group handle that could exist", () => {
		// 🔴 The paste is the point, and only the folded spelling can ever
		// resolve: a group name is a lowercase DNS slug server-side and the
		// handle lookup is an exact match, so `#OPS@…` names no group that can
		// exist. Pinned on both stacks — the twin binder stops before this tail.
		expect(() => refuseIfABareAgentName([OPS_AGENT], "OPS")).toThrow(
			"To post to a group of that name, write it as #ops@acme.rine.network.",
		);
	});

	it("answers the sigil form of the caller's own word when the org has no slug", () => {
		// 🔴 This arm used to print `#logistics@acme.rine.network` and label
		// it an example — a placeholder domain inside a refusal, banned. `#ops` is
		// the substitute because it is a real next step and not a hedge: the sigil
		// form is a first-class recipient spelling, it is the one spelling this
		// guard is deliberately skipped for, and it needs no org half — which is
		// the whole of what "slugless" means. The caller of a slugless org stops
		// being shown the whole-handle form; every org that HAS a slug still sees
		// it, derived, in the arm above.
		const noHandle: AgentRead = { ...OPS_AGENT, handle: null };
		expect(() => refuseIfABareAgentName([noHandle], "ops")).toThrow(
			"To post to a group of that name, write it as #ops.",
		);
	});

	it("describes both spellings when no group answers either, and shows neither", async () => {
		// 🔴 The placeholder ban, second rung. This assertion used to be the
		// opposite one — that both halves are COMPLETE handles rather than forms
		// with `org` left standing. The other end of that argument was measured:
		// with a whole handle printed, the local part
		// moved with the conversation and the domain did not move at all, so what
		// a model pastes back is the placeholder. The advice survives;
		// the two example handles do not.
		const { client } = clientReturning([], [LABELS]);
		// Resolving is the failure this test is written against, so the success
		// arm answers the empty string and every assertion below it goes red —
		// rather than a `catch` whose union type is a group row.
		const refusal = await resolveBareRecipientGroup(client, "invoices").then(
			() => "",
			(error: Error) => error.message,
		);

		expect(refusal).toContain(
			"An agent is addressed in full — its name, an at sign, and its org's " +
				"domain — and a group by its whole handle, which is a leading hash " +
				"and the same three parts.",
		);
		// 🔴 The arm that makes this a BAN rather than a rewording, and the reason
		// it reads `@` and not one domain: a later edit that reintroduced any
		// worked handle — `kofi@acme…`, `#logistics@acme…`, or a freshly invented
		// one — would pass an assertion written against the string it deleted.
		//
		// Scoped to the SENTENCE, not the whole refusal: everything under
		// `GROUP_ROSTER_LEAD` is the caller's own roster, and those handles are
		// real rows this org holds. Naming them is the point; inventing
		// one is what the placeholder ban forbids, and the split is where the two
		// stop overlapping.
		const [sentence] = refusal.split(GROUP_ROSTER_LEAD);
		expect(sentence).toBeTruthy();
		expect(sentence).not.toContain("@");
	});
});

describe("the Python twin", () => {
	// The two stacks share no module, so the binding is a test — the shape
	// `thread-ref.test.ts` already uses in this direction and
	// `rine-sdk/tests/test_actor_contract.py` uses in the other. What drifts here
	// is not a crash: it is one reference resolving on the SDK a caller does not
	// use, or two surfaces refusing the same word in two wordings, and nothing
	// else in either suite would notice.
	const py = readFileSync(
		new URL("../../rine-sdk/src/rine/_group_ref.py", import.meta.url).pathname,
		"utf8",
	);

	/** Join a Python implicit-concatenation of string literals into one string. */
	function joined(block: string): string {
		return (block.match(/(['"])(?:\\.|(?!\1).)*\1/g) ?? [])
			.map((lit) => lit.slice(1, -1).replace(/\\(.)/g, "$1"))
			.join("");
	}

	/** The value of a module-level Python string constant. */
	function constant(name: string): string {
		return joined(py.match(new RegExp(`^${name} = (.+)$`, "m"))?.[1] ?? "");
	}

	/**
	 * The literals a named function passes to its refusal builder or raise.
	 *
	 * The emptiness check is the test: `toThrow(substring)` passes vacuously on
	 * an empty expectation, so a regex that stopped matching a renamed Python
	 * function would turn every assertion below into a green no-op rather than
	 * into the drift report they exist to be.
	 */
	function refusalIn(fn: string, opener: string, closer: string): string {
		const found = py.match(
			new RegExp(`def ${fn}\\b[\\s\\S]*?${opener}([\\s\\S]*?)${closer}`),
		);
		const literals = joined(found?.[1] ?? "");
		expect(literals.length).toBeGreaterThan(0);
		return literals;
	}

	it("opens every refusal with the same three sentences", () => {
		expect(constant("GROUP_NOT_FOUND_LEAD")).toBe(GROUP_NOT_FOUND_LEAD);
		expect(constant("NEITHER_NAMESPACE_LEAD")).toBe(NEITHER_NAMESPACE_LEAD);
		expect(constant("GROUP_ROSTER_LEAD")).toBe(GROUP_ROSTER_LEAD);
		expect(constant("NO_GROUPS_IN_ORG")).toBe(NO_GROUPS_IN_ORG);
	});

	it("caps both rosters at the same length", () => {
		// A contract value, not a taste: a caller comparing the two stacks'
		// answers to one reference must be shown the same list.
		expect(Number(py.match(/^MAX_LISTED_GROUPS = (\d+)$/m)?.[1])).toBe(
			MAX_LISTED_GROUPS,
		);
	});

	it("prints a roster row in the same two columns", () => {
		// Bound by the RENDERED row, never by the Python locals that fill it.
		// The contract is "two spaces, a dash, the handle, then the name in
		// parentheses"; renaming the twin's `label` is a refactor whose output
		// is byte-identical, and a twin test that goes red on it — in a package
		// with no Python in it — is a twin test somebody deletes.
		const templates = [
			...py.matchAll(/f"( {2}- \{[^}]+\}(?: \(\{[^}]+\}\))?)"/g),
		].map((found) => found[1] as string);
		expect(templates).toHaveLength(2);
		const fill = (template: string, values: string[]) => {
			let next = 0;
			return template.replace(/\{[^}]+\}/g, () => values[next++] ?? "");
		};
		expect(() => matchGroupByName([LABELS], "invoices")).toThrow(
			fill(templates[0] as string, [LABELS.handle, LABELS.name]),
		);
		expect(() =>
			matchGroupByName([{ ...LABELS, name: "" } as GroupRead], "invoices"),
		).toThrow(fill(templates[1] as string, [LABELS.handle]));
	});

	it("refuses an ambiguous reference in the same words", () => {
		const north = makeGroup("g-a", "Ops", "#ops@acme.rine.network");
		const south = makeGroup("g-b", "Ops", "#ops@beta.rine.network");
		const lead = refusalIn(
			"ambiguous_group_refusal",
			"compose_group_refusal\\(",
			", matches",
		).replace("{name}", "ops");
		expect(() => matchGroupByName([north, south], "ops")).toThrow(
			`${lead} ${GROUP_ROSTER_LEAD}`,
		);
	});

	it("tells a bare recipient about both namespaces in the same words", () => {
		const lead = refusalIn(
			"recipient_group_for_bare_name",
			"compose_group_refusal\\(\\s*",
			",\\n\\s*groups,",
		)
			.replace("{NEITHER_NAMESPACE_LEAD}", NEITHER_NAMESPACE_LEAD)
			.replace("{name}", "invoices");
		expect(() => recipientGroupForBareName([], "invoices")).toThrow(
			`${lead} ${NO_GROUPS_IN_ORG}`,
		);
	});

	/**
	 * A literal set constant, lifted out of a source file by name.
	 *
	 * The emptiness check is the test, exactly as in `refusalIn`: a regex that
	 * stopped matching — because a constant was renamed, or its literal form
	 * changed — would otherwise compare `[]` against `[]` and report parity
	 * between two sets it never read.
	 */
	function wordSet(source: string, declaration: string): string[] {
		const block = source.match(new RegExp(`${declaration}([\\s\\S]*?)[\\]}]`, "m"));
		const words = [...(block?.[1] ?? "").matchAll(/"([^"]+)"/g)].map(
			(m) => m[1] as string,
		);
		expect(words.length).toBeGreaterThan(0);
		return words.sort();
	}

	// This stack's own sets are read out of the source rather than imported: they
	// are module-private, `index.ts` re-exports this file with `export *`, and
	// widening `@rine-network/core`'s published surface to let a test see a
	// constant is a worse trade than a regex.
	const ts = readFileSync(
		new URL("../src/group-ref.ts", import.meta.url).pathname,
		"utf8",
	);

	it("peels the same words on both stacks", () => {
		// 🔴 The pin that stops the two sets drifting. Nothing else could catch
		// it: a word added on one side only is not a crash, it is one reference
		// resolving on the SDK a caller did not happen to pick.
		for (const name of ["GENERIC_GROUP_NOUNS", "LEADING_ARTICLES"]) {
			expect(wordSet(ts, `const ${name}: ReadonlySet<string> = new Set\\(\\[`)).toEqual(
				wordSet(py, `^${name} = frozenset\\(\\s*\\{`),
			);
		}
	});

	it("actually peels every word it declares", () => {
		// Set equality alone would be satisfied by two sets that are declared and
		// never read. Each noun has to reach the behaviour, on this stack, for the
		// pin above to mean anything.
		const ops = makeGroup("g-w", "Ops", "#ops@acme.rine.network");
		for (const noun of wordSet(py, "^GENERIC_GROUP_NOUNS = frozenset\\(\\s*\\{")) {
			expect(matchGroupByName([ops, LABELS], `ops ${noun}`).id).toBe("g-w");
		}
		for (const article of wordSet(py, "^LEADING_ARTICLES = frozenset\\(\\s*\\{")) {
			expect(matchGroupByName([ops, LABELS], `${article} ops`).id).toBe("g-w");
		}
	});

	it("refuses an agent's name in the same words", () => {
		// Two scans and not one, because the twin hands this refusal to a
		// composer in two parts and the SEAM between them belongs to neither
		// sentence. Putting the two Python literals back together through THIS
		// stack's composer is what keeps punctuation out of a test about words:
		// the words come from the Python source, the join comes from the product,
		// and the join's own bytes are compared across the two stacks by
		// `recipient-refusal-golden.test.ts`.
		const detail = refusalIn(
			"refuse_if_a_bare_agent_name",
			"compose_group_refusal\\(\\s*",
			",\\n\\s*next_step=",
		);
		const nextStep = refusalIn(
			"refuse_if_a_bare_agent_name",
			"next_step=\\(\\s*",
			"\\n\\s*\\),",
		);
		const expected = composeGroupRefusal({
			lead: (said) => detail.replace("{name}", said),
			spelling: "ops",
			nextStep,
		}).replace("{spellings}", OPS_AGENT.handle ?? "");
		// The closing sentence names the group in the CALLER's own org, derived
		// from the handles the sentence before it just printed, so its slot is a
		// local whose name is each stack's own business. The twin binds the
		// prefix both stacks render identically; the derived tail is pinned
		// against this stack's own output above.
		const slot = expected.indexOf("{");
		const shared = slot === -1 ? expected : expected.slice(0, slot);
		expect(shared.length).toBeGreaterThan(0);
		expect(() => refuseIfABareAgentName([OPS_AGENT], "ops")).toThrow(shared);
	});
});
