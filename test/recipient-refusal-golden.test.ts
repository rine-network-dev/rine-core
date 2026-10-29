import * as fs from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import type { AgentRead, GroupRead } from "../src/api-types.js";
import { RineApiError } from "../src/errors.js";
import {
	GROUP_ROSTER_LEAD,
	NO_GROUPS_IN_ORG,
	THREAD_REF_SURFACES,
	type ThreadRefSurface,
	bareNameJoinRefusal,
	recipientGroupForBareName,
	resolveGroup,
	unknownGroupRefusal,
	unresolvedHandleJoinRefusal,
} from "../src/index.js";
import { refuseIfABareAgentName } from "../src/group-ref.js";
import { composeGroupRefusal } from "../src/recipient-refusal.js";
import { notAConversationUuidRefusal } from "../src/thread-ref.js";
import { invalidAgentIdentifierRefusal, resolveToUuid } from "../src/resolve-agent.js";

/**
 * The TypeScript half of the cross-stack refusal-parity gate.
 *
 * 🔴 A source-parse pin cannot prove refusal parity. The join contract is the
 * proof: six sentences and two numbers are pinned across the two stacks by
 * `tests/test_client-server-contract_group0.py`, and the stacks still disagreed
 * about `##ops` for months. What a caller actually reads is a COMPOSED string,
 * and the only honest way to compare two implementations of it is to run both
 * over the same inputs and diff the bytes.
 *
 * So: one committed fixture, replayed here and by
 * `rine-sdk/tests/contract/test_recipient_refusal_golden.py`. Both replays are
 * reached by `ci.sh` — this one at stage 11 (rine-core vitest), the other at
 * stage 4 — which is the gap the precedent fixture
 * (`tests/test_verification-words-golden_group0.py`) still has and this one
 * closes.
 *
 * The vectors are pure input → sentence. No HTTP, no client, no server: every
 * slot below is a function of a roster, an agent list and a spelling, which is
 * exactly the surface the two stacks are supposed to share.
 */

/**
 * The goldens sit beside this suite, and that placement is the guard.
 *
 * 🔴 A conditional read is not an option here, whatever it looks like. A suite
 * factory runs during COLLECTION and its mode is consulted afterwards, so
 * `describe.skipIf(...)` around a body whose first statement reads a file does
 * not skip a missing file — it fails the whole suite to collect, and anyone
 * running this package standalone gets a broken run and an error naming a
 * directory they cannot have. Keeping the vectors inside the package removes
 * that condition rather than guarding it: the fixture travels wherever the test
 * does, so its absence is never a checkout shape and always a deletion, which
 * fails loudly below.
 */
const FIXTURE = new URL("./fixtures/refusal-vectors.json", import.meta.url);

interface Vector {
	id: string;
	slot: string;
	spelling: string;
	lead?: string;
	next_step?: string;
	unread?: number;
	surface?: keyof typeof THREAD_REF_SURFACES;
	candidates: unknown[];
	agents: unknown[];
	expected?: string | null;
	divergence?: string;
	ts?: string | null;
	py?: string | null;
}

/**
 * The by-id disclosure vector — a status, not a roster, is what it varies.
 *
 * Deliberately a second shape rather than more optional fields on
 * {@link Vector}: this one is not composed, it is DRIVEN, and a slot union that
 * held both would let a `compose()` arm be written for something that has no
 * pure form.
 */
interface DisclosureVector {
	id: string;
	spelling: string;
	candidates: unknown[];
	indistinguishable: number[];
	propagated: number[];
	expected?: string | null;
}

/**
 * The by-id substitution vector — a BODY, not a status and not a roster.
 *
 * A third shape for the same reason {@link DisclosureVector} is a second one:
 * this is driven rather than composed, and what it varies is what
 * `GET /groups/{id}` replied with. `error` is the raise's TYPE NAME, because the
 * ruling is a typed raise and a bare `Error` carrying the right words would
 * satisfy a byte comparison on its own.
 */
interface SubstitutionVector {
	id: string;
	spelling: string;
	answered: Record<string, unknown>;
	roster: unknown[];
	error: string;
	expected?: string | null;
}

interface Fixture {
	vectors: Vector[];
	by_id_disclosure: { note: string; vectors: DisclosureVector[] };
	by_id_substitution: { note: string; vectors: SubstitutionVector[] };
	excluded: { reason: string; vectors: Vector[] };
}

const REGENERATE = process.env.RINE_REFUSAL_REGEN === "1";

function read(): Fixture {
	const path = fileURLToPath(FIXTURE);
	if (!fs.existsSync(path)) {
		throw new Error(
			`refusal vectors missing at ${path} — restore them (git checkout) or ` +
				"regenerate with RINE_REFUSAL_REGEN=1 on BOTH stacks. Deleting this " +
				"suite instead removes the only cross-stack comparison of composed text.",
		);
	}
	return JSON.parse(fs.readFileSync(path, "utf8")) as Fixture;
}

/**
 * The rows the product renders for a roster, taken FROM the product.
 *
 * `formatGroupList` is module-private and stays that way: it owns
 * `MAX_LISTED_GROUPS` and the overflow row, and a second renderer written here
 * would make this gate agree with itself instead of with `rine-core`. The
 * composer prints `sentence\nrows`, so everything after the first newline of a
 * refusal that carries a roster IS the rows.
 */
function rosterRows(groups: GroupRead[]): string {
	const [, ...rows] = unknownGroupRefusal(groups, "x").split("\n");
	expect(rows.length).toBeGreaterThan(0);
	return rows.join("\n");
}

/** The refusal a thrower raised, or `null` if it raised none. */
function refusalFrom(act: () => unknown): string | null {
	try {
		act();
		return null;
	} catch (error) {
		return (error as Error).message;
	}
}

/**
 * What this stack composes for one vector.
 *
 * The fixture's `candidates`/`agents` carry exactly the three fields a refusal
 * reads — `id`, `name`, `handle` — so the cast is the vector's whole contract
 * with the wire types rather than a hole in it: a renderer that started reading
 * a fourth field would read `undefined` here and the golden would move.
 */
function compose(vector: Vector): string | null {
	const groups = vector.candidates as GroupRead[];
	const agents = vector.agents as AgentRead[];
	const lead = (said: string) => (vector.lead ?? "").replace("{spelling}", said);
	const spelling = vector.spelling;
	switch (vector.slot) {
		case "unknown_group":
			return unknownGroupRefusal(groups, spelling);
		case "bare_recipient_group":
			return refusalFrom(() => recipientGroupForBareName(groups, spelling));
		case "bare_agent_collision":
			return refusalFrom(() => refuseIfABareAgentName(agents, spelling));
		case "compose_bare":
			return composeGroupRefusal({ lead, spelling });
		case "compose_next_step_no_roster":
			return composeGroupRefusal({ lead, spelling, nextStep: vector.next_step });
		case "compose_next_step_under_roster":
			return composeGroupRefusal({
				lead,
				spelling,
				candidates: {
					rows: rosterRows(groups),
					rosterLead: GROUP_ROSTER_LEAD,
					whenEmpty: NO_GROUPS_IN_ORG,
				},
				nextStep: vector.next_step,
			});
		case "compose_next_step_empty_roster":
			return composeGroupRefusal({
				lead,
				spelling,
				candidates: { rows: "", rosterLead: GROUP_ROSTER_LEAD, whenEmpty: NO_GROUPS_IN_ORG },
				nextStep: vector.next_step,
			});
		case "invalid_agent_identifier":
			return invalidAgentIdentifierRefusal(spelling);
		case "join_bare_name":
			return bareNameJoinRefusal(spelling);
		case "join_unresolved_handle": {
			// Read off the vector and not defaulted: `unread` picks WHICH middle
			// sentence is spliced in, so a vector that lost the field would compose
			// the other arm's golden and read as a product regression.
			expect(vector.unread, `${vector.id} must say how many rows went unread`).toBeTypeOf(
				"number",
			);
			return unresolvedHandleJoinRefusal(spelling, vector.unread);
		}
		case "not_a_conversation_uuid": {
			// The vector names its surface because this stack parameterises the two
			// parameter spellings and the Python twin hardcodes the tool ones. The
			// lookup is on the fixture's own key and is not defaulted: this
			// function's own default is `sdk`, so a vector that lost the field
			// would compare a `conversationId` sentence against Python's
			// `conversation_id` one and report a divergence that is the fixture's.
			const surface: ThreadRefSurface | undefined =
				THREAD_REF_SURFACES[vector.surface as keyof typeof THREAD_REF_SURFACES];
			if (!surface) {
				throw new Error(`unknown thread surface '${vector.surface}' in vector '${vector.id}'`);
			}
			return notAConversationUuidRefusal(spelling, surface);
		}
		default:
			throw new Error(`unknown refusal slot '${vector.slot}' in vector '${vector.id}'`);
	}
}

/**
 * What the seated resolver says when `GET /groups/{id}` answers `status`.
 *
 * The real `resolveGroup` over a stub transport, never a hand-composed
 * sentence: the rule being pinned is a mapping from a STATUS to a refusal, so a
 * helper that composed the refusal itself would make the gate agree with the
 * gate.
 */
async function refusedById(vector: DisclosureVector, status: number): Promise<string> {
	const client = {
		get: vi.fn(async (path: string) => {
			if (path === "/groups") return { items: vector.candidates as GroupRead[] };
			throw new RineApiError(status, "refused");
		}),
	} as never;
	return await resolveGroup(client, vector.spelling).then(
		() => {
			throw new Error(`${vector.id}: ${status} resolved instead of refusing`);
		},
		(error: Error) => error.message,
	);
}

/**
 * What the seated resolver does when `GET /groups/{id}` answers about another
 * group, and every path it asked on the way.
 *
 * The real `resolveGroup` over a stub transport, for the same reason
 * {@link refusedById} is: the rule is a mapping from a BODY to a raise, so a
 * helper that threw the error itself would make the gate agree with the gate.
 */
async function substituted(
	vector: SubstitutionVector,
): Promise<{ error: Error; paths: string[] }> {
	const paths: string[] = [];
	const client = {
		get: vi.fn(async (path: string) => {
			paths.push(path);
			if (path === "/groups") return { items: vector.roster as GroupRead[] };
			return vector.answered;
		}),
	} as never;
	return await resolveGroup(client, vector.spelling).then(
		() => {
			throw new Error(`${vector.id}: a substituted body resolved instead of raising`);
		},
		(error: Error) => ({ error, paths }),
	);
}

describe("the refusal vectors, replayed on this stack", () => {
	const fixture = read();

	if (REGENERATE) {
		it("regenerates its own field, and never the shared golden", () => {
			// 🔴 `expected` is written by the PYTHON replay alone, and this stack
			// only ever checks it. Two writers to one field is a fixture that
			// unifies a real divergence on whichever regeneration ran last — the
			// exact bending this gate exists to prevent, and it happened once
			// while this file was being written. With one writer, a stack that
			// disagrees goes RED and somebody has to decide whether the vector is
			// a defect or belongs in the excluded set.
			for (const vector of fixture.excluded.vectors) vector.ts = compose(vector);
			fs.writeFileSync(fileURLToPath(FIXTURE), `${JSON.stringify(fixture, null, 2)}\n`);
			expect(fixture.excluded.vectors.length).toBeGreaterThan(0);
		});
	}

	it("holds vectors at all", () => {
		// An empty fixture passes every assertion below it, and a fixture that
		// lost its excluded set has silently deleted a known divergence rather
		// than fixed one.
		expect(fixture.vectors.length).toBeGreaterThan(0);
		expect(fixture.excluded.vectors.length).toBeGreaterThan(0);
		expect(fixture.excluded.reason).toBeTruthy();
		expect(fixture.by_id_disclosure.vectors.length).toBeGreaterThan(0);
		expect(fixture.by_id_disclosure.note).toBeTruthy();
		expect(fixture.by_id_substitution.vectors.length).toBeGreaterThan(0);
		expect(fixture.by_id_substitution.note).toBeTruthy();
	});

	it.each(fixture.by_id_substitution.vectors.map((vector) => [vector.id, vector] as const))(
		"refuses %s with the typed raise the Python stack raises, to the byte",
		async (_id, vector) => {
			// 🔴 The seated resolver reads a row out of the answered body, and five
			// further surfaces route through it — an unchecked body would put every
			// downstream group verb on a group the caller never asked about. The
			// TYPE is asserted as well as the sentence because the rule is a typed
			// raise: a bare `Error` carrying the right words would
			// pass a byte comparison alone, and `rine-sdk` raises
			// `GroupIdentityMismatchError` for the same body.
			expect(vector.expected, `${vector.id} has no golden — regenerate`).toBeTruthy();
			const { error } = await substituted(vector);

			expect(error.message).toBe(vector.expected);
			expect(error.name).toBe(vector.error);
		},
	);

	it.each(fixture.by_id_substitution.vectors.map((vector) => [vector.id, vector] as const))(
		"buys no roster to say %s, because a server fault is not a missing group",
		async (_id, vector) => {
			// ⚠️ The bound the arm above cannot state. Falling through to
			// `unknownGroupRefusal` would answer a substituted body with "Group not
			// found" — and buy the unpaginated roster to say it with — sending a
			// caller off to re-spell a reference that was right while the
			// substitution went unreported. Each vector's roster deliberately HOLDS
			// the asked-for group, so a fall-through would compose a plausible
			// sentence rather than an obviously wrong one.
			const { paths } = await substituted(vector);

			expect(paths).toEqual([`/groups/${vector.spelling}`]);
		},
	);

	it.each(fixture.by_id_disclosure.vectors.map((vector) => [vector.id, vector] as const))(
		"answers %s with one sentence whatever status said so, and it is the Python one",
		async (_id, vector) => {
			// 🔴 The disclosure rule, in bytes. `GET /groups/{id}` 404s an id no
			// group carries and 403s one carried by a group of an org this caller is
			// neither owner of nor seated in; telling those apart would tell a
			// stranger which unknown ids EXIST — the non-member lookup the protocol
			// refuses to add, arrived at by reading a status code instead of a
			// route. `resolve-group-handle.test.ts` asserts the same rule on this
			// stack alone — what this adds is that the sentence is byte-identical to
			// the one `rine-sdk` composes, so "improve the 403 message" on ONE stack
			// is a failure rather than a silent divergence.
			expect(vector.expected, `${vector.id} has no golden — regenerate`).toBeTruthy();
			const said = await Promise.all(
				vector.indistinguishable.map((status) => refusedById(vector, status)),
			);

			expect(new Set(said).size, `the statuses are distinguishable: ${said.join(" | ")}`).toBe(1);
			expect(said[0]).toBe(vector.expected);
		},
	);

	it.each(fixture.by_id_disclosure.vectors.map((vector) => [vector.id, vector] as const))(
		"lets a status outside %s's rule through as itself",
		async (_id, vector) => {
			// ⚠️ The bound the rule needs. A blanket catch would answer a 500 with
			// "Group not found" — and buy the unpaginated roster to say it with —
			// sending a caller off to re-spell an id that was never the problem. The
			// assertion above cannot see that: swallowing MORE statuses makes it
			// greener, not redder.
			for (const status of vector.propagated) {
				const client = {
					get: vi.fn(async (path: string) => {
						if (path === "/groups") return { items: vector.candidates as GroupRead[] };
						throw new RineApiError(status, "boom");
					}),
				} as never;

				await expect(resolveGroup(client, vector.spelling)).rejects.toMatchObject({ status });
			}
		},
	);

	it.each(fixture.vectors.map((vector) => [vector.id, vector] as const))(
		"composes %s exactly as the Python stack does",
		(_id, vector) => {
			expect(vector.expected, `${vector.id} has no golden — regenerate`).not.toBeUndefined();
			expect(compose(vector)).toBe(vector.expected);
		},
	);

	it.each(fixture.excluded.vectors.map((vector) => [vector.id, vector] as const))(
		"composes %s the way this stack diverges, and says why",
		(_id, vector) => {
			// The excluded set is PINNED, not skipped: this stack's own recorded
			// string is asserted, so the divergence cannot drift while nobody is
			// looking, and the day the two agree the vector moves into the shared
			// set rather than quietly starting to pass.
			expect(vector.ts, `${vector.id} has no recorded output — regenerate`).not.toBeUndefined();
			expect(vector.divergence, `${vector.id} must state its divergence`).toBeTruthy();
			expect(compose(vector)).toBe(vector.ts);
			expect(vector.ts).not.toBe(vector.py);
		},
	);
});

/**
 * 🔴 Its own suite, deliberately, and its Python twin
 * (`test_the_agent_resolver_when_given_a_bare_name_then_it_raises_the_gated_sentence`)
 * stands outside that stack's fixture guard for the same reason.
 *
 * Nothing here reads the fixture — it is a spelling and a function — so this is
 * the one assertion binding the composed sentence to a SHIPPED caller that runs
 * wherever the package does, whatever any golden replay above it can reach.
 */
describe("the refusal a shipped resolver raises", () => {
	it("comes from the composer, not from a second copy of the sentence", async () => {
		// The slots above pin a composer; this pins that `resolveToUuid` still
		// uses it. Without it, extracting the sentence would have left the golden
		// comparing a helper no caller reaches — a gate agreeing with itself.
		// `apiUrl` is never touched: a spelling with no `@` is refused on syntax
		// before any request, which is what lets the fixture stay pure input →
		// sentence while the thrower is async.
		//
		// 🔴 `toThrowError(new Error(...))` and not `toThrow(string)`: the string
		// form is a SUBSTRING match, so a resolver that appended its own
		// half-sentence to the composed one passed while diverging from the
		// Python twin, whose assertion is `==`. The gate must be as strict as the
		// stack it is compared against.
		await expect(resolveToUuid("https://rine.network", "logistics")).rejects.toThrowError(
			new Error(invalidAgentIdentifierRefusal("logistics")),
		);
	});
});
