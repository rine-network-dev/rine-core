/**
 * What a caller's string names, and what a resolver answers with.
 *
 * The ladders themselves are pinned where they are written — `group-ref`,
 * `resolve-group-handle`, `resolve-group-join` — and none of those tests moved,
 * which is what makes this a consolidation rather than a change. What is
 * pinned here is the surface those ladders are now reached THROUGH: the one
 * classification table, the records the entry points answer with, and the
 * dispatch that used to be private to `rine-ts-sdk` where three other surfaces
 * could not reach it.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import type { AgentRead, GroupRead } from "../src/api-types.js";
import { RineApiError } from "../src/errors.js";
import { isBareReference, isSigilGroupReference } from "../src/group-ref.js";
import { HttpClient } from "../src/http.js";
import { resolveActor } from "../src/resolve-agent.js";
import {
	REF_CLASS,
	type RefClass,
	classifyReference,
	resolveGroup,
	resolveGroupForJoin,
	resolveRecipient,
} from "../src/recipient-resolution.js";

const OPS_ID = "11111111-1111-1111-1111-111111111111";
const LABELS_ID = "22222222-2222-2222-2222-222222222222";
const KOFI_ID = "33333333-3333-3333-3333-333333333333";
const ORG = "gqb.rine.network";
const API = "https://api.rine.network";

const OPS = group(OPS_ID, "ops", `#ops@${ORG}`);
const LABELS = group(LABELS_ID, "shipping-labels", `#shipping-labels@${ORG}`);

function group(id: string, name: string, handle: string): GroupRead {
	return { id, name, handle } as GroupRead;
}

function agent(id: string, name: string, handle: string): AgentRead {
	return { id, name, handle } as AgentRead;
}

/**
 * A client whose group reads behave like the server's: `?handle=` is an
 * equality test, the unfiltered read answers the whole org list, and
 * `GET /groups/{id}` answers one row or 404s (the UUID rung). `/agents` answers
 * the org's agents, which is what the bare-recipient collision guard asks for.
 *
 * `/groups/invites` is matched BEFORE the id route — it is a real route whose
 * path shape collides with `/groups/{id}`, and the server tells them apart by
 * declaration order for the same reason.
 */
function clientHolding(groups: GroupRead[], agents: AgentRead[] = []) {
	const get = vi.fn(
		async (
			path: string,
			params?: Record<string, unknown>,
			_headers?: Record<string, string>,
		) => {
			if (path === "/agents") return { items: agents };
			if (path === "/groups/invites") return { items: [] };
			const byId = /^\/groups\/([^/]+)$/.exec(path);
			if (byId) {
				const wanted = (byId[1] as string).toLowerCase();
				const held = groups.find((g) => g.id.toLowerCase() === wanted);
				if (held) return held;
				throw new RineApiError(404, "Group not found");
			}
			if (path !== "/groups") throw new Error(`unexpected path ${path}`);
			const asked = params?.handle as string | undefined;
			if (asked === undefined) return { items: groups };
			return { items: groups.filter((g) => g.handle === asked) };
		},
	);
	return { client: { get } as never, get };
}

type Fetches = ReturnType<typeof clientHolding>["get"];

/** The paths a resolve actually asked for, in order. */
function paths(get: Fetches): string[] {
	return get.mock.calls.map((call) => call[0]);
}

/** The query one call filtered on. */
function queryOf(get: Fetches, nth: number): Record<string, unknown> | undefined {
	return get.mock.calls[nth]?.[1];
}

/** The headers one call carried. */
function headersOf(get: Fetches, nth: number): Record<string, string> | undefined {
	return get.mock.calls[nth]?.[2];
}

describe("classifyReference", () => {
	const table: [string, RefClass][] = [
		["", REF_CLASS.empty],
		["   ", REF_CLASS.empty],
		["#ops", REF_CLASS.group],
		[`#ops@${ORG}`, REF_CLASS.group],
		[OPS_ID, REF_CLASS.id],
		[OPS_ID.toUpperCase(), REF_CLASS.id],
		[`kofi@${ORG}`, REF_CLASS.agent],
		["kofi@acme", REF_CLASS.agent],
		["ops", REF_CLASS.bare],
		["shipping-labels", REF_CLASS.bare],
	];

	for (const [value, expected] of table) {
		it(`reads ${JSON.stringify(value)} as ${expected}`, () => {
			expect(classifyReference(value)).toBe(expected);
		});
	}

	it("asks the sigil before the id, so a sigiled UUID is a group", () => {
		expect(classifyReference(`#${OPS_ID}`)).toBe(REF_CLASS.group);
	});

	it("asks empty before the sigil, so blank is never a group", () => {
		expect(classifyReference(" ")).toBe(REF_CLASS.empty);
	});

	it("never crosses namespaces: a bare word is not an agent", () => {
		expect(classifyReference("kofi")).toBe(REF_CLASS.bare);
	});

	/**
	 * 🔴 The one ordering rule with no observable consequence TODAY, pinned at
	 * the source because that is the only place it is visible: `UUID_RE` carries
	 * no `@`, so no string can reach both tests. It is pinned so the two stacks
	 * cannot drift apart the day one of them widens the uuid predicate, which is
	 * still open. Reading the source is the point, not a shortcut.
	 */
	it("asks the id test before the @ test", () => {
		const src = readFileSync(
			new URL("../src/recipient-target.ts", import.meta.url),
			"utf8",
		);
		const body = src.slice(src.indexOf("export function classifyReference"));
		const order = ["trim()", 'startsWith("#")', "UUID_RE.test", 'includes("@")'];
		const positions = order.map((probe) => body.indexOf(probe));
		expect(positions.every((at) => at > 0)).toBe(true);
		expect(positions).toEqual([...positions].sort((a, b) => a - b));
	});

	/** The send path's two predicates are views of the table, not a second one. */
	it("is the whole of what isBareReference and isSigilGroupReference ask", () => {
		const spellings = [
			"",
			"  ",
			"ops",
			"#ops",
			`#ops@${ORG}`,
			`kofi@${ORG}`,
			OPS_ID,
			`#${OPS_ID}`,
			"#",
			"@acme",
		];
		for (const value of spellings) {
			expect(isBareReference(value)).toBe(
				classifyReference(value) === REF_CLASS.bare,
			);
			expect(isSigilGroupReference(value)).toBe(
				classifyReference(value) === REF_CLASS.group && !value.includes("@"),
			);
		}
	});
});

describe("resolveGroup", () => {
	it("answers with the row, its handle and the caller's own spelling", async () => {
		const { client } = clientHolding([OPS, LABELS]);
		const target = await resolveGroup(client, "ops");
		expect(target).toEqual({
			id: OPS_ID,
			handle: `#ops@${ORG}`,
			spelling: "ops",
			row: OPS,
		});
	});

	it("quotes the handle the caller wrote, not the local part matched", async () => {
		const { client } = clientHolding([LABELS]);
		const target = await resolveGroup(client, "#shipping-labels@acme.rine.network");
		expect(target.spelling).toBe("#shipping-labels@acme.rine.network");
		expect(target.handle).toBe(`#shipping-labels@${ORG}`);
		expect(target.row).toBe(LABELS);
	});

	it("reads a UUID from the group's own route and carries the row it got back", async () => {
		const { client, get } = clientHolding([OPS, LABELS]);
		expect(await resolveGroup(client, LABELS_ID)).toMatchObject({
			id: LABELS_ID,
			handle: LABELS.handle,
			spelling: LABELS_ID,
		});
		// One indexed row, and no roster at all on the resolved path.
		expect(paths(get)).toEqual([`/groups/${LABELS_ID}`]);
	});

	it("refuses an id no group of the caller's answers to, and names theirs", async () => {
		const { client, get } = clientHolding([OPS]);
		await expect(resolveGroup(client, LABELS_ID)).rejects.toThrow(
			`Group not found: ${LABELS_ID}. Name one of these groups:\n  - #ops@${ORG} (ops)`,
		);
		// 🔴 Byte-for-byte the sentence this refusal has always carried — what
		// changed is WHEN the roster is read, never what it says — and the roster read is
		// what the second path proves was paid for here and nowhere else.
		expect(paths(get)).toEqual([`/groups/${LABELS_ID}`, "/groups"]);
	});

	it("passes extraHeaders to the rung that fetches", async () => {
		const { client, get } = clientHolding([OPS]);
		await resolveGroup(client, "ops", {
			extraHeaders: { "X-Rine-Agent": KOFI_ID },
		});
		expect(headersOf(get, 0)).toEqual({ "X-Rine-Agent": KOFI_ID });
	});

	/**
	 * Every resolved group target is a row the server served — asserted here
	 * rather than only typed.
	 *
	 * 🔴 `SeatedGroupTarget` states the guarantee to the COMPILER, and a compiler
	 * cannot see a row the resolver invented or a handle read off the caller's
	 * spelling. So every rung is run and the record checked against the row the
	 * server actually served.
	 *
	 * 🔴 **This stack has no exception**, and that is the half worth pinning: the
	 * UUID arm reads the group's own route and refuses what it will not serve, so
	 * all three rungs read and all three answer whole. The Python twin's UUID rung
	 * used to read nothing and was its one stated exception — that asymmetry was
	 * settled onto this stack's shape, and the exception left
	 * `rine-sdk/tests/contract/test_recipient_parity.py` in the same commit. A
	 * rung added here that answers without a row fails, which is what keeps the
	 * two implementations of one ladder from drifting apart again.
	 *
	 * What changed is which read the UUID rung spends, not whether it spends
	 * one, so `toBeGreaterThan(0)` still says what it said: every rung reads.
	 */
	describe("every rung answers with the handle and the row", () => {
		const rungs: [string, string][] = [
			["a bare name", "ops"],
			["a sigilled name", "#ops"],
			["an exact handle", `#ops@${ORG}`],
			["a handle whose org half is wrong", "#ops@nowhere.rine.network"],
			["a UUID", OPS_ID],
		];

		for (const [rung, reference] of rungs) {
			it(`fills the record on ${rung}`, async () => {
				const { client, get } = clientHolding([OPS, LABELS]);
				const target = await resolveGroup(client, reference);
				expect(target.id).toBe(OPS_ID);
				expect(target.row).toBe(OPS);
				expect(target.handle).toBe(`#ops@${ORG}`);
				expect(target.spelling).toBe(reference);
				// Every rung READS — including the UUID one, which is the shape
				// both stacks settled on and the Python ladder converges to.
				expect(paths(get).length).toBeGreaterThan(0);
			});
		}
	});
});

describe("resolveGroupForJoin", () => {
	it("answers with the id its own ladder found and no row it was not given", async () => {
		const { client, get } = clientHolding([]);
		expect(await resolveGroupForJoin(client, OPS_ID)).toEqual({
			id: OPS_ID,
			handle: undefined,
			spelling: OPS_ID,
			row: undefined,
		});
		expect(get).not.toHaveBeenCalled();
	});

	it("walks the join rungs, not the member ladder", async () => {
		const get = vi.fn(async (path: string) => {
			if (path === "/groups") return { items: [] };
			if (path === "/groups/invites")
				return { items: [{ group_id: OPS_ID, group_handle: `#ops@${ORG}` }] };
			throw new Error(`unexpected path ${path}`);
		});
		const target = await resolveGroupForJoin({ get } as never, `#ops@${ORG}`);
		expect(target.id).toBe(OPS_ID);
		expect(get.mock.calls.map((call) => call[0])).toContain("/groups/invites");
	});
});

describe("resolveRecipient", () => {
	it("reads a bare word as the group it names, and answers the row's handle", async () => {
		const { client } = clientHolding([OPS]);
		const target = await resolveRecipient(client, API, "ops");
		expect(target).toEqual({
			kind: "group",
			id: OPS_ID,
			handle: `#ops@${ORG}`,
			spelling: "ops",
			row: OPS,
		});
	});

	it("refuses a bare word that is one of the org's own agents", async () => {
		const { client } = clientHolding([OPS], [agent(KOFI_ID, "ops", `ops@${ORG}`)]);
		await expect(resolveRecipient(client, API, "ops")).rejects.toThrow(
			"is the name of an agent of your org",
		);
	});

	it("takes the org's agents from the caller rather than fetching them again", async () => {
		const { client, get } = clientHolding([OPS]);
		await resolveRecipient(client, API, "ops", {
			agents: [agent(KOFI_ID, "kofi", `kofi@${ORG}`)],
		});
		expect(paths(get)).not.toContain("/agents");
	});

	it("reads a sigiled name as a group without asking the agent guard", async () => {
		const { client, get } = clientHolding([OPS], [agent(KOFI_ID, "ops", `ops@${ORG}`)]);
		const target = await resolveRecipient(client, API, "#ops");
		expect(target.kind).toBe("group");
		expect(target.spelling).toBe("#ops");
		expect(target.handle).toBe(`#ops@${ORG}`);
		expect(paths(get)).not.toContain("/agents");
	});

	it("reads a whole group handle through the exact lookup", async () => {
		const { client, get } = clientHolding([OPS]);
		const target = await resolveRecipient(client, API, `#ops@${ORG}`);
		expect(target).toMatchObject({ kind: "group", id: OPS_ID });
		expect(queryOf(get, 0)).toEqual({ handle: `#ops@${ORG}` });
	});

	it("reads a UUID as an agent, with no handle to normalise and no request", async () => {
		const { client, get } = clientHolding([OPS]);
		expect(await resolveRecipient(client, API, KOFI_ID)).toEqual({
			kind: "agent",
			id: KOFI_ID,
			handle: undefined,
			spelling: KOFI_ID,
			row: undefined,
		});
		expect(get).not.toHaveBeenCalled();
	});

	it("reads an agent handle as an agent, normalised, and keeps the spelling", async () => {
		const webfinger = vi
			.spyOn(HttpClient, "publicGet")
			.mockResolvedValue({ aliases: [`https://rine.network/agents/${KOFI_ID}`] });
		try {
			const { client } = clientHolding([OPS]);
			expect(await resolveRecipient(client, API, "kofi@gqb")).toEqual({
				kind: "agent",
				id: KOFI_ID,
				handle: "kofi@gqb.rine.network",
				spelling: "kofi@gqb",
				row: undefined,
			});
		} finally {
			webfinger.mockRestore();
		}
	});

	it("refuses a blank recipient on syntax, before any request", async () => {
		const { client, get } = clientHolding([OPS]);
		await expect(resolveRecipient(client, API, "")).rejects.toThrow(
			"Invalid agent identifier '': expected a UUID or handle",
		);
		expect(get).not.toHaveBeenCalled();
	});
});

describe("the agent list an actor resolve already bought (R-B2)", () => {
	const KOFI = agent(KOFI_ID, "kofi", `kofi@${ORG}`);

	it("asks /agents once across the actor and the bare-recipient guard", async () => {
		// Before this, a bare-name send read the same org-scoped page twice —
		// `resolveActor` fetched it, resolved one agent off it and dropped it, and
		// `refuseIfABareAgentName` bought it again one call later.
		const { client, get } = clientHolding([OPS], [KOFI]);
		const acting = await resolveActor(client, "kofi");
		expect(paths(get)).toEqual(["/agents"]);

		const target = await resolveRecipient(client, API, "ops", {
			agents: acting.agents,
		});
		expect(target.id).toBe(OPS_ID);
		expect(paths(get)).toEqual(["/agents", "/groups"]);
	});

	it("buys the page itself when the actor rung read none", async () => {
		// 🔴 The economy is an economy, never a licence to skip the guard: an
		// unset `agents` means "no list was read for you", so the guard fetches.
		// A UUID-spelled actor is exactly that rung, and it is the spelling the
		// SDK surfaces use most.
		const { client, get } = clientHolding([OPS], [KOFI]);
		const acting = await resolveActor(client, KOFI_ID);
		expect(acting.agents).toBeUndefined();
		expect(paths(get)).toEqual([]);

		await resolveRecipient(client, API, "ops", { agents: acting.agents });
		expect(paths(get)).toEqual(["/agents", "/groups"]);
	});

	it("still refuses a bare name that is one of the handed-over agents", async () => {
		// 🔴 The property the saving must not cost. `send("ops")` meaning
		// `ops@acme` is the dropped-`@org` typo, and posting it to a group called
		// `ops` is a silent misdelivery on an E2EE product — so a guard reading a
		// handed-over list has to refuse exactly what a guard reading its own
		// fetch would, and name the handle that would have sent the DM.
		const ops = agent("a-1", "ops", `ops@${ORG}`);
		const { client, get } = clientHolding([OPS], [ops]);
		const acting = await resolveActor(client, "ops");

		await expect(
			resolveRecipient(client, API, "ops", { agents: acting.agents }),
		).rejects.toThrow(`ops@${ORG}`);
		// And it refused off the handed-over list: no second `/agents`, and no
		// `/groups` either, because the guard stands in front of the ladder.
		expect(paths(get)).toEqual(["/agents"]);
	});
});
