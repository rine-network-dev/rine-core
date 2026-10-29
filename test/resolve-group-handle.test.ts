/**
 * What a group handle resolves to when its ORG half names nothing.
 *
 * `GET /groups?handle=` is an equality test against the stored handle, so a
 * fabricated org half used to fail HARDER than writing no org at all — the `@`
 * is precisely what routes a reference down the exact branch instead of the
 * ladder, and `shipping-labels` matched where `#shipping-labels@acme…` could
 * not. A spelling carrying strictly more information did strictly worse.
 *
 * These pin the routing, not any one name: that the exact lookup still answers
 * alone when it can, that the fallback runs the same four tiers a bare name
 * gets, that the refusal quotes what the caller WROTE, and — the one that is
 * easy to break by "tidying" — that `seatedGroupByHandle` is left narrow,
 * because the join ladder takes its empty answer as a rung rather than an
 * answer.
 */

import { describe, expect, it, vi } from "vitest";
import type { GroupRead } from "../src/api-types.js";
import { GroupIdentityMismatchError, RineApiError } from "../src/errors.js";
import {
	resolveGroupByHandle,
	resolveGroupUuid,
	seatedGroupByHandle,
} from "../src/resolve-group.js";

const LABELS_ID = "11111111-1111-1111-1111-111111111111";
const OPS_ONE_ID = "22222222-2222-2222-2222-222222222222";
const OPS_TWO_ID = "33333333-3333-3333-3333-333333333333";

/** The org this caller is actually in. Nothing here answers to `acme`. */
const LABELS = row(LABELS_ID, "shipping-labels", "#shipping-labels@gqb.rine.network");

function row(id: string, name: string, handle: string): GroupRead {
	return { id, name, handle } as GroupRead;
}

/**
 * An `HttpClient` whose three group reads behave like the server's: `?handle=`
 * is an equality test against the stored handle, the unfiltered `GET /groups`
 * answers the whole org list, and `GET /groups/{id}` answers one row or 404s.
 *
 * 🔴 The id route folds case, because the server does: `get_group` types its
 * path parameter `group_id: uuid.UUID` (`src/rine/api/group_routes_read.py`), which parses
 * `AAAA…` and `aaaa…` to the same value. The client-side spelling comparison
 * that used to have to know this is gone, so the fixture is now where the
 * assumption lives — and it is asserted, below, on an id with hex LETTERS in it.
 *
 * A miss raises `RineApiError(404)` rather than a bare `Error`: the resolver
 * tells a refusal from an outage by the status, and a fixture that threw
 * something statusless would prove the swallow instead of the refusal.
 */
function clientHolding(groups: GroupRead[]) {
	const get = vi.fn(
		async (path: string, params?: Record<string, unknown>, _h?: unknown) => {
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

/** The `handle` each call filtered on, `undefined` for the unfiltered list. */
function filters(get: ReturnType<typeof vi.fn>): (string | undefined)[] {
	return get.mock.calls.map(
		(call) => (call[1] as { handle?: string } | undefined)?.handle,
	);
}

/** The paths a resolve actually asked for, in order. */
function paths(get: ReturnType<typeof vi.fn>): string[] {
	return get.mock.calls.map((call) => call[0] as string);
}

describe("resolveGroupByHandle", () => {
	it("answers an exact handle off the server's own lookup, asking nothing else", async () => {
		// The fallback is a fallback. A handle that resolves must still cost one
		// round trip, or every send in the product pays for a miss nobody made.
		const { client, get } = clientHolding([LABELS]);

		const group = await resolveGroupByHandle(
			client,
			"#shipping-labels@gqb.rine.network",
		);

		expect(group.id).toBe(LABELS_ID);
		expect(filters(get)).toEqual(["#shipping-labels@gqb.rine.network"]);
	});

	it("resolves the local part when the org half names nothing", async () => {
		// The measured shape: local part learned from the conversation, domain
		// copied out of the shipped examples.
		const { client, get } = clientHolding([LABELS]);

		const group = await resolveGroupByHandle(
			client,
			"#shipping-labels@acme.rine.network",
		);

		expect(group.id).toBe(LABELS_ID);
		expect(filters(get)).toEqual(["#shipping-labels@acme.rine.network", undefined]);
	});

	it("reaches the whole ladder, classifier peel included, not just exact equality", async () => {
		// Tier 4 already shipped for a bare name. The fallback hands the local
		// part to the same function, so `#ops-group@…` peels to `ops` here for
		// the same reason `ops group` does on the send path.
		const { client } = clientHolding([row(OPS_ONE_ID, "ops", "#ops@gqb.rine.network")]);

		const group = await resolveGroupByHandle(client, "#ops-group@acme.rine.network");

		expect(group.id).toBe(OPS_ONE_ID);
	});

	it("quotes the handle the caller wrote, not the local part it searched on", async () => {
		// Otherwise a caller who wrote a handle is answered about a string they
		// never typed — which reads as the product having lost their reference.
		const { client } = clientHolding([LABELS]);

		await expect(
			resolveGroupByHandle(client, "#payroll@acme.rine.network"),
		).rejects.toThrow(/^Group not found: #payroll@acme\.rine\.network\./);
	});

	it("names the caller's groups in that refusal, as every other group miss does", async () => {
		const { client } = clientHolding([LABELS]);

		await expect(
			resolveGroupByHandle(client, "#payroll@acme.rine.network"),
		).rejects.toThrow(/#shipping-labels@gqb\.rine\.network/);
	});

	it("refuses and names both when the local part answers to two groups", async () => {
		// Reachable precisely because the org half was dropped: two orgs may each
		// run a group called `ops`, and the handle told them apart until it
		// stopped matching. Picking one would post to a group nobody chose.
		const { client } = clientHolding([
			row(OPS_ONE_ID, "ops", "#ops@one.rine.network"),
			row(OPS_TWO_ID, "ops", "#ops@two.rine.network"),
		]);

		await expect(
			resolveGroupByHandle(client, "#ops@acme.rine.network"),
		).rejects.toThrow(/ambiguous.*#ops@one\.rine\.network.*#ops@two\.rine\.network/s);
	});

	it("leaves seatedGroupByHandle narrow, because join reads its empty answer", async () => {
		// 🔴 The one assertion that stops this being "fixed" one level down. The
		// join ladder treats an empty seats page as its FIRST RUNG — a group the
		// caller is not yet in is exactly what join is aimed at — so widening
		// here would collapse the rung into the answer.
		const { client, get } = clientHolding([LABELS]);

		expect(
			await seatedGroupByHandle(client, "#shipping-labels@acme.rine.network"),
		).toBeUndefined();
		expect(filters(get)).toEqual(["#shipping-labels@acme.rine.network"]);
	});
});

describe("resolveGroupUuid", () => {
	it("carries the fallback, so every verb that takes a reference gets it", async () => {
		const { client } = clientHolding([LABELS]);

		expect(await resolveGroupUuid(client, "#shipping-labels@acme.rine.network")).toBe(
			LABELS_ID,
		);
	});

	it("reads a uuid from the group's own route, and buys no roster to do it", async () => {
		// 🔴 This entry once passed a uuid through unchecked; the first fix
		// built the check as an unpaginated `GET /groups` — so a RESOLVED id paid
		// for a list it never printed, on a route that counts members per row.
		// The check now sits on the one indexed read, which is what
		// makes "cost only on the refusal path" true for the first
		// time. Twin:
		// `TestResolveGroup::test_a_uuid_costs_one_indexed_read_and_answers_with_the_row`.
		const { client, get } = clientHolding([LABELS]);

		expect(await resolveGroupUuid(client, LABELS_ID)).toBe(LABELS_ID);
		expect(paths(get)).toEqual([`/groups/${LABELS_ID}`]);
	});

	it("answers a uuid the caller spelled in upper case, in the server's own spelling", async () => {
		// 🔴 `UUID_RE` is case-INSENSITIVE and every group route types its path
		// parameter `group_id: uuid.UUID`, which parses either spelling to the
		// same value — so this id has always reached the wire and worked. The old
		// roster match compared spellings and refused it, with a roster that
		// printed the group it meant; the comparison is deleted rather than
		// folding it, so the caller's own spelling goes on the path and the row
		// comes back in the server's. Hex LETTERS deliberately: on an all-decimal
		// id `toUpperCase()` is a no-op and this test proves nothing. Twin:
		// `TestResolveGroup::test_a_uuid_spelled_in_upper_case_is_the_same_group`.
		const upper = row(
			"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
			"accounts",
			"#accounts@gqb.rine.network",
		);
		const { client, get } = clientHolding([upper]);

		expect(await resolveGroupUuid(client, upper.id.toUpperCase())).toBe(upper.id);
		expect(paths(get)).toEqual([`/groups/${upper.id.toUpperCase()}`]);
	});

	it("does not read a uuid with a trailing newline as an id", async () => {
		// 🔴 The smallest cross-stack divergence, and the one the indexed read made
		// expensive. Python's
		// `$` matches BEFORE a trailing newline and JavaScript's does not, so a
		// line read off a file — `f.readline()`, a piped CLI argument — was an id
		// to `is_uuid` and a name to `UUID_RE`. Once the id goes on the PATH the
		// Python half raised `httpx.InvalidURL`, which is not a `RineError` and
		// escapes that SDK's error hierarchy, where this stack composed the
		// roster refusal. The Python classifier was anchored with `fullmatch` to
		// converge on the behaviour asserted here; this pins the target so the
		// two cannot drift apart again from the other side.
		//
		// Twin:
		// `TestResolveGroup::test_a_uuid_carrying_a_trailing_newline_is_not_read_as_an_id`.
		const { client, get } = clientHolding([LABELS]);

		const refused = resolveGroupUuid(client, `${LABELS_ID}\n`);

		await expect(refused).rejects.toThrow(LABELS.handle as string);
		// The id route is never asked: a newline cannot go on a path, and the
		// name ladder is where a spelling that is not an id belongs.
		expect(paths(get)).toEqual(["/groups"]);
	});

	it("refuses a uuid that names no group of this org, naming the ones there are", async () => {
		// The other side of the same ruling: what a bare server 404 bought was a
		// measured 0/6 recovery rate, and the id is the spelling a model is most
		// likely to have invented.
		const { client, get } = clientHolding([LABELS]);

		const refused = resolveGroupUuid(client, "cccccccc-0000-4000-8000-00000000ffff");

		await expect(refused).rejects.toThrow("Group not found: cccccccc-0000-4000-8000-00000000ffff");
		// The roster is the half that refusal buys, and it is what the Python
		// twin asserts on the same rung
		// (`TestResolveGroup::test_a_uuid_no_group_of_this_org_carries_is_refused_with_the_roster`).
		// A refusal that paid for the list and then named nothing from it has
		// spent the round trip for a sentence a bare 404 already said.
		await expect(refused).rejects.toThrow(LABELS.handle as string);
		// 🔴 And the ORDER is the contract: the indexed read first, the roster only
		// after it said no. Asserting the pair without the order would pass on an
		// implementation that fetched the list up front and read the row for
		// nothing, which is the old defect with an extra request bolted on.
		expect(paths(get)).toEqual([
			"/groups/cccccccc-0000-4000-8000-00000000ffff",
			"/groups",
		]);
	});

	it("answers a 403 exactly as it answers a 404, so no stranger's id is confirmed", async () => {
		// 🔴 `GET /groups/{id}` 404s an id no group carries and 403s
		// one carried by a group of an org this caller is neither owner of nor
		// seated in. Telling those apart would tell a caller which ids they are
		// not allowed to see EXIST — a non-member lookup rine does not offer,
		// arrived at by reading a status code instead of a route.
		const stranger = "cccccccc-0000-4000-8000-00000000ffff";
		const { client } = clientHolding([LABELS]);
		const forbidding = {
			get: vi.fn(async (path: string) => {
				if (path !== "/groups") throw new RineApiError(403, "Access denied");
				return { items: [LABELS] };
			}),
		} as never;

		const missing = await resolveGroupUuid(client, stranger).catch((e: Error) => e.message);
		const forbidden = await resolveGroupUuid(forbidding, stranger).catch(
			(e: Error) => e.message,
		);

		expect(forbidden).toBe(missing);
		expect(forbidden).toContain(LABELS.handle as string);
	});

	it("lets any other failure through, because an outage is not a wrong reference", async () => {
		// A 500 answered as "Group not found: <id>" would tell a caller their
		// reference was wrong about an outage, and send a model off to re-spell a
		// perfectly good id. Only 404 and 403 mean "no group of yours".
		const boom = new RineApiError(500, "Internal Server Error");
		const client = {
			get: vi.fn(async (path: string) => {
				if (path.startsWith("/groups/")) throw boom;
				return { items: [LABELS] };
			}),
		} as never;

		await expect(resolveGroupUuid(client, LABELS_ID)).rejects.toBe(boom);
	});

	it("refuses a body that names another group, as the class and not as a sentence", async () => {
		// 🔴 The golden fixture pins the SENTENCE across the two stacks;
		// this pins the class a caller branches on, which a `name` string cannot —
		// a rename that left `this.name` alone would keep that gate green while
		// every `instanceof` in the product went false. The ids are on the error
		// so a caller can report the substitution without parsing prose.
		const substituting = {
			get: vi.fn(async (path: string) => {
				if (path === "/groups") return { items: [LABELS] };
				return row(OPS_ONE_ID, "ops", "#ops@gqb.rine.network");
			}),
		} as never;

		const raised = await resolveGroupUuid(substituting, LABELS_ID).catch((e: unknown) => e);

		expect(raised).toBeInstanceOf(GroupIdentityMismatchError);
		expect((raised as GroupIdentityMismatchError).requestedGroupId).toBe(LABELS_ID);
		expect((raised as GroupIdentityMismatchError).answeredGroupId).toBe(OPS_ONE_ID);
	});
});
