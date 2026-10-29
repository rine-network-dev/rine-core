import { describe, expect, it, vi } from "vitest";
import {
	BARE_NAME_IS_ONLY_AN_INVITATION,
	DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ,
	DIRECTORY_PAGES_FOR_A_JOIN,
	DIRECTORY_PAGE_LIMIT,
	JOIN_TAKES_A_HANDLE_OR_AN_ID,
	NO_SUCH_GROUP_TO_JOIN,
	TWO_INVITATIONS_OF_THAT_NAME,
	directoryQueryForHandle,
	isExactGroupHandle,
	isInvitationOfThatName,
} from "../src/group-join-words.js";
import { GROUP_NOT_FOUND_LEAD, groupLocalPart } from "../src/group-ref.js";
import { resolveGroupUuidForJoin } from "../src/resolve-group-join.js";

const SEATED_ID = "11111111-1111-1111-1111-111111111111";
const INVITED_ID = "22222222-2222-2222-2222-222222222222";
const PUBLIC_ID = "33333333-3333-3333-3333-333333333333";

const HANDLE = "#warehouse-restock@gqb.rine.network";
const LOCAL_NAME = "warehouse-restock";

/** What each rung answers, by path; anything unstubbed answers empty. */
interface Rungs {
	seated?: unknown[];
	invites?: unknown[];
	orgJoinable?: string | null;
	directory?: { items: unknown[]; next_cursor?: string; total_estimate?: number }[];
}

/**
 * An `HttpClient` stubbed per rung, recording every call.
 *
 * The rungs are asserted by which paths were asked and in what order, because
 * the order is the safety property: an irreversible verb must exhaust the two
 * scopes that mean a relationship exists before it reads the open directory.
 */
function clientFor(rungs: Rungs) {
	const pages = rungs.directory ?? [{ items: [] }];
	let page = 0;
	const get = vi.fn(
		async (path: string, _params?: unknown, _headers?: unknown) => {
			if (path === "/groups") return { items: rungs.seated ?? [] };
			if (path === "/groups/invites") return { items: rungs.invites ?? [] };
			if (path === "/groups/org-joinable") return { id: rungs.orgJoinable ?? null };
			if (path === "/directory/groups") return pages[page++] ?? { items: [] };
			throw new Error(`unexpected path ${path}`);
		},
	);
	return { client: { get } as never, get };
}

function paths(get: ReturnType<typeof vi.fn>): string[] {
	return get.mock.calls.map((call) => call[0] as string);
}

describe("resolveGroupUuidForJoin", () => {
	it("returns a uuid unchanged when given one, without asking any rung", async () => {
		const { client, get } = clientFor({});

		expect(await resolveGroupUuidForJoin(client, PUBLIC_ID)).toBe(PUBLIC_ID);
		expect(get).not.toHaveBeenCalled();
	});

	it("resolves a handle off the org's own seats when it holds one", async () => {
		const { client, get } = clientFor({
			seated: [{ id: SEATED_ID, handle: HANDLE }],
		});

		expect(await resolveGroupUuidForJoin(client, HANDLE)).toBe(SEATED_ID);
		expect(paths(get)).toEqual(["/groups"]);
	});

	it("asks the seats rung with the sigil the server stores, however the caller wrote it", async () => {
		// `?handle=` is an equality test against a stored handle that always
		// carries `#`, and every comparison on this stack reads `ops@acme` and
		// `#ops@acme` as the same reference. Unsigiled, this rung matched nothing
		// while its Python twin resolved it — and on THIS ladder that miss is not
		// a miss: it falls through to a refusal telling a caller the group is
		// unreachable about a private group they are already sitting in.
		const { client, get } = clientFor({
			seated: [{ id: SEATED_ID, handle: HANDLE }],
		});

		expect(
			await resolveGroupUuidForJoin(client, HANDLE.replace("#", "")),
		).toBe(SEATED_ID);
		expect(get.mock.calls[0]?.[1]).toEqual({ handle: HANDLE });
	});

	it("resolves a handle off this agent's invitations when no seat exists", async () => {
		// An invitation mints no membership row, so the seated rung structurally
		// cannot see it — this is the rung that made `join` work at all before.
		const { client, get } = clientFor({
			invites: [{ group_id: INVITED_ID, group_handle: HANDLE }],
		});

		expect(await resolveGroupUuidForJoin(client, HANDLE)).toBe(INVITED_ID);
		expect(paths(get)).toEqual(["/groups", "/groups/invites"]);
	});

	it("resolves a handle off the public directory when there is no relationship", async () => {
		// The measured defect: a handle `discoverGroups` had just printed, refused
		// client-side with the server never having been asked.
		const { client, get } = clientFor({
			directory: [{ items: [{ id: PUBLIC_ID, handle: HANDLE }] }],
		});

		expect(await resolveGroupUuidForJoin(client, HANDLE)).toBe(PUBLIC_ID);
		expect(paths(get)).toEqual(["/groups", "/groups/invites", "/groups/org-joinable", "/directory/groups"]);
	});

	it("resolves a handle off an open or voted group the org is seated in when no seat or invitation answers", async () => {
		const { client, get } = clientFor({ orgJoinable: PUBLIC_ID });

		expect(await resolveGroupUuidForJoin(client, HANDLE)).toBe(PUBLIC_ID);
		expect(paths(get)).toEqual(["/groups", "/groups/invites", "/groups/org-joinable"]);
		expect(get).toHaveBeenLastCalledWith("/groups/org-joinable", { handle: HANDLE }, undefined);
	});

	it("queries the directory by the handle's local part at the server's page ceiling", async () => {
		const { client, get } = clientFor({
			directory: [{ items: [{ id: PUBLIC_ID, handle: HANDLE }] }],
		});

		await resolveGroupUuidForJoin(client, HANDLE);

		const directoryCall = get.mock.calls.find((c) => c[0] === "/directory/groups");
		expect(directoryCall?.[1]).toEqual({ q: LOCAL_NAME, limit: DIRECTORY_PAGE_LIMIT });
	});

	it("passes the acting-agent header to the rung that selects whose invites are read", async () => {
		const { client, get } = clientFor({
			invites: [{ group_id: INVITED_ID, group_handle: HANDLE }],
		});

		await resolveGroupUuidForJoin(client, HANDLE, { "X-Rine-Agent": INVITED_ID });

		const invitesCall = get.mock.calls.find((c) => c[0] === "/groups/invites");
		expect(invitesCall?.[2]).toEqual({ "X-Rine-Agent": INVITED_ID });
	});

	it("refuses a directory row whose handle is merely similar to the one named", async () => {
		// 🔴 The directory filter is `name ILIKE OR description ILIKE`, so it
		// returns candidates, not answers. Taking the first row would be the fuzzy
		// match feeding an irreversible verb, which is what bare-name
		// resolution was refused for.
		const { client } = clientFor({
			directory: [
				{
					items: [
						{ id: PUBLIC_ID, handle: "#warehouse-restock-old@gqb.rine.network" },
						{ id: SEATED_ID, handle: "#warehouse-restock@other.rine.network" },
					],
				},
			],
		});

		await expect(resolveGroupUuidForJoin(client, HANDLE)).rejects.toThrow(
			NO_SUCH_GROUP_TO_JOIN,
		);
	});

	it("follows one directory cursor and stops there when the handle is on a later page", async () => {
		const { client, get } = clientFor({
			directory: [
				{ items: [{ id: SEATED_ID, handle: "#other@gqb.rine.network" }], next_cursor: "p2" },
				{ items: [{ id: PUBLIC_ID, handle: HANDLE }], next_cursor: "p3" },
				{ items: [{ id: INVITED_ID, handle: HANDLE }] },
			],
		});

		expect(await resolveGroupUuidForJoin(client, HANDLE)).toBe(PUBLIC_ID);
		expect(paths(get).filter((p) => p === "/directory/groups")).toHaveLength(
			DIRECTORY_PAGES_FOR_A_JOIN,
		);
	});

	it("stops reading the directory after its page budget rather than crawling it", async () => {
		const { client, get } = clientFor({
			directory: Array.from({ length: 5 }, () => ({
				items: [{ id: SEATED_ID, handle: "#other@gqb.rine.network" }],
				next_cursor: "more",
			})),
		});

		await expect(resolveGroupUuidForJoin(client, HANDLE)).rejects.toThrow(GROUP_NOT_FOUND_LEAD);
		expect(paths(get).filter((p) => p === "/directory/groups")).toHaveLength(
			DIRECTORY_PAGES_FOR_A_JOIN,
		);
	});

	it("states how many matching rows it never read when the budget cut the search short", async () => {
		// 🔴 A bounded search must never report itself as an exhaustive one. Two
		// pages of one row each, against a server that says nine match: seven rows
		// went unread, so the group's absence from the directory is not a fact
		// this refusal has earned.
		const { client } = clientFor({
			directory: Array.from({ length: 3 }, () => ({
				items: [{ id: SEATED_ID, handle: "#other@gqb.rine.network" }],
				next_cursor: "more",
				total_estimate: 9,
			})),
		});

		const refusal = resolveGroupUuidForJoin(client, HANDLE);
		await expect(refusal).rejects.toThrow(
			DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ.replace("{unread}", "7"),
		);
		await expect(refusal).rejects.not.toThrow(NO_SUCH_GROUP_TO_JOIN);
	});

	it("says the exhaustive sentence when the total it read covers every matching row", async () => {
		const { client } = clientFor({
			directory: [
				{ items: [{ id: SEATED_ID, handle: "#other@gqb.rine.network" }], total_estimate: 1 },
			],
		});

		await expect(resolveGroupUuidForJoin(client, HANDLE)).rejects.toThrow(NO_SUCH_GROUP_TO_JOIN);
	});

	it("says the exhaustive sentence rather than inventing a shortfall from a missing total", async () => {
		// A server that sends no total leaves nothing to subtract from; a
		// shortfall invented out of a missing field is worse than none.
		const { client } = clientFor({
			directory: Array.from({ length: 3 }, () => ({
				items: [{ id: SEATED_ID, handle: "#other@gqb.rine.network" }],
				next_cursor: "more",
			})),
		});

		await expect(resolveGroupUuidForJoin(client, HANDLE)).rejects.toThrow(NO_SUCH_GROUP_TO_JOIN);
	});

	it("resolves a bare name off this agent's own pending invitations", async () => {
		// The one rung a bare name gets. It is admissible because it is bounded to
		// groups that have already asked for this agent, so a match cannot be a
		// group the caller has no business in.
		const { client, get } = clientFor({
			invites: [{ group_id: INVITED_ID, group_handle: HANDLE }],
		});

		expect(await resolveGroupUuidForJoin(client, LOCAL_NAME)).toBe(INVITED_ID);
		expect(paths(get)).toEqual(["/groups/invites"]);
	});

	it("resolves a bare name off an invitation the server left unenriched", async () => {
		// A row from an older server carries `group_name` and no handle.
		const { client } = clientFor({
			invites: [{ group_id: INVITED_ID, group_name: LOCAL_NAME }],
		});

		expect(await resolveGroupUuidForJoin(client, LOCAL_NAME)).toBe(INVITED_ID);
	});

	it("refuses a bare name no invitation of this agent's answers to", async () => {
		// 🔴 Deliberate and settled: nothing wider is searched for a bare name —
		// the directory's ILIKE has no exactness filter to put behind it, and a
		// join cannot be taken back. The seats are never consulted either.
		const { client, get } = clientFor({
			seated: [{ id: SEATED_ID, handle: HANDLE }],
			invites: [{ group_id: INVITED_ID, group_handle: "#other@gqb.rine.network" }],
		});

		await expect(resolveGroupUuidForJoin(client, LOCAL_NAME)).rejects.toThrow(
			BARE_NAME_IS_ONLY_AN_INVITATION,
		);
		expect(paths(get)).toEqual(["/groups/invites"]);
	});

	it("refuses rather than picks when two invitations answer to one bare name", async () => {
		// 🔴 A bare name carries no org, so two orgs inviting this agent to a group
		// called `ops` are indistinguishable in the reference — and seating an
		// agent in the wrong one cannot be undone.
		const { client } = clientFor({
			invites: [
				{ group_id: INVITED_ID, group_handle: HANDLE },
				{ group_id: PUBLIC_ID, group_handle: `#${LOCAL_NAME}@other.rine.network` },
			],
		});

		const refusal = resolveGroupUuidForJoin(client, LOCAL_NAME);
		await expect(refusal).rejects.toThrow(TWO_INVITATIONS_OF_THAT_NAME);
		await expect(refusal).rejects.toThrow(`#${LOCAL_NAME}@other.rine.network`);
	});

	it("names what to hand the verb instead on a refused bare name", async () => {
		const { client } = clientFor({});

		await expect(resolveGroupUuidForJoin(client, LOCAL_NAME)).rejects.toThrow(
			JOIN_TAKES_A_HANDLE_OR_AN_ID,
		);
	});

	it("leads every refusal with the phrase the connectors key their remedy on", async () => {
		// `Group not found` is what eve/mastra's `formatError` and the three Python
		// connectors' `_not_found_message` read to append that surface's discover
		// verbs. A refusal that does not lead with it carries no remedy at all.
		const { client } = clientFor({});

		await expect(resolveGroupUuidForJoin(client, LOCAL_NAME)).rejects.toThrow(
			new RegExp(`^${GROUP_NOT_FOUND_LEAD}`),
		);
		await expect(resolveGroupUuidForJoin(client, HANDLE)).rejects.toThrow(
			new RegExp(`^${GROUP_NOT_FOUND_LEAD}`),
		);
	});

	it("names all four scopes when no rung answers the handle", async () => {
		const { client, get } = clientFor({});

		await expect(resolveGroupUuidForJoin(client, HANDLE)).rejects.toThrow(NO_SUCH_GROUP_TO_JOIN);
		expect(paths(get)).toEqual(["/groups", "/groups/invites", "/groups/org-joinable", "/directory/groups"]);
	});
});

describe("isExactGroupHandle", () => {
	it("matches the same handle written with and without its sigil", () => {
		expect(isExactGroupHandle("warehouse-restock@gqb.rine.network", HANDLE)).toBe(true);
	});

	it("matches a short-domain handle against the full one it stores", () => {
		expect(isExactGroupHandle("#warehouse-restock@gqb", HANDLE)).toBe(true);
	});

	it("refuses a handle in a different org with the same local name", () => {
		expect(isExactGroupHandle("#warehouse-restock@other.rine.network", HANDLE)).toBe(false);
	});

	it("refuses a handle the named one is merely a prefix of", () => {
		expect(isExactGroupHandle("#warehouse-restock-old@gqb.rine.network", HANDLE)).toBe(false);
	});

	it("refuses a row that carries no handle at all", () => {
		expect(isExactGroupHandle(undefined, HANDLE)).toBe(false);
	});

	it("refuses a doubled sigil, so converging the local part did not widen this rung", () => {
		expect(isExactGroupHandle(HANDLE, `#${HANDLE}`)).toBe(false);
		expect(isExactGroupHandle(`#${HANDLE}`, HANDLE)).toBe(false);
	});
});

/**
 * 🔴 The repeated leading sigil, pinned on both stacks at once.
 *
 * These four cases are the ONLY thing standing between this product and a
 * measured divergence: `groupLocalPart` stripped one `#` and Python's
 * `group_local_part` a whole run, so `join("##ops")` was seated on crewai,
 * langchain and hermes and refused on eve and mastra — one reference, two
 * answers, decided by which SDK the caller happened to be running. Their
 * byte-for-byte twins are `TestTheRepeatedSigil` in
 * `rine-sdk/tests/test_group_join_ref.py`; a case added here without its twin
 * there re-opens exactly the hole this closes.
 *
 * The last case is the other half of that, and the reason the forgiving
 * spelling is safe: the FILTER did not move. A doubled sigil reaches a group
 * only through the invitations rung, which is bounded to groups that have
 * already invited this agent.
 */
describe("a repeated leading sigil", () => {
	it("names the same local part as a single one", () => {
		expect(groupLocalPart(`#${HANDLE}`)).toBe(LOCAL_NAME);
		expect(groupLocalPart(`###${HANDLE}`)).toBe(LOCAL_NAME);
	});

	it("still matches the invitation it names", () => {
		expect(isInvitationOfThatName(HANDLE, undefined, `##${LOCAL_NAME}`)).toBe(true);
	});

	it("still matches an unenriched row by the name its creator typed", () => {
		expect(isInvitationOfThatName(undefined, LOCAL_NAME, `##${LOCAL_NAME}`)).toBe(true);
	});

	it("queries the directory for the bare local part, not for a sigil", () => {
		expect(directoryQueryForHandle(`#${HANDLE}`)).toBe(LOCAL_NAME);
	});
});

describe("isInvitationOfThatName", () => {
	it("matches an invitation by the local part of its handle", () => {
		expect(isInvitationOfThatName(HANDLE, undefined, LOCAL_NAME)).toBe(true);
	});

	it("matches a sigiled, org-less reference, which names a namespace and nothing more", () => {
		expect(isInvitationOfThatName(HANDLE, undefined, `#${LOCAL_NAME}`)).toBe(true);
	});

	it("matches an unenriched row by the name its creator typed", () => {
		expect(isInvitationOfThatName(undefined, LOCAL_NAME, LOCAL_NAME)).toBe(true);
	});

	it("matches a same-named group in ANY org, which is why two matches must refuse", () => {
		expect(isInvitationOfThatName("#warehouse-restock@other.rine.network", undefined, LOCAL_NAME)).toBe(
			true,
		);
	});

	it("refuses a name the invitation's is merely a prefix of", () => {
		expect(isInvitationOfThatName(HANDLE, undefined, "warehouse")).toBe(false);
	});

	it("refuses a row that carries neither handle nor name", () => {
		expect(isInvitationOfThatName(undefined, undefined, LOCAL_NAME)).toBe(false);
	});
});

describe("directoryQueryForHandle", () => {
	it("queries by the local part, which is the column the directory searches", () => {
		expect(directoryQueryForHandle(HANDLE)).toBe(LOCAL_NAME);
	});
});
