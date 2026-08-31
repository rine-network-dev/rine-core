/**
 * Which route a named transcript is read from, and what it costs to get there.
 *
 * What the group leg does on this stack: a group is named the way
 * every other group verb takes it, and the read lands on the group's own route
 * rather than on a conversation id the caller never had.
 */

import { describe, expect, it, vi } from "vitest";
import type { HttpClient } from "../src/http.js";
import { resolveGroupUuid } from "../src/resolve-group.js";
import { readThreadPage } from "../src/thread-read.js";

const GROUP_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const CONV = "11111111-2222-3333-4444-555555555555";
const PAGE = { messages: [], truncated: false };

function clientReturning(...responses: unknown[]): {
	client: HttpClient;
	calls: unknown[][];
} {
	const calls: unknown[][] = [];
	const queue = [...responses];
	const get = vi.fn(async (...args: unknown[]) => {
		calls.push(args);
		return queue.shift() ?? PAGE;
	});
	return { client: { get } as unknown as HttpClient, calls };
}

const groupRow = (handle: string) => ({
	id: GROUP_ID,
	name: handle.replace(/^#|@.*$/g, ""),
	handle,
});

const groupsPage = (handle: string) => ({ items: [groupRow(handle)] });

describe("readThreadPage", () => {
	it("reads a conversation from its own route, without a lookup", async () => {
		const { client, calls } = clientReturning(PAGE);
		await readThreadPage(client, { kind: "conversation", conversationId: CONV });
		expect(calls).toHaveLength(1);
		expect(calls[0]?.[0]).toBe(`/conversations/${CONV}/messages`);
	});

	it("reads a group by its own id, not by a conversation", async () => {
		// 🔴 The group route filters `messages.group_id`. A group's
		// history is not its conversation's, and on a pre-cutover group the two
		// legitimately disagree.
		//
		// The read in front of the read: a uuid is checked against the
		// group's own route before the transcript is asked for, so this fixture
		// has to answer that row rather than a page.
		const { client, calls } = clientReturning(groupRow("#ops@acme.rine.network"), PAGE);
		await readThreadPage(client, { kind: "group", ref: GROUP_ID });
		expect(calls).toHaveLength(2);
		expect(calls[0]?.[0]).toBe(`/groups/${GROUP_ID}`);
		expect(calls[1]?.[0]).toBe(`/groups/${GROUP_ID}/messages`);
	});

	it("resolves a handle to the group's id first", async () => {
		const { client, calls } = clientReturning(groupsPage("#ops@acme.rine.network"), PAGE);
		await readThreadPage(client, { kind: "group", ref: "#ops@acme" });
		expect(calls[0]).toEqual(["/groups", { handle: "#ops@acme.rine.network" }, undefined]);
		expect(calls[1]?.[0]).toBe(`/groups/${GROUP_ID}/messages`);
	});

	it("names the same acting agent on the resolve as on the read", async () => {
		// Both legs of one call, or two different actors answer it. Harmless while
		// `GET /groups` selects on the org alone — and a silent wrong-group resolve
		// the day it does not.
		const { client, calls } = clientReturning(groupsPage("#ops@acme.rine.network"), PAGE);
		await readThreadPage(
			client,
			{ kind: "group", ref: "#ops@acme" },
			{ extraHeaders: { "X-Rine-Agent": "a-1" } },
		);
		expect(calls[0]?.[2]).toEqual({ "X-Rine-Agent": "a-1" });
		expect(calls[1]?.[2]).toEqual({ "X-Rine-Agent": "a-1" });
	});

	it("passes the caller's window and headers through to either route", async () => {
		const { client, calls } = clientReturning(PAGE);
		await readThreadPage(
			client,
			{ kind: "conversation", conversationId: CONV },
			{ limit: 5, extraHeaders: { "X-Rine-Agent": "a-1" } },
		);
		expect(calls[0]?.[1]).toEqual({ limit: 5 });
		expect(calls[0]?.[2]).toEqual({ "X-Rine-Agent": "a-1" });
	});
});

describe("resolveGroupUuid", () => {
	it("costs one indexed read for a UUID, and answers the id it checked", async () => {
		// 🔴 A uuid used to cost nothing here and be answered unchecked; closing
		// that split onto a roster refusal made the RESOLVED path
		// pay for an unpaginated `GET /groups` it never printed. It now
		// spends the one indexed row instead and leaves the roster to the refusal.
		// The join ladder (`resolveGroupForJoin`) keeps the passthrough and must:
		// its target is a group this org is neither owner of nor seated in, so
		// neither of these two reads can describe it.
		const { client, calls } = clientReturning(groupRow("#ops@acme.rine.network"));
		expect(await resolveGroupUuid(client, GROUP_ID)).toBe(GROUP_ID);
		expect(calls).toEqual([[`/groups/${GROUP_ID}`, undefined, undefined]]);
	});

	it("normalises a short handle before asking, so both spellings resolve", async () => {
		const { client, calls } = clientReturning(groupsPage("#ops@acme.rine.network"));
		expect(await resolveGroupUuid(client, "#ops@acme")).toBe(GROUP_ID);
		expect(calls[0]?.[1]).toEqual({ handle: "#ops@acme.rine.network" });
	});

	it("matches a bare name against the caller's own groups", async () => {
		// The server's `?handle=` filter matches a full handle only, so a bare
		// name has to be compared locally or it refuses every group it names.
		const { client, calls } = clientReturning({
			items: [
				{ id: "other", name: "Eng", handle: "#eng@acme.rine.network" },
				{ id: GROUP_ID, name: "Ops", handle: "#ops@acme.rine.network" },
			],
		});
		expect(await resolveGroupUuid(client, "ops")).toBe(GROUP_ID);
		expect(calls[0]).toEqual(["/groups", undefined, undefined]);
	});

	it("refuses an ambiguous name rather than picking one of them", async () => {
		// Two orgs' groups can carry one local part, so the candidates are named
		// by handle — the spelling that still tells them apart — in the column
		// set every group refusal shares, on both stacks.
		const { client } = clientReturning({
			items: [
				{ id: "g1", name: "Ops", handle: "#ops@acme.rine.network" },
				{ id: "g2", name: "Ops", handle: "#ops@other.rine.network" },
			],
		});
		await expect(resolveGroupUuid(client, "ops")).rejects.toThrow(
			"Group name 'ops' is ambiguous — more than one group answers to it. " +
				"Name one of these groups:\n" +
				"  - #ops@acme.rine.network (Ops)\n" +
				"  - #ops@other.rine.network (Ops)",
		);
	});

	it("names the reference it could not find", async () => {
		const { client } = clientReturning({ items: [] });
		await expect(resolveGroupUuid(client, "#ghost@acme")).rejects.toThrow(
			"Group not found: #ghost@acme",
		);
	});
});
