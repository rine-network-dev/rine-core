import { describe, expect, it, vi } from "vitest";

import type { GroupMemberRead } from "../src/api-types.js";
import { fetchGroupMembers } from "../src/group-members.js";

const GROUP_ID = "11111111-2222-4333-8444-555555555555";

function member(agentId: string): GroupMemberRead {
	return {
		id: `row-${agentId}`,
		group_id: GROUP_ID,
		agent_id: agentId,
		role: "member",
		joined_at: "2026-10-01T00:00:00Z",
	};
}

describe("fetchGroupMembers", () => {
	it("test_fetchGroupMembers_when_the_server_lists_members_then_the_rows_come_back_as_sent", async () => {
		const rows = [member("a1"), member("a2")];
		const get = vi.fn(async () => ({ items: rows, total: 2 }));

		expect(await fetchGroupMembers({ get }, GROUP_ID)).toEqual(rows);
		expect(get).toHaveBeenCalledWith(
			`/groups/${GROUP_ID}/members`,
			undefined,
			undefined,
		);
	});

	it("test_fetchGroupMembers_when_headers_are_given_then_they_ride_on_the_read", async () => {
		const get = vi.fn(async () => ({ items: [], total: 0 }));
		const headers = { "X-Rine-Agent": "a1" };

		await fetchGroupMembers({ get }, GROUP_ID, headers);

		expect(get).toHaveBeenCalledWith(
			`/groups/${GROUP_ID}/members`,
			undefined,
			headers,
		);
	});

	it("test_fetchGroupMembers_when_the_page_carries_no_items_then_an_empty_roster", async () => {
		const get = vi.fn(async () => ({}));

		expect(await fetchGroupMembers({ get }, GROUP_ID)).toEqual([]);
	});

	it("test_fetchGroupMembers_when_the_read_fails_then_the_error_propagates", async () => {
		const refused = new Error("403");
		const get = vi.fn(async () => {
			throw refused;
		});

		await expect(fetchGroupMembers({ get }, GROUP_ID)).rejects.toBe(refused);
	});
});
