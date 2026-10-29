/**
 * The read that recovery's reseat is built on: which MLS groups the server lists
 * with a given agent seated. The fake client here IS the network, so the test
 * pins both the filter and the acting-agent header the request must carry.
 */
import { describe, expect, it, vi } from "vitest";

import { ACTING_AGENT_HEADER } from "../src/actor.js";
import type { GroupRead } from "../src/api-types.js";
import { seatedMlsGroups } from "../src/mls-seated-groups.js";

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const OTHER = "b2c3d4e5-f6a7-8901-bcde-f12345678901";

/** The fields the filter reads; the rest of `GroupRead` is irrelevant here. */
function group(overrides: Partial<GroupRead> & { id: string }): GroupRead {
	return {
		name: "g",
		handle: "g",
		description: null,
		enrollment_policy: "closed",
		visibility: "private",
		isolated: false,
		vote_duration_hours: 24,
		member_count: 1,
		created_at: "2024-01-01T00:00:00Z",
		conversation_id: null,
		...overrides,
	} as GroupRead;
}

function clientReturning(items: unknown): { get: ReturnType<typeof vi.fn> } {
	return { get: vi.fn(async () => ({ items })) };
}

describe("seatedMlsGroups", () => {
	it("test_seated_mls_groups_when_items_mix_mls_and_seating_then_only_the_seated_mls_group_is_kept", async () => {
		const seated = group({ id: "seated", mls_group_id: "seated" });
		const unseated = group({ id: "unseated", mls_group_id: "unseated" });
		const open = group({ id: "open", mls_group_id: null });
		const client = clientReturning([
			{ ...seated, member_agent_ids: [AGENT] },
			{ ...unseated, member_agent_ids: [OTHER] },
			{ ...open, member_agent_ids: [AGENT] },
		]);

		const result = await seatedMlsGroups(client as never, AGENT);

		expect(result.map((g) => g.id)).toEqual(["seated"]);
	});

	it("test_seated_mls_groups_when_called_then_the_request_carries_the_acting_agent_header", async () => {
		const client = clientReturning([]);

		await seatedMlsGroups(client as never, AGENT);

		expect(client.get).toHaveBeenCalledWith("/groups", undefined, {
			[ACTING_AGENT_HEADER]: AGENT,
		});
	});

	it("test_seated_mls_groups_when_the_response_has_no_items_then_it_is_empty", async () => {
		const client = { get: vi.fn(async () => ({})) };

		await expect(seatedMlsGroups(client as never, AGENT)).resolves.toEqual([]);
	});

	it("test_seated_mls_groups_when_the_listing_rejects_then_it_rejects_with_the_same_error", async () => {
		const failure = new Error("groups unavailable");
		const client = {
			get: vi.fn(async () => {
				throw failure;
			}),
		};

		await expect(seatedMlsGroups(client as never, AGENT)).rejects.toBe(failure);
	});
});
