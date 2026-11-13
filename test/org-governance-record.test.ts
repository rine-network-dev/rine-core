import { describe, expect, it, vi } from "vitest";
import { RineApiError } from "../src/errors.js";
import type { HttpClient } from "../src/http.js";
import { fetchOrgEvents } from "../src/org-governance.js";
import * as record from "../src/org-governance-record.js";
import codes from "./fixtures/governance-codes.json" with { type: "json" };

function fake() {
	const fn = () => vi.fn(async () => ({ groups: [] }));
	return { get: fn(), put: fn() } as unknown as HttpClient &
		Record<"get" | "put", ReturnType<typeof vi.fn>>;
}

describe("the record's read routes", () => {
	it("test_record_routes_when_called_then_each_hits_its_path_with_its_params", async () => {
		const c = fake();
		await fetchOrgEvents(c, 7, undefined, 3);
		await record.fetchOrgEventHead(c, "n".repeat(43));
		await record.fetchOrgMetadata(c, 5, 100, 2);
		await record.fetchOrgMetadata(c, 0);
		await record.fetchCounterparties(c, "cur", 50);
		await record.fetchCounterparties(c);
		await record.fetchCounterpartyGroups(c);
		await record.fetchLogSettings(c);
		await record.putLogSettings(c, 90);
		expect(c.get.mock.calls).toEqual([
			["/org/events", { after_seq: 7, chain_epoch: 3 }],
			["/org/events/head", { nonce: "n".repeat(43) }],
			["/org/metadata", { after_seq: 5, limit: 100, chain_epoch: 2 }],
			["/org/metadata", { after_seq: 0 }],
			["/org/counterparties", { cursor: "cur", limit: 50 }],
			["/org/counterparties", {}],
			["/org/counterparties/groups"],
			["/org/log-settings"],
		]);
		expect(c.put.mock.calls).toEqual([
			["/org/log-settings", { event_retention_days: 90 }],
		]);
	});

	it("test_head_keys_when_fetched_then_the_public_route_is_read_without_a_token", async () => {
		const fetchMock = vi.fn(
			async () => new Response(JSON.stringify({ keys: [] })),
		);
		vi.stubGlobal("fetch", fetchMock);
		try {
			expect(await record.fetchHeadKeys("https://api.example")).toEqual({
				keys: [],
			});
			const [url, init] = fetchMock.mock.calls[0] as unknown as [
				string,
				RequestInit,
			];
			expect(url).toBe(
				"https://api.example/.well-known/rine-event-head-keys.json",
			);
			expect(JSON.stringify(init.headers)).not.toContain("Authorization");
		} finally {
			vi.unstubAllGlobals();
		}
	});
});

describe("forkPointOf", () => {
	const conflict = (code: string, body: Record<string, unknown>) =>
		new RineApiError(409, "moved", undefined, code, { error: code, ...body });

	it("test_fork_point_when_the_409_names_the_epoch_then_it_is_returned_with_the_hash", () => {
		expect(
			record.forkPointOf(
				conflict("chain_epoch_changed", {
					current_epoch: 4,
					fork_after_seq: 9,
					fork_after_hash: "ab",
				}),
			),
		).toEqual({ currentEpoch: 4, forkAfterSeq: 9, forkAfterHash: "ab" });
	});

	it("test_fork_point_when_the_stream_has_no_hash_then_the_hash_is_absent", () => {
		const fork = record.forkPointOf(
			conflict("chain_epoch_changed", { current_epoch: 4, fork_after_seq: 0 }),
		);
		expect(fork).toEqual({ currentEpoch: 4, forkAfterSeq: 0 });
	});

	it.each([
		[
			"another 409",
			conflict("something_else", { current_epoch: 4, fork_after_seq: 1 }),
		],
		["a 409 without the numbers", conflict("chain_epoch_changed", {})],
		["a 503", new RineApiError(503, "down")],
		["a plain error", new Error("x")],
	])("test_fork_point_when_%s_then_undefined", (_n, err) => {
		expect(record.forkPointOf(err)).toBeUndefined();
	});
});

describe("RecordRefusal", () => {
	it("test_record_refusal_when_compared_to_the_server_list_then_the_codes_match", () => {
		expect(Object.values(record.RecordRefusal).sort()).toEqual(
			[...codes.record_refusals].sort(),
		);
	});
});
