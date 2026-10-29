import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { ESCROW_MAX_ROWS, ReaderClient } from "../src/org-reader/client.js";
import { MalformedPageError } from "../src/org-reader/page-envelope.js";
import { KeyChainError } from "../src/crypto/key-chain.js";
import { RineApiError } from "../src/errors.js";
import { ReaderNetworkError } from "../src/org-reader/fetch-budget.js";
import {
	READER_SIGNER,
	jsonResponse,
	router,
} from "./org-reader-client-fixture.js";

const API = "https://api.test";
const MINT = {
	"POST /oauth/token": () =>
		jsonResponse({ access_token: "tok", expires_in: 900 }),
};

function setup(
	routes: Parameters<typeof router>[0],
	now = () => 0,
	extra: Partial<ConstructorParameters<typeof ReaderClient>[0]> = {},
) {
	const transport = router({ ...MINT, ...routes });
	return {
		transport,
		reader: new ReaderClient({
			apiUrl: API,
			signer: READER_SIGNER,
			fetch: transport,
			now,
			refreshMarginMs: 60_000,
			...extra,
		}),
	};
}

const sentTo = (transport: ReturnType<typeof router>, path: string) =>
	transport.mock.calls
		.map(([input]) => new URL(String(input)))
		.filter((url) => url.pathname === path);

describe("ReaderClient.activity", () => {
	it("asks_for_the_payload_and_sends_only_the_filters_that_are_set", async () => {
		const { reader, transport } = setup({
			"GET /org/activity": () =>
				jsonResponse({ items: [{ id: "a" }], next_cursor: "c2" }),
		});
		const page = await reader.activity({
			agent: "ag",
			groupId: "gr",
			direction: "sent",
			cursor: "c1",
		});
		expect(page).toEqual({ items: [{ id: "a" }], nextCursor: "c2" });
		const [url] = sentTo(transport, "/org/activity");
		expect(Object.fromEntries(url?.searchParams ?? [])).toEqual({
			include: "payload",
			limit: "100",
			agent: "ag",
			group_id: "gr",
			direction: "sent",
			cursor: "c1",
		});
	});

	it.each([
		[undefined, "100"],
		[500, "100"],
		[30, "30"],
		[0, "1"],
		[-4, "1"],
	])("clamps_the_limit_%s_to_%s", async (limit, sent) => {
		const { reader, transport } = setup({
			"GET /org/activity": () => jsonResponse({ items: [] }),
		});
		await reader.activity({ limit });
		expect(
			sentTo(transport, "/org/activity")[0]?.searchParams.get("limit"),
		).toBe(sent);
	});

	it("authenticates_with_the_minted_bearer_token", async () => {
		const { reader, transport } = setup({
			"GET /org/activity": () => jsonResponse({ items: [] }),
		});
		await reader.activity();
		const headers = transport.mock.calls.find(([input]) =>
			String(input).includes("/org/activity"),
		)?.[1]?.headers;
		expect(headers).toMatchObject({ Authorization: "Bearer tok" });
	});

	it.each([null, "x", {}, { items: "no" }, { items: [], next_cursor: 5 }])(
		"rejects_the_malformed_page_%j",
		async (body) => {
			const { reader } = setup({
				"GET /org/activity": () => jsonResponse(body),
			});
			await expect(reader.activity()).rejects.toBeInstanceOf(
				MalformedPageError,
			);
		},
	);

	it("treats_an_empty_next_cursor_as_the_last_page", async () => {
		const { reader } = setup({
			"GET /org/activity": () => jsonResponse({ items: [], next_cursor: "" }),
		});
		expect((await reader.activity()).nextCursor).toBeNull();
	});

	it("passes_a_server_error_through_as_a_rine_api_error", async () => {
		const { reader } = setup({
			"GET /org/activity": () => jsonResponse({ detail: "down" }, 503),
		});
		await expect(reader.activity()).rejects.toBeInstanceOf(RineApiError);
	});
});

describe("the reader's token", () => {
	it("is_reused_until_a_minute_before_it_expires", async () => {
		let at = 0;
		const { reader, transport } = setup(
			{ "GET /org/activity": () => jsonResponse({ items: [] }) },
			() => at,
		);
		await reader.activity();
		at = 839_999;
		await reader.activity();
		expect(sentTo(transport, "/oauth/token")).toHaveLength(1);
		at = 840_000;
		await reader.activity();
		expect(sentTo(transport, "/oauth/token")).toHaveLength(2);
	});

	it("refreshes_by_a_margin_drawn_with_the_sdks_jitter_when_none_is_given", async () => {
		let at = 0;
		const transport = router({
			...MINT,
			"GET /org/activity": () => jsonResponse({ items: [] }),
		});
		const reader = new ReaderClient({
			apiUrl: API,
			signer: READER_SIGNER,
			fetch: transport,
			now: () => at,
		});
		await reader.activity();
		// A 900 s token with a 60..180 s margin: always valid at 719 s, never at 840 s.
		at = 719_999;
		await reader.activity();
		expect(sentTo(transport, "/oauth/token")).toHaveLength(1);
		at = 840_000;
		await reader.activity();
		expect(sentTo(transport, "/oauth/token")).toHaveLength(2);
	});

	it("is_minted_once_for_requests_made_at_the_same_time", async () => {
		const { reader, transport } = setup({
			"GET /org/activity": () => jsonResponse({ items: [] }),
		});
		await Promise.all([
			reader.activity(),
			reader.activity(),
			reader.activity(),
		]);
		expect(sentTo(transport, "/oauth/token")).toHaveLength(1);
	});
});

describe("ReaderClient.agentKeys", () => {
	const AGENT = "11111111-1111-4111-8111-111111111111";

	it("reads_the_keys_route_for_the_agent_and_generation", async () => {
		const { reader, transport } = setup({
			[`GET /agents/${AGENT}/keys`]: () => jsonResponse({}),
		});
		await expect(reader.agentKeys(AGENT, 2)).rejects.toThrow();
		expect(
			sentTo(transport, `/agents/${AGENT}/keys`)[0]?.searchParams.get("gen"),
		).toBe("2");
	});

	it.each([
		["an_empty_object", {}],
		["a_missing_nested_key", { agent_id: AGENT, signing_public_key: null }],
	])("raises_a_key_chain_error_for_%s", async (_name, body) => {
		const { reader } = setup({
			[`GET /agents/${AGENT}/keys`]: () => jsonResponse(body),
		});
		const err = await reader.agentKeys(AGENT).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(KeyChainError);
		expect((err as KeyChainError).fault).toBe("malformed");
	});
});

describe("the contract with the server's routes", () => {
	it("keeps_both_request_paths_as_literals_the_contract_gate_can_extract", () => {
		const source = readFileSync(
			new URL("../src/org-reader/client.ts", import.meta.url),
			"utf8",
		);
		// The same pattern as `_CALL` in tests/helpers_client_paths.py.
		const calls = [
			...source.matchAll(
				/client\.(get|post|put|patch|delete)\(\s*(?:`([^`]*)`|"([^"]*)")/g,
			),
		];
		expect(calls.map((m) => `${m[1]} ${m[2] ?? m[3]}`)).toEqual([
			"get /org/activity",
			"get /orgs/me/mls-escrow",
		]);
	});
});

describe("the transport's limits", () => {
	/** A `fetch` that, like the real one, rejects when its signal fires; `/org/activity` stalls. */
	const stalling = (stallBody: boolean) =>
		vi.fn(
			(input: Parameters<typeof fetch>[0], init?: RequestInit) =>
				new Promise<Response>((resolve, reject) => {
					const signal = init?.signal;
					if (String(input).endsWith("/oauth/token"))
						return resolve(
							jsonResponse({ access_token: "tok", expires_in: 900 }),
						);
					signal?.addEventListener("abort", () => reject(signal.reason));
					if (!stallBody) return;
					resolve(
						new Response(
							new ReadableStream({
								start(controller) {
									signal?.addEventListener("abort", () =>
										controller.error(signal.reason),
									);
								},
							}),
						),
					);
				}),
		) as unknown as typeof fetch;

	it.each([
		["a_request_that_never_answers", false],
		["a_body_that_never_finishes", true],
	])("fails_%s_with_a_reader_network_error", async (_name, stallBody) => {
		const reader = new ReaderClient({
			apiUrl: API,
			signer: READER_SIGNER,
			fetch: stalling(stallBody),
			requestTimeoutMs: 50,
		});
		await expect(reader.activity()).rejects.toBeInstanceOf(ReaderNetworkError);
	});

	it("stops_an_escrow_page_of_a_million_items_at_the_row_cap_without_a_stack_overflow", async () => {
		const { reader } = setup({
			"GET /orgs/me/mls-escrow": () =>
				jsonResponse({ rows: new Array(1_000_000).fill(0) }),
		});
		const result = await reader.escrowRows("g", 0, 1);
		expect(result.complete).toBe(false);
		expect(result.rows).toHaveLength(ESCROW_MAX_ROWS);
	});

	it("rejects_an_activity_page_over_its_limit", async () => {
		const { reader } = setup({
			"GET /org/activity": () =>
				jsonResponse({ items: new Array(101).fill(0) }),
		});
		await expect(reader.activity()).rejects.toBeInstanceOf(MalformedPageError);
	});
});
