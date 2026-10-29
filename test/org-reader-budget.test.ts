import { describe, expect, it, vi } from "vitest";
import {
	ESCROW_MAX_PAGES,
	ESCROW_MAX_ROWS,
	ReaderClient,
} from "../src/org-reader/client.js";
import {
	MAX_BODY_BYTES,
	ReaderNetworkError,
	TokenBucket,
	createBudgetedFetch,
} from "../src/org-reader/fetch-budget.js";
import {
	READER_SIGNER,
	jsonResponse,
	router,
} from "./org-reader-client-fixture.js";

const API = "https://api.test";

function clock() {
	const state = { at: 1_000_000, slept: [] as number[] };
	return {
		state,
		now: () => state.at,
		sleep: async (ms: number) => {
			state.slept.push(ms);
			state.at += ms;
		},
	};
}

describe("the token bucket", () => {
	it("serves_a_minutes_worth_at_once_then_waits_for_the_next_token", async () => {
		const time = clock();
		const bucket = new TokenBucket({
			perMinute: 20,
			now: time.now,
			sleep: time.sleep,
		});
		for (let i = 0; i < 20; i++) await bucket.take();
		expect(time.state.slept).toEqual([]);
		await bucket.take();
		expect(time.state.slept).toEqual([3000]);
	});

	it("refills_with_time_but_never_past_one_minutes_worth", async () => {
		const time = clock();
		const bucket = new TokenBucket({
			perMinute: 20,
			now: time.now,
			sleep: time.sleep,
		});
		for (let i = 0; i < 20; i++) await bucket.take();
		time.state.at += 6000;
		expect(bucket.msUntilToken()).toBe(0);
		time.state.at += 10 * 60_000;
		for (let i = 0; i < 20; i++) await bucket.take();
		expect(time.state.slept).toEqual([]);
		expect(bucket.msUntilToken()).toBe(3000);
	});
});

describe("the budgeted fetch", () => {
	const build = (transport: typeof fetch, bucket = new TokenBucket()) =>
		createBudgetedFetch({ apiUrl: API, bucket, fetch: transport });

	it("refuses_every_method_but_get_and_passes_only_the_token_mint_as_a_post", async () => {
		const transport = vi.fn(async () => jsonResponse({}));
		const budgeted = build(transport);
		for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
			await expect(
				budgeted(`${API}/groups`, { method }),
			).rejects.toBeInstanceOf(TypeError);
		}
		await expect(
			budgeted(`${API}/oauth/token/x`, { method: "POST" }),
		).rejects.toBeInstanceOf(TypeError);
		expect(transport).not.toHaveBeenCalled();
		await budgeted(`${API}/oauth/token`, { method: "POST" });
		await budgeted(`${API}/org/activity`);
		expect(transport).toHaveBeenCalledTimes(2);
	});

	it("refuses_a_non_get_method_carried_by_a_request_object", async () => {
		const transport = vi.fn(async () => jsonResponse({}));
		const budgeted = build(transport);
		await expect(
			budgeted(new Request(`${API}/groups`, { method: "DELETE" })),
		).rejects.toBeInstanceOf(TypeError);
		expect(transport).not.toHaveBeenCalled();
		await budgeted(new Request(`${API}/org/activity`));
		expect(transport).toHaveBeenCalledTimes(1);
	});

	it("passes_the_token_mint_when_the_api_url_has_a_trailing_slash", async () => {
		const transport = vi.fn(async () => jsonResponse({}));
		const budgeted = createBudgetedFetch({
			apiUrl: `${API}/`,
			bucket: new TokenBucket(),
			fetch: transport,
		});
		await budgeted(`${API}/oauth/token`, { method: "POST" });
		expect(transport).toHaveBeenCalledTimes(1);
	});

	it("takes_one_token_per_request", async () => {
		const bucket = new TokenBucket();
		const take = vi.spyOn(bucket, "take");
		const budgeted = build(async () => jsonResponse({}), bucket);
		await budgeted(`${API}/a`);
		await budgeted(`${API}/b`);
		expect(take).toHaveBeenCalledTimes(2);
	});

	it("refuses_a_body_whose_declared_length_is_over_the_cap", async () => {
		const budgeted = build(
			async () =>
				new Response("{}", {
					headers: { "content-length": String(MAX_BODY_BYTES + 1) },
				}),
		);
		await expect(budgeted(`${API}/a`)).rejects.toBeInstanceOf(
			ReaderNetworkError,
		);
	});

	it("refuses_a_streamed_body_that_passes_the_cap_and_reads_one_that_does_not", async () => {
		const chunk = new Uint8Array(1024 * 1024);
		const stream = (chunks: number) =>
			new Response(
				new ReadableStream({
					pull(controller) {
						if (chunks-- > 0) controller.enqueue(chunk);
						else controller.close();
					},
				}),
			);
		await expect(
			build(async () => stream(9))(`${API}/a`),
		).rejects.toBeInstanceOf(ReaderNetworkError);
		const ok = await build(async () => stream(8))(`${API}/a`);
		expect((await ok.arrayBuffer()).byteLength).toBe(MAX_BODY_BYTES);
	});

	it("keeps_the_status_and_headers_of_the_response_it_rebuilds", async () => {
		const res = await build(async () =>
			jsonResponse({ a: 1 }, 503, { "retry-after": "7" }),
		)(`${API}/a`);
		expect(res.status).toBe(503);
		expect(res.headers.get("retry-after")).toBe("7");
		expect(await res.json()).toEqual({ a: 1 });
	});
});

describe("requests made through the reader client", () => {
	it("count_an_inner_401_retry_and_the_token_mint_in_the_bucket", async () => {
		const bucket = new TokenBucket();
		const take = vi.spyOn(bucket, "take");
		let activity = 0;
		const transport = router({
			"POST /oauth/token": () =>
				jsonResponse({
					access_token: `t${take.mock.calls.length}`,
					expires_in: 900,
				}),
			"GET /org/activity": () =>
				activity++ === 0 ? jsonResponse({}, 401) : jsonResponse({ items: [] }),
		});
		const reader = new ReaderClient({
			apiUrl: API,
			signer: READER_SIGNER,
			bucket,
			fetch: transport,
		});
		await reader.activity();
		// mint, activity (401), mint again, activity
		expect(transport).toHaveBeenCalledTimes(4);
		expect(take).toHaveBeenCalledTimes(4);
	});

	it("count_the_token_mints_429_retry_in_the_bucket", async () => {
		const bucket = new TokenBucket();
		const take = vi.spyOn(bucket, "take");
		let mints = 0;
		const transport = router({
			"POST /oauth/token": () =>
				mints++ === 0
					? jsonResponse({}, 429, { "retry-after": "0.001" })
					: jsonResponse({ access_token: "t", expires_in: 900 }),
			"GET /org/activity": () => jsonResponse({ items: [] }),
		});
		const reader = new ReaderClient({
			apiUrl: API,
			signer: READER_SIGNER,
			bucket,
			fetch: transport,
		});
		await reader.activity();
		expect(transport).toHaveBeenCalledTimes(3);
		expect(take).toHaveBeenCalledTimes(3);
	});

	it("send_only_get_requests_and_the_token_mint", async () => {
		const transport = router({
			"POST /oauth/token": () =>
				jsonResponse({ access_token: "t", expires_in: 900 }),
			"GET /org/activity": () => jsonResponse({ items: [] }),
			"GET /orgs/me/mls-escrow": () => jsonResponse({ rows: [] }),
		});
		const reader = new ReaderClient({
			apiUrl: API,
			signer: READER_SIGNER,
			fetch: transport,
		});
		await reader.activity();
		await reader.escrowRows("g", 0, 3);
		const sent = transport.mock.calls.map(
			([input, init]) =>
				`${init?.method ?? "GET"} ${new URL(String(input)).pathname}`,
		);
		expect(new Set(sent)).toEqual(
			new Set([
				"POST /oauth/token",
				"GET /org/activity",
				"GET /orgs/me/mls-escrow",
			]),
		);
	});
});

describe("escrow pagination", () => {
	const pages = (next: (n: number) => string | null, rowsPerPage = 1) => {
		let n = 0;
		return router({
			"POST /oauth/token": () =>
				jsonResponse({ access_token: "t", expires_in: 900 }),
			"GET /orgs/me/mls-escrow": () => {
				const rows = Array.from({ length: rowsPerPage }, (_, i) => ({ n, i }));
				return jsonResponse({ rows, next_cursor: next(n++) });
			},
		});
	};
	const read = (transport: typeof fetch) =>
		new ReaderClient({
			apiUrl: API,
			signer: READER_SIGNER,
			fetch: transport,
			bucket: new TokenBucket({ perMinute: 100_000 }),
		}).escrowRows("g", 0, 9);

	it("reads_every_page_to_the_last_and_reports_it_complete", async () => {
		const result = await read(pages((n) => (n < 2 ? `c${n}` : null)));
		expect(result.rows).toHaveLength(3);
		expect(result.complete).toBe(true);
	});

	it("stops_on_a_repeated_cursor", async () => {
		const transport = pages(() => "same");
		const result = await read(transport);
		expect(result.complete).toBe(false);
		expect(result.rows).toHaveLength(2);
	});

	it("stops_after_the_page_cap", async () => {
		const transport = pages((n) => `c${n}`);
		const result = await read(transport);
		expect(result.complete).toBe(false);
		expect(result.rows).toHaveLength(ESCROW_MAX_PAGES);
		expect(
			transport.mock.calls.filter(([url]) =>
				String(url).includes("mls-escrow"),
			),
		).toHaveLength(ESCROW_MAX_PAGES);
	});

	it("stops_at_the_row_cap_even_when_a_page_overshoots_it", async () => {
		const result = await read(pages((n) => `c${n}`, ESCROW_MAX_ROWS));
		expect(result.complete).toBe(false);
		expect(result.rows).toHaveLength(ESCROW_MAX_ROWS);
	});
});
