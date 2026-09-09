/**
 * The quote ref is payer-controlled, and it names a URL.
 *
 * `loadReferencedQuote` interpolates `extensions["rine.quoteMessageId"]` straight
 * into `GET /messages/{ref}` with the PAYEE's acting-agent header on it. Every
 * other guard in that function reads the RESPONSE, so before this refusal existed
 * the only thing standing between a payer and any endpoint the payee can reach was
 * `typeof ref === "string" && ref !== ""` — and the server has GETs that MUTATE
 * (`/agents/{id}/mls/welcomes` consumes the welcomes it returns), so the payer
 * could spend the payee's credentials on a destructive read and take a
 * fail-closed `NO_QUOTE` as its cover story.
 *
 * 🔴 The load-bearing assertion in every refusal test here is
 * `expect(get).not.toHaveBeenCalled()`, not the thrown error. A guard that refused
 * on the way back would satisfy an error-shape assertion and still have issued the
 * request — the damage is done by the request, not by the return value.
 */

import { describe, expect, it, vi } from "vitest";
import type { HttpClient } from "../../src/http.js";
import { X402Error, X402_ERROR } from "../../src/x402/errors.js";
import { loadReferencedQuote } from "../../src/x402/quote-ref.js";
import { X402_QUOTE_REF_KEY, type PaymentPayload } from "../../src/x402/types.js";

const PAYEE = "44444444-0000-4000-8000-000000000004";
const CONV = "22222222-0000-4000-8000-000000000002";
const QUOTE_ID = "66666666-0000-4000-8000-000000000006";

/** A payment carrying whatever ref the caller wants to smuggle. */
function paymentWithRef(ref: unknown): PaymentPayload {
	return {
		x402Version: 2,
		accepted: {
			scheme: "exact",
			network: "eip155:84532",
			amount: "1",
			asset: "0xasset",
			payTo: "0xpayee",
			maxTimeoutSeconds: 60,
		},
		payload: { signature: "0xsig", authorization: {} },
		extensions: { [X402_QUOTE_REF_KEY]: ref },
	} as unknown as PaymentPayload;
}

/** A client that records every GET and never answers one. */
function recordingClient(): { client: HttpClient; get: ReturnType<typeof vi.fn> } {
	const get = vi.fn(async () => {
		throw new Error("404 not found");
	});
	return { client: { get } as unknown as HttpClient, get };
}

async function load(ref: unknown, client: HttpClient): Promise<unknown> {
	return loadReferencedQuote({
		payment: paymentWithRef(ref),
		client,
		configDir: "/nonexistent",
		payeeAgentId: PAYEE,
		conversationId: CONV,
	});
}

describe("loadReferencedQuote — the ref cannot name an endpoint", () => {
	/**
	 * The audit's own reproduction: a traversal out of `/messages/` and into the
	 * MLS welcome drain, which is a GET that consumes what it hands back. One
	 * settle of a payment the payee never has to accept, and the payee's pending
	 * welcomes are gone — every group it was mid-join on goes un-decryptable, and
	 * the payer sees an ordinary `NO_QUOTE`.
	 */
	it("test_load_when_the_ref_traverses_to_a_mutating_get_then_no_request_is_issued", async () => {
		const { client, get } = recordingClient();

		await expect(
			load(`../agents/${PAYEE}/mls/welcomes`, client),
		).rejects.toThrow(X402Error);
		expect(get).not.toHaveBeenCalled();
	});

	it("test_load_when_the_ref_appends_a_query_string_then_no_request_is_issued", async () => {
		const { client, get } = recordingClient();

		await expect(load(`${QUOTE_ID}?limit=1000`, client)).rejects.toThrow(
			X402Error,
		);
		expect(get).not.toHaveBeenCalled();
	});

	it("test_load_when_the_ref_is_not_an_id_at_all_then_no_request_is_issued", async () => {
		const { client, get } = recordingClient();

		await expect(load("quote-9999", client)).rejects.toThrow(X402Error);
		expect(get).not.toHaveBeenCalled();
	});

	it("test_load_when_the_ref_is_refused_then_the_code_is_the_same_no_quote", async () => {
		const { client } = recordingClient();

		// A settle path must not learn a NEW error class from a hostile ref: the
		// surfaces above it branch on `NO_QUOTE` and would render anything else as
		// an internal failure of the payee's own.
		await expect(load("../../etc/passwd", client)).rejects.toMatchObject({
			code: X402_ERROR.NO_QUOTE,
		});
	});

	/**
	 * The control, and the reason the three above prove anything: this harness DOES
	 * issue the request when the ref is a real id, so a refusal above is the guard
	 * and not a broken fixture.
	 */
	it("test_load_when_the_ref_is_a_real_id_then_the_message_is_fetched", async () => {
		const { client, get } = recordingClient();

		await expect(load(QUOTE_ID, client)).rejects.toThrow(X402Error);

		expect(get).toHaveBeenCalledOnce();
		expect(get.mock.calls[0]![0]).toBe(`/messages/${QUOTE_ID}`);
	});

	/**
	 * 🔴 A pre-flight is only allowed to refuse what the wire would have refused.
	 * The server types this path parameter `uuid.UUID`, which has always read the
	 * dashless spelling as an id — so refusing it here would be a capability
	 * removal wearing a validation fix, and this is the test that would catch one.
	 */
	it("test_load_when_the_ref_is_dashless_then_it_is_still_fetched", async () => {
		const { client, get } = recordingClient();
		const dashless = QUOTE_ID.replace(/-/g, "");

		await expect(load(dashless, client)).rejects.toThrow(X402Error);

		expect(get).toHaveBeenCalledOnce();
		expect(get.mock.calls[0]![0]).toBe(`/messages/${dashless}`);
	});
});
