/**
 * x402 facilitator client — the single implementation now lives in rine-core.
 * The facilitator is an EXTERNAL service, so the only thing to mock is the
 * global `fetch`; every assertion is against the public verify/settle interface
 * and the standard x402 V2 request body it posts.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	FACILITATOR_PRESET,
	X402FacilitatorError,
	facilitatorRequestBody,
	settlePayment,
	verifyPayment,
} from "../../src/x402/facilitator.js";
import type { PaymentPayload } from "../../src/x402/types.js";

const EURC_BASE = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42";

function paymentPayload(): PaymentPayload {
	return {
		x402Version: 2,
		accepted: {
			scheme: "exact",
			network: "eip155:8453",
			amount: "100000",
			asset: EURC_BASE,
			payTo: "0x000000000000000000000000000000000000dEaD",
			maxTimeoutSeconds: 60,
			extra: { name: "EURC", version: "2" },
		},
		payload: {
			signature: `0x${"11".repeat(65)}`,
			authorization: {
				from: "0x1111111111111111111111111111111111111111",
				to: "0x000000000000000000000000000000000000dEaD",
				value: "100000",
				validAfter: "1",
				validBefore: "9999999999",
				nonce: `0x${"22".repeat(32)}`,
			},
		},
		extensions: {},
	};
}

afterEach(() => {
	vi.clearAllMocks();
	vi.unstubAllGlobals();
});

describe("facilitatorRequestBody", () => {
	it("test_body_echoes_accepted_requirement_verbatim_as_paymentRequirements", () => {
		const pp = paymentPayload();
		const body = facilitatorRequestBody(pp);
		expect(body.x402Version).toBe(2);
		expect(body.paymentPayload).toBe(pp);
		// The single accepted requirement is echoed verbatim (no reshape).
		expect(body.paymentRequirements).toBe(pp.accepted);
		expect(body.paymentRequirements.asset).toBe(EURC_BASE);
	});

	it("test_body_defaults_x402Version_when_absent", () => {
		const pp = paymentPayload();
		pp.x402Version = undefined as unknown as number;
		expect(facilitatorRequestBody(pp).x402Version).toBe(2);
	});
});

describe("FACILITATOR_PRESET", () => {
	it("test_presets_expose_reference_facilitator_base_urls", () => {
		expect(FACILITATOR_PRESET.cdp.url).toBe(
			"https://api.cdp.coinbase.com/platform/v2/x402",
		);
		expect(FACILITATOR_PRESET.payai.url).toBe(
			"https://facilitator.payai.network",
		);
		expect(FACILITATOR_PRESET["x402-rs"].url).toBe("http://localhost:8080");
	});
});

describe("verifyPayment", () => {
	it("test_verify_posts_standard_body_to_verify_endpoint_and_returns_response", async () => {
		const fetchMock = vi.fn(
			async () =>
				new Response(JSON.stringify({ isValid: true, payer: "0x1111" }), {
					status: 200,
				}),
		);
		vi.stubGlobal("fetch", fetchMock);

		const res = await verifyPayment(paymentPayload(), {
			facilitator: FACILITATOR_PRESET.payai,
		});

		expect(res.isValid).toBe(true);
		expect(res.payer).toBe("0x1111");
		const [url, init] = fetchMock.mock.calls[0] as unknown as [
			string,
			RequestInit,
		];
		expect(url).toBe("https://facilitator.payai.network/verify");
		expect(init.method).toBe("POST");
		const body = JSON.parse(init.body as string);
		expect(body.x402Version).toBe(2);
		expect(body.paymentRequirements.asset).toBe(EURC_BASE);
		expect(body.paymentPayload.payload.signature).toMatch(/^0x/);
	});

	it("test_verify_honors_custom_verifyPath_and_strips_trailing_slash", async () => {
		const fetchMock = vi.fn(
			async () =>
				new Response(JSON.stringify({ isValid: true }), { status: 200 }),
		);
		vi.stubGlobal("fetch", fetchMock);

		await verifyPayment(paymentPayload(), {
			facilitator: {
				url: "https://fac.example.com/",
				verifyPath: "/x402/verify",
			},
		});

		const [url] = fetchMock.mock.calls[0] as unknown as [string];
		expect(url).toBe("https://fac.example.com/x402/verify");
	});

	it("test_verify_sends_provider_auth_headers", async () => {
		const fetchMock = vi.fn(
			async () =>
				new Response(JSON.stringify({ isValid: true }), { status: 200 }),
		);
		vi.stubGlobal("fetch", fetchMock);

		await verifyPayment(paymentPayload(), {
			facilitator: {
				url: "https://fac.example.com",
				headers: { authorization: "Bearer secret" },
			},
		});

		const [, init] = fetchMock.mock.calls[0] as unknown as [
			string,
			RequestInit,
		];
		const headers = init.headers as Record<string, string>;
		expect(headers.authorization).toBe("Bearer secret");
		expect(headers["content-type"]).toBe("application/json");
	});
});

describe("settlePayment", () => {
	it("test_settle_posts_to_settle_endpoint_and_returns_settlement", async () => {
		const settlement = {
			success: true,
			transaction: "0xabc",
			network: "base-sepolia", // v1 slug echoed verbatim; NEVER string-matched
			payer: "0x1111",
		};
		const fetchMock = vi.fn(
			async () => new Response(JSON.stringify(settlement), { status: 200 }),
		);
		vi.stubGlobal("fetch", fetchMock);

		const res = await settlePayment(paymentPayload(), {
			facilitator: FACILITATOR_PRESET.payai,
		});

		expect(res.success).toBe(true);
		expect(res.transaction).toBe("0xabc");
		// The verbatim v1 network slug survives round-trip untouched.
		expect(res.network).toBe("base-sepolia");
		const [url] = fetchMock.mock.calls[0] as unknown as [string];
		expect(url).toBe("https://facilitator.payai.network/settle");
	});
});

describe("X402FacilitatorError", () => {
	it("test_non_2xx_throws_with_status_and_parsed_body", async () => {
		const fetchMock = vi.fn(
			async () =>
				new Response(JSON.stringify({ error: "resource required" }), {
					status: 400,
				}),
		);
		vi.stubGlobal("fetch", fetchMock);

		await expect(
			verifyPayment(paymentPayload(), {
				facilitator: FACILITATOR_PRESET.payai,
			}),
		).rejects.toMatchObject({
			name: "X402FacilitatorError",
			status: 400,
			body: { error: "resource required" },
		});
	});

	it("test_non_json_response_throws_facilitator_error", async () => {
		const fetchMock = vi.fn(
			async () => new Response("<html>gateway</html>", { status: 502 }),
		);
		vi.stubGlobal("fetch", fetchMock);

		await expect(
			settlePayment(paymentPayload(), {
				facilitator: FACILITATOR_PRESET.payai,
			}),
		).rejects.toBeInstanceOf(X402FacilitatorError);
	});

	it("test_transport_failure_wraps_as_facilitator_error", async () => {
		const fetchMock = vi.fn(async () => {
			throw new Error("ECONNREFUSED");
		});
		vi.stubGlobal("fetch", fetchMock);

		await expect(
			verifyPayment(paymentPayload(), {
				facilitator: FACILITATOR_PRESET.payai,
			}),
		).rejects.toMatchObject({ name: "X402FacilitatorError" });
	});

	it("test_abort_propagates_the_abort_error", async () => {
		const fetchMock = vi.fn(async () => {
			const err = new Error("aborted");
			err.name = "AbortError";
			throw err;
		});
		vi.stubGlobal("fetch", fetchMock);

		await expect(
			verifyPayment(paymentPayload(), {
				facilitator: FACILITATOR_PRESET.payai,
			}),
		).rejects.toMatchObject({ name: "AbortError" });
	});
});
