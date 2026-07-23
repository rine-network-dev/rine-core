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
import type {
	PaymentPayload,
	PaymentRequirements,
} from "../../src/x402/types.js";
import { X402_QUOTE_REF_KEY } from "../../src/x402/types.js";

const EURC_BASE = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42";
const MERCHANT = "0x000000000000000000000000000000000000dEaD";

/** The payee-owned requirement callers reconcile against and forward. */
function requirement(
	over: Partial<PaymentRequirements> = {},
): PaymentRequirements {
	return {
		scheme: "exact",
		network: "eip155:8453",
		amount: "100000",
		asset: EURC_BASE,
		payTo: MERCHANT,
		maxTimeoutSeconds: 60,
		extra: { name: "EURC", version: "2" },
		...over,
	};
}

function paymentPayload(): PaymentPayload {
	return {
		x402Version: 2,
		accepted: requirement(),
		payload: {
			signature: `0x${"11".repeat(65)}`,
			authorization: {
				from: "0x1111111111111111111111111111111111111111",
				to: MERCHANT,
				value: "100000",
				validAfter: "1",
				validBefore: "9999999999",
				nonce: `0x${"22".repeat(32)}`,
			},
		},
		extensions: {},
	};
}

function okFetch(body: unknown, status = 200) {
	return vi.fn(async () => new Response(JSON.stringify(body), { status }));
}

afterEach(() => {
	vi.clearAllMocks();
	vi.unstubAllGlobals();
});

describe("facilitatorRequestBody", () => {
	it("test_body_forwards_the_payee_owned_requirement_not_the_payer_accepted", () => {
		const pp = paymentPayload();
		// The payee reconciled to its OWN terms (payTo/amount authored by payee);
		// the body must send THAT, never `pp.accepted`.
		const payeeReq = requirement({ payTo: MERCHANT, amount: "100000" });
		const body = facilitatorRequestBody(pp, payeeReq);
		expect(body.x402Version).toBe(2);
		expect(body.paymentPayload.accepted).toBe(pp.accepted);
		expect(body.paymentPayload.payload).toBe(pp.payload);
		expect(body.paymentRequirements).toBe(payeeReq);
	});

	it("test_body_strips_extensions_and_unknown_keys_from_the_forwarded_payload", () => {
		// The quote-ref stamp is rine-payee-internal (read from the payee's own
		// decrypted payment, never the facilitator round-trip) and facilitators
		// schema-validate `extensions` (PayAI 403s non-object values) — so nothing
		// outside the standard whitelist may reach a facilitator.
		const pp = paymentPayload();
		pp.extensions = { [X402_QUOTE_REF_KEY]: "11111111-2222-3333-4444-555555555555" };
		pp["rine.internal"] = "never-forwarded";
		const body = facilitatorRequestBody(pp, requirement());
		expect(body.paymentPayload.extensions).toBeUndefined();
		expect(body.paymentPayload["rine.internal"]).toBeUndefined();
		// The signed struct and payee-reconciled terms still go through intact.
		expect(body.paymentPayload.accepted).toBe(pp.accepted);
		expect(body.paymentPayload.payload).toBe(pp.payload);
		// The original payload is NOT mutated — the payee still reads its quote-ref.
		expect(pp.extensions[X402_QUOTE_REF_KEY]).toBe(
			"11111111-2222-3333-4444-555555555555",
		);
	});

	it("test_body_preserves_standard_top_level_scheme_and_network", () => {
		// Interop payloads (x402 V2 wire format) carry top-level `scheme`/`network`
		// via unknown-key passthrough; those ARE standard and must survive the strip.
		const pp = paymentPayload();
		pp.scheme = "exact";
		pp.network = "eip155:84532";
		const body = facilitatorRequestBody(pp, requirement());
		expect(body.paymentPayload.scheme).toBe("exact");
		expect(body.paymentPayload.network).toBe("eip155:84532");
	});

	it("test_body_defaults_x402Version_when_absent", () => {
		const pp = paymentPayload();
		pp.x402Version = undefined as unknown as number;
		expect(facilitatorRequestBody(pp, requirement()).x402Version).toBe(2);
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
		const fetchMock = okFetch({ isValid: true, payer: "0x1111" });
		vi.stubGlobal("fetch", fetchMock);

		const res = await verifyPayment(paymentPayload(), requirement(), {
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
		// Even an empty `extensions` never rides to the facilitator.
		expect(body.paymentPayload).not.toHaveProperty("extensions");
	});

	it("test_verify_honors_custom_verifyPath_and_strips_trailing_slash", async () => {
		const fetchMock = okFetch({ isValid: true });
		vi.stubGlobal("fetch", fetchMock);

		await verifyPayment(paymentPayload(), requirement(), {
			facilitator: {
				url: "https://fac.example.com/",
				verifyPath: "/x402/verify",
			},
		});

		const [url] = fetchMock.mock.calls[0] as unknown as [string];
		expect(url).toBe("https://fac.example.com/x402/verify");
	});

	it("test_verify_sends_provider_auth_headers", async () => {
		const fetchMock = okFetch({ isValid: true });
		vi.stubGlobal("fetch", fetchMock);

		await verifyPayment(paymentPayload(), requirement(), {
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
		const fetchMock = okFetch(settlement);
		vi.stubGlobal("fetch", fetchMock);

		const res = await settlePayment(paymentPayload(), requirement(), {
			facilitator: FACILITATOR_PRESET.payai,
		});

		expect(res.success).toBe(true);
		expect(res.transaction).toBe("0xabc");
		expect(res.network).toBe("base-sepolia");
		const [url] = fetchMock.mock.calls[0] as unknown as [string];
		expect(url).toBe("https://facilitator.payai.network/settle");
	});
});

describe("X402FacilitatorError", () => {
	it("test_non_2xx_throws_with_status_and_parsed_body", async () => {
		const fetchMock = okFetch({ error: "resource required" }, 400);
		vi.stubGlobal("fetch", fetchMock);

		await expect(
			verifyPayment(paymentPayload(), requirement(), {
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
			settlePayment(paymentPayload(), requirement(), {
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
			verifyPayment(paymentPayload(), requirement(), {
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
			verifyPayment(paymentPayload(), requirement(), {
				facilitator: FACILITATOR_PRESET.payai,
			}),
		).rejects.toMatchObject({ name: "AbortError" });
	});
});

describe("transport enforcement", () => {
	it("test_rejects_cleartext_http_with_credentials_to_non_loopback", async () => {
		vi.stubGlobal("fetch", okFetch({ isValid: true }));
		await expect(
			verifyPayment(paymentPayload(), requirement(), {
				facilitator: {
					url: "http://evil.example.com",
					headers: { authorization: "Bearer secret" },
				},
			}),
		).rejects.toBeInstanceOf(X402FacilitatorError);
	});

	it("test_allows_http_loopback_even_with_credentials", async () => {
		const fetchMock = okFetch({ isValid: true });
		vi.stubGlobal("fetch", fetchMock);
		await verifyPayment(paymentPayload(), requirement(), {
			facilitator: {
				url: "http://localhost:8080",
				headers: { authorization: "Bearer secret" },
			},
		});
		expect(fetchMock).toHaveBeenCalledOnce();
	});

	it("test_rejects_http_non_loopback_even_without_credentials", async () => {
		// Tightened: a facilitator call carries payment terms; cleartext http
		// to a remote host is refused regardless of whether headers are present.
		vi.stubGlobal("fetch", okFetch({ isValid: true }));
		await expect(
			verifyPayment(paymentPayload(), requirement(), {
				facilitator: { url: "http://dev.example.com:8080" },
			}),
		).rejects.toBeInstanceOf(X402FacilitatorError);
	});

	it("test_allows_http_ipv6_loopback_bracketed", async () => {
		// `new URL("http://[::1]").hostname` is the BRACKETED `[::1]`; the loopback
		// check strips the brackets so IPv6 loopback matches (parity with Python's
		// unbracketed `urlsplit().hostname` → `::1`).
		const fetchMock = okFetch({ isValid: true });
		vi.stubGlobal("fetch", fetchMock);
		await verifyPayment(paymentPayload(), requirement(), {
			facilitator: {
				url: "http://[::1]:8080",
				headers: { authorization: "Bearer secret" },
			},
		});
		expect(fetchMock).toHaveBeenCalledOnce();
	});

	it("test_allows_http_ipv4_loopback", async () => {
		const fetchMock = okFetch({ isValid: true });
		vi.stubGlobal("fetch", fetchMock);
		await verifyPayment(paymentPayload(), requirement(), {
			facilitator: { url: "http://127.0.0.1:8080" },
		});
		expect(fetchMock).toHaveBeenCalledOnce();
	});

	it("test_allows_https", async () => {
		const fetchMock = okFetch({ isValid: true });
		vi.stubGlobal("fetch", fetchMock);
		await verifyPayment(paymentPayload(), requirement(), {
			facilitator: {
				url: "https://fac.example.com",
				headers: { authorization: "Bearer secret" },
			},
		});
		expect(fetchMock).toHaveBeenCalledOnce();
	});

	it("test_rejects_non_http_scheme", async () => {
		vi.stubGlobal("fetch", okFetch({ isValid: true }));
		await expect(
			verifyPayment(paymentPayload(), requirement(), {
				facilitator: { url: "file:///etc/passwd" },
			}),
		).rejects.toBeInstanceOf(X402FacilitatorError);
	});
});

describe("facilitator path validation", () => {
	for (const bad of ["verify", "//evil.com/verify", "/x@evil/verify"]) {
		it(`test_rejects_bad_verifyPath_${bad}`, async () => {
			vi.stubGlobal("fetch", okFetch({ isValid: true }));
			await expect(
				verifyPayment(paymentPayload(), requirement(), {
					facilitator: { url: "https://fac.example.com", verifyPath: bad },
				}),
			).rejects.toBeInstanceOf(X402FacilitatorError);
		});
	}

	it("test_rejects_bad_settlePath", async () => {
		vi.stubGlobal("fetch", okFetch({ success: true }));
		await expect(
			settlePayment(paymentPayload(), requirement(), {
				facilitator: {
					url: "https://fac.example.com",
					settlePath: "//x/settle",
				},
			}),
		).rejects.toBeInstanceOf(X402FacilitatorError);
	});
});

describe("request timeout", () => {
	it("test_default_timeout_signal_is_wired_when_caller_supplies_none", async () => {
		const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
			// A default AbortSignal.timeout is composed even without a caller signal.
			expect(init.signal).toBeInstanceOf(AbortSignal);
			return new Response(JSON.stringify({ isValid: true }), { status: 200 });
		});
		vi.stubGlobal("fetch", fetchMock);
		await verifyPayment(paymentPayload(), requirement(), {
			facilitator: FACILITATOR_PRESET.payai,
		});
		expect(fetchMock).toHaveBeenCalledOnce();
	});

	it("test_caller_signal_is_composed_and_still_aborts_the_request", async () => {
		const fetchMock = vi.fn(
			(_url: string, init: RequestInit) =>
				new Promise<Response>((_resolve, reject) => {
					const signal = init.signal as AbortSignal;
					signal.addEventListener("abort", () => {
						const err = new Error("aborted");
						err.name = "AbortError";
						reject(err);
					});
				}),
		);
		vi.stubGlobal("fetch", fetchMock);

		const controller = new AbortController();
		const p = verifyPayment(paymentPayload(), requirement(), {
			facilitator: FACILITATOR_PRESET.payai,
			signal: controller.signal,
		});
		controller.abort();
		await expect(p).rejects.toMatchObject({ name: "AbortError" });
	});
});
