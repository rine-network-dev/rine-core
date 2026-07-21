/**
 * F-4 — a malformed payment payload must yield a typed MALFORMED_PAYLOAD refusal
 * at parse time, never a downstream `pp.accepted.network` / `authorization.from`
 * deref crash. Valid payloads still round-trip unchanged.
 */

import { describe, expect, it } from "vitest";
import { X402_ERROR } from "../../src/x402/errors.js";
import { X402_MESSAGE_TYPE } from "../../src/x402/message-types.js";
import { parseX402Payload } from "../../src/x402/parse.js";

const PAYMENT = X402_MESSAGE_TYPE.PAYMENT;

function expectCode(fn: () => unknown, code: string): void {
	try {
		fn();
		throw new Error("expected a typed X402Error");
	} catch (err) {
		expect((err as { code?: string }).code).toBe(code);
	}
}

const validPayment = JSON.stringify({
	x402Version: 2,
	accepted: {
		scheme: "exact",
		network: "eip155:84532",
		amount: "1000000",
		asset: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
		payTo: "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF",
		maxTimeoutSeconds: 60,
		extra: { name: "USDC", version: "2" },
	},
	payload: {
		signature: `0x${"11".repeat(65)}`,
		authorization: {
			from: "0x1111111111111111111111111111111111111111",
			to: "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF",
			value: "1000000",
			validAfter: "1",
			validBefore: "9999999999",
			nonce: `0x${"22".repeat(32)}`,
		},
	},
});

describe("parseX402Payload — PAYMENT structural validation (F-4)", () => {
	it("test_valid_payment_parses_unchanged", () => {
		const parsed = parseX402Payload(PAYMENT, validPayment) as Record<
			string,
			unknown
		>;
		expect((parsed.accepted as { network: string }).network).toBe(
			"eip155:84532",
		);
	});

	it("test_missing_accepted_is_malformed", () => {
		expectCode(
			() =>
				parseX402Payload(
					PAYMENT,
					JSON.stringify({ payload: { authorization: {} } }),
				),
			X402_ERROR.MALFORMED_PAYLOAD,
		);
	});

	it("test_missing_payload_is_malformed", () => {
		expectCode(
			() => parseX402Payload(PAYMENT, JSON.stringify({ accepted: {} })),
			X402_ERROR.MALFORMED_PAYLOAD,
		);
	});

	it("test_empty_payload_object_is_malformed", () => {
		// The audit's exact crash input: `{"payload":{}}` — no accepted, no auth.
		expectCode(
			() => parseX402Payload(PAYMENT, JSON.stringify({ payload: {} })),
			X402_ERROR.MALFORMED_PAYLOAD,
		);
	});

	it("test_missing_authorization_is_malformed", () => {
		expectCode(
			() =>
				parseX402Payload(
					PAYMENT,
					JSON.stringify({ accepted: {}, payload: { signature: "0x" } }),
				),
			X402_ERROR.MALFORMED_PAYLOAD,
		);
	});

	it("test_non_object_body_is_malformed", () => {
		expectCode(
			() => parseX402Payload(PAYMENT, "[]"),
			X402_ERROR.MALFORMED_PAYLOAD,
		);
	});
});
