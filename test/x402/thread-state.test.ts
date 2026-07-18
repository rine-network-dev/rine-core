import { describe, expect, it } from "vitest";
import {
	X402_MESSAGE_TYPE,
	X402_STATUS,
	buildPaymentMessage,
	buildPaymentRequiredMessage,
	buildReceiptMessage,
	x402ThreadStatus,
} from "../../src/x402/index.js";
import type {
	PaymentPayload,
	PaymentRequired,
	SettlementResponse,
} from "../../src/x402/types.js";

const QUOTE: PaymentRequired = {
	x402Version: 2,
	accepts: [
		{
			scheme: "exact",
			network: "eip155:8453",
			amount: "100000",
			asset: "0xEURC",
			payTo: "0xPAYEE",
			maxTimeoutSeconds: 60,
			extra: { name: "EURC", version: "2" },
		},
	],
};
const PAYMENT = {
	x402Version: 2,
	accepted: QUOTE.accepts[0],
	payload: {},
} as unknown as PaymentPayload;
const RECEIPT: SettlementResponse = {
	success: true,
	transaction: "0x1",
	network: "eip155:8453",
	payer: "0xP",
};

// A thread entry as the reducer consumes it: type + cleartext metadata (marker).
function entryFrom(built: { type: string; metadata?: unknown }) {
	return {
		type: built.type,
		metadata: built.metadata as Record<string, unknown> | undefined,
	};
}

describe("x402ThreadStatus", () => {
	it("threadState_empty_returnsNull", () => {
		expect(x402ThreadStatus([])).toBeNull();
	});

	it("threadState_nonX402Only_returnsNull", () => {
		expect(
			x402ThreadStatus([
				{ type: "rine.v1.task_request" },
				{ type: "rine.v1.task_response" },
			]),
		).toBeNull();
	});

	it("threadState_quoteOnly_isRequired", () => {
		expect(
			x402ThreadStatus([entryFrom(buildPaymentRequiredMessage(QUOTE))]),
		).toBe(X402_STATUS.REQUIRED);
	});

	it("threadState_quoteThenPay_isSubmitted", () => {
		expect(
			x402ThreadStatus([
				entryFrom(buildPaymentRequiredMessage(QUOTE)),
				entryFrom(buildPaymentMessage(PAYMENT)),
			]),
		).toBe(X402_STATUS.SUBMITTED);
	});

	it("threadState_quotePayReceipt_isCompleted", () => {
		expect(
			x402ThreadStatus([
				{ type: "rine.v1.task_request" },
				entryFrom(buildPaymentRequiredMessage(QUOTE)),
				entryFrom(buildPaymentMessage(PAYMENT)),
				entryFrom(buildReceiptMessage(RECEIPT)),
			]),
		).toBe(X402_STATUS.COMPLETED);
	});

	it("threadState_failedReceipt_isFailed", () => {
		const failed = buildReceiptMessage({
			success: false,
			transaction: "",
			network: "eip155:8453",
			payer: "0xP",
			errorReason: "insufficient_funds",
		});
		expect(
			x402ThreadStatus([
				entryFrom(buildPaymentRequiredMessage(QUOTE)),
				entryFrom(buildPaymentMessage(PAYMENT)),
				entryFrom(failed),
			]),
		).toBe(X402_STATUS.FAILED);
	});

	it("threadState_sealedMessages_derivesFromTypeAndSuccess", () => {
		// No markers (fully sealed) — the reducer falls back to type + success.
		expect(
			x402ThreadStatus([
				{ type: X402_MESSAGE_TYPE.PAYMENT_REQUIRED },
				{ type: X402_MESSAGE_TYPE.PAYMENT },
				{ type: X402_MESSAGE_TYPE.RECEIPT, success: false },
			]),
		).toBe(X402_STATUS.FAILED);
	});

	it("threadState_sealedReceiptSuccessUnknown_defaultsCompleted", () => {
		expect(x402ThreadStatus([{ type: X402_MESSAGE_TYPE.RECEIPT }])).toBe(
			X402_STATUS.COMPLETED,
		);
	});
});
