import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	type AgentKeys,
	generateAgentKeys,
	saveAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
} from "../../src/crypto/keys.js";
import { decryptMessage, encryptMessage } from "../../src/crypto/message.js";
import { X402Error } from "../../src/x402/errors.js";
import {
	X402_MESSAGE_TYPE,
	X402_METADATA_KEY,
	X402_RAIL,
	X402_STATUS,
	buildPaymentMessage,
	buildPaymentRequiredMessage,
	buildReceiptMessage,
	isX402MessageType,
	parseX402Payload,
	readX402Marker,
	x402Marker,
} from "../../src/x402/index.js";
import type {
	PaymentPayload,
	PaymentRequired,
	SettlementResponse,
} from "../../src/x402/types.js";

const PAYEE = "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF";
const PAYER = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
const EURC = "0x808456652fA6a1B03Dd2E7Fb87dF1a8FCda9Bb3B";

const QUOTE: PaymentRequired = {
	x402Version: 2,
	error: "PAYMENT-SIGNATURE header is required",
	resource: {
		url: "rine://task/translate",
		description: "Translate 1 page",
		mimeType: "application/json",
	},
	accepts: [
		{
			scheme: "exact",
			network: "eip155:8453",
			amount: "100000",
			asset: EURC,
			payTo: PAYEE,
			maxTimeoutSeconds: 60,
			extra: { name: "EURC", version: "2" },
		},
	],
	extensions: {},
};

const REQ = QUOTE.accepts[0] as PaymentRequired["accepts"][number];

const PAYMENT: PaymentPayload = {
	x402Version: 2,
	resource: { url: "rine://task/translate" },
	accepted: REQ,
	payload: {
		signature: `0x${"ab".repeat(65)}`,
		authorization: {
			from: PAYER,
			to: PAYEE,
			value: "100000",
			validAfter: "1740672089",
			validBefore: "1740672154",
			nonce: `0x${"cd".repeat(32)}`,
		},
	},
	extensions: {},
};

const RECEIPT: SettlementResponse = {
	success: true,
	transaction: `0x${"ef".repeat(32)}`,
	network: "eip155:8453",
	payer: PAYER,
};

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-x402-msg-"));
}

const SENDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const RECIPIENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";

function mockClientWithKeys(keys: AgentKeys) {
	return {
		get: vi.fn().mockImplementation((path: string) => {
			if (path.includes("/keys")) {
				return Promise.resolve({
					agent_id: SENDER_ID,
					signing_public_key: signingPublicKeyToJWK(keys.signing.publicKey),
					encryption_public_key: {
						kty: "OKP",
						crv: "X25519",
						x: toBase64Url(keys.encryption.publicKey),
					},
				});
			}
			return Promise.reject(new Error(`Unexpected GET: ${path}`));
		}),
		post: vi.fn(),
	};
}

describe("x402 message build", () => {
	it("build_paymentRequired_setsTypeSchemaAndRequiredMarker", () => {
		const m = buildPaymentRequiredMessage(QUOTE);
		expect(m.type).toBe(X402_MESSAGE_TYPE.PAYMENT_REQUIRED);
		expect(m.content_type).toBe("application/json");
		expect(m.payload_schema).toContain("x402-payment-required.json");
		expect(m.payload).toBe(QUOTE); // verbatim, same reference — no reshape
		expect(m.metadata).toEqual({
			[X402_METADATA_KEY]: { status: X402_STATUS.REQUIRED, rail: X402_RAIL },
		});
	});

	it("build_payment_setsSubmittedMarker", () => {
		const m = buildPaymentMessage(PAYMENT);
		expect(m.type).toBe(X402_MESSAGE_TYPE.PAYMENT);
		expect(m.metadata?.[X402_METADATA_KEY].status).toBe(X402_STATUS.SUBMITTED);
	});

	it("build_receiptSuccess_setsCompletedMarker", () => {
		const m = buildReceiptMessage(RECEIPT);
		expect(m.metadata?.[X402_METADATA_KEY].status).toBe(X402_STATUS.COMPLETED);
	});

	it("build_receiptFailure_setsFailedMarker", () => {
		const m = buildReceiptMessage({
			success: false,
			transaction: "",
			network: "eip155:8453",
			payer: PAYER,
			errorReason: "insufficient_funds",
		});
		expect(m.metadata?.[X402_METADATA_KEY].status).toBe(X402_STATUS.FAILED);
	});

	it("build_emitMarkerFalse_omitsMetadata", () => {
		const m = buildPaymentRequiredMessage(QUOTE, { emitMarker: false });
		expect(m.metadata).toBeUndefined();
	});
});

describe("x402 marker never carries economic detail (adversarial)", () => {
	it("marker_builtFromRichQuote_hasOnlyStatusAndRail", () => {
		const m = buildPaymentRequiredMessage(QUOTE);
		const marker = m.metadata?.[X402_METADATA_KEY] as unknown as Record<
			string,
			unknown
		>;
		// Exactly two keys, nothing else can leak in.
		expect(Object.keys(marker).sort()).toEqual(["rail", "status"]);
		for (const banned of [
			"amount",
			"asset",
			"payTo",
			"address",
			"value",
			"accepts",
			"extra",
		]) {
			expect(marker).not.toHaveProperty(banned);
		}
	});

	it("marker_serialized_containsNoAmountAssetOrAddress", () => {
		// Build from a quote AND a signed payload — both carry economics.
		const serialized =
			JSON.stringify(buildPaymentRequiredMessage(QUOTE).metadata) +
			JSON.stringify(buildPaymentMessage(PAYMENT).metadata) +
			JSON.stringify(buildReceiptMessage(RECEIPT).metadata);
		for (const secret of [
			REQ.amount,
			EURC,
			PAYEE,
			PAYER,
			RECEIPT.transaction,
		]) {
			expect(serialized).not.toContain(secret);
		}
	});

	it("marker_standalone_isStatusAndRailOnly", () => {
		expect(x402Marker(X402_STATUS.COMPLETED)).toEqual({
			status: X402_STATUS.COMPLETED,
			rail: X402_RAIL,
		});
	});
});

describe("readX402Marker", () => {
	it("read_validMarker_returnsStatusAndRail", () => {
		const md = buildPaymentMessage(PAYMENT).metadata;
		expect(readX402Marker(md)).toEqual({
			status: X402_STATUS.SUBMITTED,
			rail: X402_RAIL,
		});
	});

	it("read_missingKey_returnsNull", () => {
		expect(readX402Marker({ other: 1 })).toBeNull();
		expect(readX402Marker(null)).toBeNull();
		expect(readX402Marker(undefined)).toBeNull();
	});

	it("read_unknownStatus_failsClosedToNull", () => {
		expect(
			readX402Marker({
				[X402_METADATA_KEY]: { status: "paid-lol", rail: "x402" },
			}),
		).toBeNull();
	});

	it("read_ignoresExtraKeys_returnsOnlyStatusAndRail", () => {
		const got = readX402Marker({
			[X402_METADATA_KEY]: {
				status: X402_STATUS.COMPLETED,
				rail: "x402",
				amount: "100000",
			},
		});
		expect(got).toEqual({ status: X402_STATUS.COMPLETED, rail: "x402" });
		expect(got).not.toHaveProperty("amount");
	});
});

describe("parseX402Payload", () => {
	it("parse_paymentRequired_returnsQuote", () => {
		const got = parseX402Payload(
			X402_MESSAGE_TYPE.PAYMENT_REQUIRED,
			JSON.stringify(QUOTE),
		);
		expect(got).toEqual(QUOTE);
	});

	it("parse_nonX402Type_throws", () => {
		expect(() => parseX402Payload("rine.v1.task_request", "{}")).toThrow(
			X402Error,
		);
	});

	it("parse_malformedJson_throws", () => {
		expect(() =>
			parseX402Payload(X402_MESSAGE_TYPE.PAYMENT, "not-json"),
		).toThrow(X402Error);
	});

	it("parse_receiptMissingSuccess_throws", () => {
		expect(() =>
			parseX402Payload(
				X402_MESSAGE_TYPE.RECEIPT,
				JSON.stringify({ transaction: "0x1" }),
			),
		).toThrow(X402Error);
	});

	it("isX402MessageType_discriminates", () => {
		expect(isX402MessageType(X402_MESSAGE_TYPE.RECEIPT)).toBe(true);
		expect(isX402MessageType("rine.v1.receipt")).toBe(false);
	});
});

describe("verbatim-object round-trip through the real E2EE envelope", () => {
	let dir: string;
	let senderKeys: AgentKeys;
	let recipientKeys: AgentKeys;

	beforeEach(() => {
		dir = makeTmpDir();
		senderKeys = generateAgentKeys();
		saveAgentKeys(dir, SENDER_ID, senderKeys);
		recipientKeys = generateAgentKeys();
		saveAgentKeys(dir, RECIPIENT_ID, recipientKeys);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	async function roundTrip(built: {
		type: string;
		payload: unknown;
	}): Promise<unknown> {
		const enc = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			built.payload,
		);
		const client = mockClientWithKeys(senderKeys);
		const dec = await decryptMessage(
			dir,
			RECIPIENT_ID,
			enc.encrypted_payload,
			client as never,
			SENDER_ID,
		);
		return parseX402Payload(built.type, dec.plaintext as string);
	}

	it("roundTrip_paymentRequired_preservesObjectByteForByte", async () => {
		const built = buildPaymentRequiredMessage(QUOTE);
		expect(await roundTrip(built)).toEqual(QUOTE);
	});

	it("roundTrip_payment_preservesSignedAuthorization", async () => {
		const built = buildPaymentMessage(PAYMENT);
		expect(await roundTrip(built)).toEqual(PAYMENT);
	});

	it("roundTrip_receipt_preservesSettlementResponse", async () => {
		const built = buildReceiptMessage(RECEIPT);
		expect(await roundTrip(built)).toEqual(RECEIPT);
	});

	it("roundTrip_preservesUnknownForwardCompatFields", async () => {
		const future: PaymentRequired = {
			...QUOTE,
			accepts: [{ ...QUOTE.accepts[0], futureField: { nested: [1, 2, 3] } }],
			someTopLevelExtension: "keep-me",
		} as PaymentRequired;
		const built = buildPaymentRequiredMessage(future);
		expect(await roundTrip(built)).toEqual(future);
	});
});
