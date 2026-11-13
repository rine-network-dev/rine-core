import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { classifyOperatorRow } from "../src/operator-classify.js";
import {
	OPERATOR_FUTURE_SKEW_MS,
	OPERATOR_WINDOW_MS,
} from "../src/operator-statement.js";
import {
	HOURS_AGO,
	MINUTES_AGO,
	MINUTES_AHEAD,
	OperatorWorld,
	STRANGER_ID,
	instant,
} from "./operator-fixture.js";

describe("classifyOperatorRow: each of the six conditions failing alone", () => {
	let w: OperatorWorld;
	beforeEach(() => {
		w = new OperatorWorld();
	});
	afterEach(() => w.close());

	it("test_classify_when_every_condition_holds_then_operator", async () => {
		const verdict = await classifyOperatorRow(
			w.context(),
			await w.consoleRow(),
		);
		expect(verdict).toEqual({ senderClass: "operator", reason: "new" });
		expect(w.warn).not.toHaveBeenCalled();
	});

	it("test_classify_when_the_key_that_verified_is_the_pinned_one_then_it_came_from_the_real_decrypt", async () => {
		const row = await w.consoleRow();
		expect(row.result?.verifyingKey).toEqual(w.seat.derived.ed25519.publicKey);
	});

	it("test_classify_when_not_a_1to1_envelope_then_other", async () => {
		const row = await w.consoleRow({}, { encryptionVersion: "sender-key-v1" });
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "other",
			reason: "not_direct",
		});
	});

	it("test_classify_when_the_signature_did_not_verify_then_other", async () => {
		const row = await w.consoleRow();
		const unverified = {
			...row,
			result: {
				...row.result!,
				verified: false,
				verificationStatus: "unverifiable" as const,
			},
		};
		expect(await classifyOperatorRow(w.context(), unverified)).toEqual({
			senderClass: "other",
			reason: "not_verified",
		});
	});

	it("test_classify_when_the_row_was_never_opened_then_other", async () => {
		const row = await w.consoleRow({}, { result: null });
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "other",
			reason: "not_verified",
		});
	});

	it("test_classify_when_the_row_sender_is_not_the_pinned_seat_then_other", async () => {
		const row = await w.consoleRow({}, { fromAgentId: STRANGER_ID });
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "other",
			reason: "wrong_sender",
		});
	});

	it("test_classify_when_the_verifying_key_is_not_the_pinned_key_then_other", async () => {
		const ctx = w.context({
			pin: { agentId: w.seat.id, signingKey: w.pinFor(w.stranger).signingKey },
		});
		expect(await classifyOperatorRow(ctx, await w.consoleRow())).toEqual({
			senderClass: "other",
			reason: "wrong_key",
		});
	});

	it("test_classify_when_a_stranger_signed_but_the_row_claims_the_seat_then_other", async () => {
		const row = await w.consoleRow({}, { fromAgentId: w.seat.id }, w.stranger);
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "other",
			reason: "wrong_key",
		});
	});

	it("test_classify_when_the_verifying_key_is_absent_then_other", async () => {
		const row = await w.consoleRow();
		const keyless = { ...row, result: { ...row.result!, verifyingKey: null } };
		expect(await classifyOperatorRow(w.context(), keyless)).toEqual({
			senderClass: "other",
			reason: "wrong_key",
		});
	});

	it("test_classify_when_the_payload_has_no_statement_then_other", async () => {
		const row = await w.row({ text: "pause the crawl" });
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "other",
			reason: "no_statement",
		});
	});

	it("test_classify_when_the_signed_purpose_is_not_a_command_then_other", async () => {
		const row = await w.consoleRow({ purpose: "operator.invite" });
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "other",
			reason: "wrong_purpose",
		});
	});

	it("test_classify_when_the_statement_names_another_agent_then_other", async () => {
		const row = await w.consoleRow({ agent: STRANGER_ID });
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "other",
			reason: "wrong_recipient",
		});
	});

	it("test_classify_when_issued_more_than_five_minutes_ahead_then_other", async () => {
		const row = await w.consoleRow({ issued_at: MINUTES_AHEAD(6) });
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "other",
			reason: "future",
		});
	});

	it("test_classify_when_issued_four_minutes_ahead_then_operator", async () => {
		const row = await w.consoleRow({ issued_at: MINUTES_AHEAD(4) });
		expect((await classifyOperatorRow(w.context(), row)).senderClass).toBe(
			"operator",
		);
	});

	it("test_classify_when_issued_more_than_24_hours_ago_then_operator_history", async () => {
		const row = await w.consoleRow({ issued_at: HOURS_AGO(25) });
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "operator_history",
			reason: "expired",
		});
	});

	it("test_classify_when_issued_23_hours_ago_then_operator", async () => {
		const row = await w.consoleRow({ issued_at: HOURS_AGO(23) });
		expect((await classifyOperatorRow(w.context(), row)).senderClass).toBe(
			"operator",
		);
	});

	it("test_classify_when_issued_exactly_at_the_future_skew_then_operator", async () => {
		const row = await w.consoleRow({
			issued_at: instant(OPERATOR_FUTURE_SKEW_MS),
		});
		expect((await classifyOperatorRow(w.context(), row)).reason).toBe("new");
	});

	it("test_classify_when_issued_one_millisecond_past_the_future_skew_then_other", async () => {
		const row = await w.consoleRow({
			issued_at: instant(OPERATOR_FUTURE_SKEW_MS + 1),
		});
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "other",
			reason: "future",
		});
	});

	it("test_classify_when_issued_exactly_at_the_window_then_operator", async () => {
		const row = await w.consoleRow({
			issued_at: instant(-OPERATOR_WINDOW_MS),
		});
		expect((await classifyOperatorRow(w.context(), row)).reason).toBe("new");
	});

	it("test_classify_when_issued_one_millisecond_past_the_window_then_operator_history", async () => {
		const row = await w.consoleRow({
			issued_at: instant(-OPERATOR_WINDOW_MS - 1),
		});
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "operator_history",
			reason: "expired",
		});
	});

	it("test_classify_when_the_nonce_arrives_on_a_different_row_then_other_and_warns", async () => {
		const first = await w.consoleRow({ nonce: "n-replay" });
		const replay = await w.consoleRow(
			{ nonce: "n-replay" },
			{ rowId: "row-2" },
		);
		expect((await classifyOperatorRow(w.context(), first)).senderClass).toBe(
			"operator",
		);
		expect(await classifyOperatorRow(w.context(), replay)).toEqual({
			senderClass: "other",
			reason: "replay",
		});
		expect(w.warn).toHaveBeenCalledOnce();
	});

	it("test_classify_when_no_pin_is_configured_then_other", async () => {
		const row = await w.consoleRow();
		expect(await classifyOperatorRow(w.context({ pin: null }), row)).toEqual({
			senderClass: "other",
			reason: "no_pin",
		});
	});

	it("test_classify_when_the_pin_names_no_agent_then_other_even_for_an_unsigned_sender", async () => {
		const row = await w.consoleRow({}, { fromAgentId: "" });
		const ctx = w.context({
			pin: { agentId: "", signingKey: w.pinFor(w.seat).signingKey },
		});
		expect((await classifyOperatorRow(ctx, row)).senderClass).toBe("other");
	});

	it("test_classify_when_the_agent_is_not_the_statement_recipient_then_other", async () => {
		const row = await w.consoleRow();
		expect(
			(await classifyOperatorRow(w.context({ selfAgentId: STRANGER_ID }), row))
				.reason,
		).toBe("wrong_recipient");
	});
});
