import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { classifyOperatorRow } from "../src/operator-classify.js";
import {
	HOURS_AGO,
	MINUTES_AHEAD,
	OperatorWorld,
	STRANGER_ID,
} from "./operator-fixture.js";

describe("classifyOperatorRow: a row the server marked context_only", () => {
	let w: OperatorWorld;
	beforeEach(() => {
		w = new OperatorWorld();
	});
	afterEach(() => w.close());

	it.each(["sender_held", "recipient_held", "held", "a_value_a_newer_server_adds"])(
		"test_classify_when_context_only_is_%s_then_operator_history",
		async (value) => {
			const row = await w.consoleRow({}, { contextOnly: value });
			expect(await classifyOperatorRow(w.context(), row)).toEqual({
				senderClass: "operator_history",
				reason: "context_only",
			});
		},
	);

	it("test_classify_when_context_only_is_set_and_issued_at_is_fresh_then_still_context", async () => {
		const row = await w.consoleRow(
			{ issued_at: MINUTES_AHEAD(-1) },
			{ contextOnly: "sender_held" },
		);
		expect((await classifyOperatorRow(w.context(), row)).senderClass).toBe(
			"operator_history",
		);
	});

	it.each([null, undefined, ""])(
		"test_classify_when_context_only_is_%j_then_operator",
		async (value) => {
			const row = await w.consoleRow({}, { contextOnly: value });
			expect(await classifyOperatorRow(w.context(), row)).toEqual({
				senderClass: "operator",
				reason: "new",
			});
		},
	);

	it("test_classify_when_context_only_and_issued_over_24_hours_ago_then_context_not_expired", async () => {
		const row = await w.consoleRow(
			{ issued_at: HOURS_AGO(25) },
			{ contextOnly: "recipient_held" },
		);
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "operator_history",
			reason: "context_only",
		});
	});

	it("test_classify_when_context_only_but_a_stranger_sent_it_then_other", async () => {
		const row = await w.consoleRow(
			{},
			{ contextOnly: "held", fromAgentId: STRANGER_ID },
		);
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "other",
			reason: "wrong_sender",
		});
	});

	it("test_classify_when_a_context_only_statement_is_replayed_in_a_later_row_then_other", async () => {
		const held = await w.consoleRow(
			{ nonce: "n-held" },
			{ contextOnly: "sender_held" },
		);
		const replay = await w.consoleRow({ nonce: "n-held" }, { rowId: "row-2" });
		expect((await classifyOperatorRow(w.context(), held)).reason).toBe(
			"context_only",
		);
		expect(await classifyOperatorRow(w.context(), replay)).toEqual({
			senderClass: "other",
			reason: "replay",
		});
	});

	it("test_classify_when_a_future_dated_row_is_context_only_then_other", async () => {
		const row = await w.consoleRow(
			{ issued_at: MINUTES_AHEAD(6) },
			{ contextOnly: "held" },
		);
		expect((await classifyOperatorRow(w.context(), row)).reason).toBe("future");
	});
});
