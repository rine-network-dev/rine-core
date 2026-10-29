import { describe, expect, it } from "vitest";
import { ReadGapReason } from "../src/org-reader/gaps.js";
import { markDuplicates } from "../src/org-reader/duplicates.js";
import { type ReadMessage, readMessage } from "../src/org-reader/page.js";
import { type Row, isParseFailure, parseRow } from "../src/org-reader/rows.js";

function makeRow(id: string, createdAt: string): Row {
	const result = parseRow({
		id,
		created_at: createdAt,
		type: "rine.v1.group_message",
		direction: "received",
		from: { agent_id: "agent-a", handle: null, org_id: "org-a", own: false },
		to: null,
		group: { id: "group-a", handle: null },
		conversation_id: "conv-a",
		encryption_version: "mls-v1",
		payload: { encrypted_payload: "AQID" },
	});
	if (isParseFailure(result)) throw new Error("expected a row");
	return result;
}

function message(
	id: string,
	createdAt: string,
	slot: string | null,
	envelope: number[] | null,
): ReadMessage {
	return readMessage(makeRow(id, createdAt), {
		slot,
		envelope: envelope === null ? null : Uint8Array.from(envelope),
		epoch: 3,
		text: `text-${id}`,
	});
}

describe("markDuplicates", () => {
	it("leaves_messages_with_distinct_or_no_slots_untouched", () => {
		const input = [
			message("a", "2026-10-24T12:00:00Z", "s1", [1]),
			message("b", "2026-10-24T12:00:01Z", null, null),
		];
		expect(markDuplicates(input)).toEqual(input);
	});

	it("keeps_the_first_stored_row_and_marks_later_ones_duplicate_in_input_order", () => {
		const later = message("late", "2026-10-24T12:00:05Z", "s1", [1]);
		const earlier = message("early", "2026-10-24T12:00:01Z", "s1", [1]);
		const out = markDuplicates([later, earlier]);
		expect(out[1]).toEqual(earlier);
		expect(out[0]?.gap).toEqual({ reason: ReadGapReason.Duplicate });
		expect(out[0]?.text).toBeNull();
		expect(out[0]?.epoch).toBe(3);
		expect(out[0]?.equivocation).toBe(false);
	});

	it("breaks_a_timestamp_tie_by_row_id", () => {
		const out = markDuplicates([
			message("b", "2026-10-24T12:00:00Z", "s1", [1]),
			message("a", "2026-10-24T12:00:00Z", "s1", [1]),
		]);
		expect(out[1]?.gap).toBeNull();
		expect(out[0]?.gap?.reason).toBe(ReadGapReason.Duplicate);
	});

	it("orders_by_microseconds_not_by_input_position", () => {
		const out = markDuplicates([
			message("x", "2026-10-24T12:00:00.000002Z", "s1", [1]),
			message("y", "2026-10-24T12:00:00.000001Z", "s1", [1]),
		]);
		expect(out[1]?.gap).toBeNull();
		expect(out[0]?.gap?.reason).toBe(ReadGapReason.Duplicate);
	});

	it("flags_equivocation_on_both_rows_when_the_envelope_bytes_differ", () => {
		const out = markDuplicates([
			message("a", "2026-10-24T12:00:00Z", "s1", [1, 2]),
			message("b", "2026-10-24T12:00:01Z", "s1", [1, 3]),
		]);
		expect(out[0]?.equivocation).toBe(true);
		expect(out[0]?.text).toBe("text-a");
		expect(out[1]?.equivocation).toBe(true);
		expect(out[1]?.gap?.reason).toBe(ReadGapReason.Duplicate);
	});

	it("compares_envelopes_by_value_not_by_reference", () => {
		const out = markDuplicates([
			message("a", "2026-10-24T12:00:00Z", "s1", [9, 9]),
			message("b", "2026-10-24T12:00:01Z", "s1", [9, 9]),
		]);
		expect(out[0]?.equivocation).toBe(false);
		expect(out[1]?.equivocation).toBe(false);
	});

	it("treats_a_missing_envelope_against_a_present_one_as_equivocation", () => {
		const out = markDuplicates([
			message("a", "2026-10-24T12:00:00Z", "s1", null),
			message("b", "2026-10-24T12:00:01Z", "s1", [1]),
		]);
		expect(out[0]?.equivocation).toBe(true);
		expect(out[1]?.equivocation).toBe(true);
	});
});
