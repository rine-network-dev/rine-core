import { describe, expect, it } from "vitest";
import {
	type ReadGap,
	ReadGapReason,
	escrowForged,
	escrowInvalid,
	forkUnmatched,
	findingKey,
	gapKey,
	gapOf,
	gapToJson,
	keysUnavailable,
	memberRejected,
	noDistribution,
	noEscrow,
	ratchetGap,
	unreadable,
} from "../src/org-reader/gaps.js";

describe("gapToJson", () => {
	it("emits_only_the_reason_when_no_field_is_set", () => {
		expect(gapToJson(gapOf(ReadGapReason.Duplicate))).toEqual({ reason: "Duplicate" });
		expect(gapToJson(unreadable())).toEqual({ reason: "Unreadable" });
		expect(gapToJson(keysUnavailable())).toEqual({ reason: "KeysUnavailable" });
	});

	it("emits_the_epoch_for_epoch_reasons", () => {
		expect(gapToJson(noEscrow(4))).toEqual({ reason: "NoEscrow", epoch: 4 });
		expect(gapToJson(escrowForged(0))).toEqual({ reason: "EscrowForged", epoch: 0 });
		expect(gapToJson(forkUnmatched(2))).toEqual({ reason: "ForkUnmatched", epoch: 2 });
		expect(gapToJson(memberRejected(9))).toEqual({ reason: "MemberRejected", epoch: 9 });
		expect(gapToJson(unreadable(3))).toEqual({ reason: "Unreadable", epoch: 3 });
		expect(gapToJson(keysUnavailable(5))).toEqual({ reason: "KeysUnavailable", epoch: 5 });
	});

	it("names_the_uploader_only_on_escrow_invalid", () => {
		expect(gapToJson(escrowInvalid(1, "agent-a"))).toEqual({
			reason: "EscrowInvalid",
			epoch: 1,
			uploader: "agent-a",
		});
	});

	it("carries_the_sender_and_a_set_index_for_a_ratchet_gap", () => {
		expect(gapToJson(ratchetGap("s", 7))).toEqual({ reason: "RatchetGap", sender: "s", index: 7 });
		expect(gapToJson(ratchetGap("s", 0))).toEqual({ reason: "RatchetGap", sender: "s", index: 0 });
		expect(gapToJson(ratchetGap("s", null))).toEqual({ reason: "RatchetGap", sender: "s" });
		expect(gapToJson(noDistribution("s"))).toEqual({ reason: "NoDistribution", sender: "s" });
	});

	it("spells_every_reason_as_the_wire_names_it", () => {
		expect(Object.values(ReadGapReason).sort()).toEqual(
			[
				"Duplicate",
				"EscrowForged",
				"EscrowInvalid",
				"ForkUnmatched",
				"KeyDistributionUnreadable",
				"KeyDistributionUnverified",
				"KeysUnavailable",
				"MemberRejected",
				"NoDistribution",
				"NoEscrow",
				"OutOfScope",
				"RatchetGap",
				"Unreadable",
			].sort(),
		);
	});
});

describe("gapKey", () => {
	it("gives_equal_gaps_one_key_whatever_order_their_fields_were_built_in", () => {
		const a: ReadGap = { reason: ReadGapReason.EscrowInvalid, epoch: 3, uploader: "u1" };
		const b: ReadGap = { uploader: "u1", epoch: 3, reason: ReadGapReason.EscrowInvalid };
		expect(gapKey(a)).toBe(gapKey(b));
	});

	it("tells_gaps_apart_that_differ_in_any_field", () => {
		const keys = [
			ratchetGap("s", null),
			ratchetGap("s", 0),
			ratchetGap("s", 1),
			ratchetGap("t", 1),
			escrowInvalid(3, "u1"),
			escrowInvalid(3, "u2"),
			escrowInvalid(4, "u1"),
			noEscrow(3),
		].map(gapKey);
		expect(new Set(keys).size).toBe(keys.length);
	});
});

describe("findingKey", () => {
	it("keeps_one_gap_in_two_groups_as_two_findings_and_equal_findings_as_one", () => {
		const gap = escrowInvalid(3, "u1");
		expect(findingKey({ groupId: "g1", gap })).toBe(findingKey({ groupId: "g1", gap: { ...gap } }));
		expect(findingKey({ groupId: "g1", gap })).not.toBe(findingKey({ groupId: "g2", gap }));
		expect(findingKey({ groupId: "g1", gap })).not.toBe(findingKey({ groupId: "g1", gap: noEscrow(3) }));
	});
});
