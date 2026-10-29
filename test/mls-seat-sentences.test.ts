/**
 * The sentence a group sync appends about the agent's own leaf.
 *
 * These strings are pinned byte for byte: the Python SDK prints the same ones,
 * and a harness greps them.
 */
import { describe, expect, it } from "vitest";
import { MLS_EVICTED_BY_COMMIT, seatUpdateLine } from "../src/mls-seat-sentences.js";
import {
	SeatDeferReason,
	SeatFailReason,
	type SeatUpdate,
	SeatUpdateStatus,
} from "../src/mls-seat-update.js";

const GROUP = "11111111-0000-4000-8000-0000000000a1";

const seat = (fields: Partial<SeatUpdate> & Pick<SeatUpdate, "status">): SeatUpdate => ({
	group_id: GROUP,
	...fields,
});

describe("seatUpdateLine", () => {
	it("test_seat_line_when_there_is_nothing_to_say_then_it_is_empty", () => {
		expect(seatUpdateLine(undefined)).toBe("");
		expect(seatUpdateLine(seat({ status: SeatUpdateStatus.Current, epoch: 4 }))).toBe("");
	});

	it("test_seat_line_when_the_leaf_moved_then_it_names_the_epoch", () => {
		expect(seatUpdateLine(seat({ status: SeatUpdateStatus.Updated, epoch: 7 }))).toBe(
			"Its leaf now carries the agent's current key (epoch 7).",
		);
	});

	it.each([
		[
			SeatDeferReason.EpochRace,
			undefined,
			"Its leaf still carries an earlier key: another commit landed first; the next sync retries.",
		],
		[
			SeatDeferReason.Unreachable,
			undefined,
			"Its leaf still carries an earlier key: the update could not be posted; the next sync retries.",
		],
		[
			SeatDeferReason.AwaitingAck,
			9,
			"Its leaf moves to the agent's current key once a member acknowledges the update (epoch 9); until then it carries the earlier key.",
		],
		[
			SeatDeferReason.RolledBack,
			undefined,
			"Its leaf still carries an earlier key: the group rolled the update back before a member acknowledged it; the next sync retries.",
		],
	])("test_seat_line_when_deferred_for_%s_then_the_sentence_is_pinned", (reason, epoch, line) => {
		expect(seatUpdateLine(seat({ status: SeatUpdateStatus.Deferred, reason, epoch }))).toBe(line);
	});

	it.each([
		[SeatFailReason.Evicted, undefined, MLS_EVICTED_BY_COMMIT],
		[
			SeatFailReason.SeatUnhealable,
			"anything",
			"Its leaf carries a key this agent cannot sign for; a member must remove the agent and invite it again.",
		],
		[
			SeatFailReason.KeyNotCurrent,
			undefined,
			"Its leaf was not moved: this device holds an earlier key generation than the agent's current one.",
		],
		[
			SeatFailReason.Refused,
			"the core said no",
			"Its leaf was not moved: the update was refused: the core said no",
		],
	])("test_seat_line_when_failed_for_%s_then_the_sentence_is_pinned", (reason, detail, line) => {
		expect(seatUpdateLine(seat({ status: SeatUpdateStatus.Failed, reason, detail }))).toBe(line);
	});

	it("test_seat_line_when_a_refusal_has_no_detail_then_it_says_so", () => {
		expect(
			seatUpdateLine(seat({ status: SeatUpdateStatus.Failed, reason: SeatFailReason.Refused })),
		).toBe("Its leaf was not moved: the update was refused: no reason was reported");
	});

	it("test_seat_line_when_a_status_and_reason_disagree_then_it_is_empty", () => {
		expect(
			seatUpdateLine(seat({ status: SeatUpdateStatus.Deferred, reason: SeatFailReason.Evicted })),
		).toBe("");
		expect(
			seatUpdateLine(seat({ status: SeatUpdateStatus.Failed, reason: SeatDeferReason.EpochRace })),
		).toBe("");
	});

	it("test_evicted_sentence_when_read_then_it_is_the_one_sentence_the_recovery_prints", () => {
		expect(MLS_EVICTED_BY_COMMIT).toBe(
			"This agent was removed from the group by a commit it just replayed: messages that already arrived still open, and nothing committed after the Remove ever will.",
		);
	});
});
