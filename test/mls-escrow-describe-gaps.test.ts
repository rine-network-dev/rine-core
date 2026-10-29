/**
 * The one-line description of the epochs a result reports as having no escrow:
 * a surface prints it beside the count so a lost epoch is named, not only
 * counted, and the reasons stay in the order the result reported them.
 */
import { describe, expect, it } from "vitest";
import { EscrowLoss, type DrainGap } from "../src/mls-escrow-gap.js";
import { describeEscrowGaps } from "../src/mls-escrow-report.js";

describe("describeEscrowGaps", () => {
	it("test_describe_escrow_gaps_when_there_are_none_then_the_line_is_empty", () => {
		expect(describeEscrowGaps([])).toBe("");
	});

	it("test_describe_escrow_gaps_when_one_epoch_was_refused_then_it_names_the_epoch_and_reason", () => {
		const gaps: DrainGap[] = [{ epoch: 4, reason: EscrowLoss.Refused }];

		expect(describeEscrowGaps(gaps)).toBe("4 (refused)");
	});

	it("test_describe_escrow_gaps_when_several_epochs_were_lost_then_they_are_listed_in_order_with_each_reason", () => {
		const gaps: DrainGap[] = [
			{ epoch: 4, reason: EscrowLoss.Refused },
			{ epoch: 5, reason: EscrowLoss.AgentRevoked },
		];

		expect(describeEscrowGaps(gaps)).toBe("4 (refused), 5 (agent_revoked)");
	});
});
