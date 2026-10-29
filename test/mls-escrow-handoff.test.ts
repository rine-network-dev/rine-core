/**
 * The handoff: the epochs a background sweep lost, held in memory until the next
 * result for their group reports them. Noting accumulates in order per
 * (config dir, agent); taking clears what it returns, for one group.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { EscrowLoss } from "../src/mls-escrow-gap.js";
import {
	noteUnreported,
	takeUnreported,
} from "../src/mls-escrow-handoff.js";
import { resetProcessGates } from "../src/process-gate.js";

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const OTHER_AGENT = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const OTHER_GROUP = "d4e5f6a7-b8c9-0123-def0-234567890123";
const DIR = "/tmp/rine-handoff-a";
const OTHER_DIR = "/tmp/rine-handoff-b";

const gap = (epoch: number) => ({ epoch, reason: EscrowLoss.Refused });
const lost = (groupId: string, epoch: number) => ({ groupId, gap: gap(epoch) });

beforeEach(() => resetProcessGates());
afterEach(() => resetProcessGates());

describe("takeUnreported", () => {
	it("test_take_unreported_when_epochs_were_noted_then_they_come_back_in_order", () => {
		noteUnreported(DIR, AGENT, [lost(GROUP, 4)]);
		noteUnreported(DIR, AGENT, [lost(GROUP, 5), lost(GROUP, 6)]);

		expect(takeUnreported(DIR, AGENT, GROUP)).toEqual([gap(4), gap(5), gap(6)]);
	});

	it("test_take_unreported_when_it_has_returned_the_epochs_then_a_second_take_is_empty", () => {
		noteUnreported(DIR, AGENT, [lost(GROUP, 4)]);

		takeUnreported(DIR, AGENT, GROUP);

		expect(takeUnreported(DIR, AGENT, GROUP)).toEqual([]);
	});

	it("test_take_unreported_when_another_agent_or_dir_was_noted_then_this_one_is_empty", () => {
		noteUnreported(DIR, OTHER_AGENT, [lost(GROUP, 4)]);
		noteUnreported(OTHER_DIR, AGENT, [lost(GROUP, 5)]);

		expect(takeUnreported(DIR, AGENT, GROUP)).toEqual([]);
		expect(takeUnreported(DIR, OTHER_AGENT, GROUP)).toEqual([gap(4)]);
		expect(takeUnreported(OTHER_DIR, AGENT, GROUP)).toEqual([gap(5)]);
	});

	it("test_take_unreported_when_other_groups_were_noted_then_each_group_takes_only_its_own", () => {
		noteUnreported(DIR, AGENT, [lost(GROUP, 4), lost(OTHER_GROUP, 7), lost(GROUP, 5)]);

		expect(takeUnreported(DIR, AGENT, GROUP)).toEqual([gap(4), gap(5)]);
		expect(takeUnreported(DIR, AGENT, OTHER_GROUP)).toEqual([gap(7)]);
		expect(takeUnreported(DIR, AGENT, OTHER_GROUP)).toEqual([]);
	});

	it("test_take_unreported_when_nothing_was_noted_then_it_is_empty", () => {
		expect(takeUnreported(DIR, AGENT, GROUP)).toEqual([]);
	});
});
