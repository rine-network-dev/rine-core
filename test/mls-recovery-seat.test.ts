/**
 * What a group sync says about the agent's own leaf, and where it says it.
 *
 * The seat sentence follows the recovery's head and precedes the key-package
 * line, so the head stays what two matrix drivers anchor on.
 */
import { describe, expect, it } from "vitest";
import { describeMlsRecovery } from "../src/mls-recovery-format.js";
import type { MlsGroupRecovery } from "../src/group-recovery-seat.js";
import { emptyReport } from "../src/mls-escrow-report.js";
import { SeatUpdateStatus } from "../src/mls-seat-update.js";

const GROUP = "11111111-0000-4000-8000-0000000000a1";

const replay: MlsGroupRecovery = {
	regime: "mls",
	rung: "replay",
	fromEpoch: 1,
	epoch: 2,
	behind: 1,
	processed: 1,
	evicted: false,
	escrow: emptyReport(),
};

describe("describeMlsRecovery with a seat", () => {
	it("test_describe_when_the_leaf_moved_then_the_sentence_follows_the_head", () => {
		const said = describeMlsRecovery("#ops", {
			...replay,
			seat: { group_id: GROUP, status: SeatUpdateStatus.Updated, epoch: 2 },
		});

		const [head, ...rest] = said.split("\n");
		expect(head).toMatch(/^Replayed 1 commit\(s\) for group #ops/);
		expect(rest).toEqual(["Its leaf now carries the agent's current key (epoch 2)."]);
	});

	it("test_describe_when_a_seat_and_a_top_up_meet_then_the_seat_comes_first", () => {
		const lines = describeMlsRecovery("#ops", {
			...replay,
			seat: { group_id: GROUP, status: SeatUpdateStatus.Updated, epoch: 2 },
			keyPackages: { outcome: "failed", published: 0, detail: "down" },
		}).split("\n");

		expect(lines[1]).toBe("Its leaf now carries the agent's current key (epoch 2).");
		expect(lines[2]).toContain("down");
	});

	it("test_describe_when_the_leaf_is_current_then_nothing_is_added", () => {
		const said = describeMlsRecovery("#ops", {
			...replay,
			seat: { group_id: GROUP, status: SeatUpdateStatus.Current },
		});

		expect(said).not.toContain("\n");
	});

	it("test_describe_when_no_self_update_ran_then_the_text_is_unchanged", () => {
		expect(describeMlsRecovery("#ops", replay)).toBe(
			describeMlsRecovery("#ops", { ...replay, seat: undefined }),
		);
	});
});
