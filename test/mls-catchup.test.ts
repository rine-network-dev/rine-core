/**
 * The eager catch-up an ordinary successful group read runs, and the floor that
 * keeps it from being a sync per read.
 *
 * What is held here is the GATE, because that is the whole design decision: a
 * catch-up with nothing to do costs one GET, and a daemon polling an inbox would
 * otherwise issue one per row per poll. The sync itself is covered by
 * `mls-ops.test.ts` against a real native core; mocking it here is what lets the
 * gate be measured on its own, with time as the only variable.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const syncMlsGroupMock = vi.fn();

vi.mock("../src/mls-ops-sync.js", () => ({
	syncMlsGroup: (...args: unknown[]) => syncMlsGroupMock(...args),
}));

const { MLS_CATCHUP_MIN_INTERVAL_MS, catchUpMlsGroup, resetMlsCatchUpGate } =
	await import("../src/mls-catchup.js");

const DIR = "/tmp/rine-catchup";
const AGENT = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const OTHER_AGENT = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
const GROUP = "dddddddd-4444-4444-8444-dddddddddddd";
const OTHER_GROUP = "eeeeeeee-5555-4555-8555-eeeeeeeeeeee";
const client = {} as never;

beforeEach(() => {
	resetMlsCatchUpGate();
	syncMlsGroupMock.mockReset();
	syncMlsGroupMock.mockResolvedValue({
		epoch: 7,
		processed: 0,
		evicted: false,
	});
	vi.useFakeTimers();
});
afterEach(() => vi.useRealTimers());

describe("catchUpMlsGroup", () => {
	it("test_first_read_when_nothing_cached_then_catches_up", async () => {
		// What it just did, which the read it runs behind now carries.
		expect(await catchUpMlsGroup(DIR, AGENT, GROUP, client)).toEqual({
			epoch: 7,
			processed: 0,
			evicted: false,
		});
		expect(syncMlsGroupMock).toHaveBeenCalledTimes(1);
	});

	it("test_second_read_when_inside_the_floor_then_skips", async () => {
		await catchUpMlsGroup(DIR, AGENT, GROUP, client);
		vi.advanceTimersByTime(MLS_CATCHUP_MIN_INTERVAL_MS - 1);

		// A twenty-row inbox is twenty reads; without this it would be twenty
		// GETs against one group, per poll.
		// Declined, and saying nothing: no report is not the claim "you are
		// current" — it is the absence of one.
		expect(await catchUpMlsGroup(DIR, AGENT, GROUP, client)).toBeNull();
		expect(syncMlsGroupMock).toHaveBeenCalledTimes(1);
	});

	it("test_read_when_past_the_floor_then_catches_up_again", async () => {
		await catchUpMlsGroup(DIR, AGENT, GROUP, client);
		vi.advanceTimersByTime(MLS_CATCHUP_MIN_INTERVAL_MS);

		expect(await catchUpMlsGroup(DIR, AGENT, GROUP, client)).not.toBeNull();
		expect(syncMlsGroupMock).toHaveBeenCalledTimes(2);
	});

	it("test_floor_when_another_group_or_agent_reads_then_does_not_apply", async () => {
		await catchUpMlsGroup(DIR, AGENT, GROUP, client);

		// The gate is per (agent, group): one busy group must not silence a
		// different one, or a second agent in the same config dir.
		expect(
			await catchUpMlsGroup(DIR, AGENT, OTHER_GROUP, client),
		).not.toBeNull();
		expect(
			await catchUpMlsGroup(DIR, OTHER_AGENT, GROUP, client),
		).not.toBeNull();
		expect(syncMlsGroupMock).toHaveBeenCalledTimes(3);
	});

	it("test_catchup_when_the_sync_fails_then_does_not_throw", async () => {
		syncMlsGroupMock.mockRejectedValue(new Error("the server is down"));

		// It runs behind a read that already succeeded, so a failure here must
		// leave that read exactly where it was.
		// It ran and has nothing to report, which is what a declined catch-up
		// says too: neither moved this agent's state, and the read is not the
		// place to explain a failure it survived. That it RAN is observable in
		// the call the sync issued.
		await expect(catchUpMlsGroup(DIR, AGENT, GROUP, client)).resolves.toBeNull();
		expect(syncMlsGroupMock).toHaveBeenCalledTimes(1);
	});

	it("test_catchup_when_it_runs_then_passes_the_acting_headers_through", async () => {
		await catchUpMlsGroup(DIR, AGENT, GROUP, client, { "X-Rine-Agent": AGENT });

		expect(syncMlsGroupMock).toHaveBeenCalledWith(DIR, AGENT, GROUP, client, {
			"X-Rine-Agent": AGENT,
		});
	});
});
