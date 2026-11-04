import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ackFailureNotice, createAckBatcher, markDeliveredAs } from "../src/ack-batcher.js";
import { ACTING_AGENT_HEADER } from "../src/actor.js";
import type { HttpClient } from "../src/http.js";
import { DeadlineError } from "../src/timing.js";

function setup(ack: (ids: string[]) => Promise<unknown> = async () => ({})) {
	const sent: string[][] = [];
	const errors: Array<[number, unknown]> = [];
	const batcher = createAckBatcher({
		ack: async (ids) => {
			sent.push(ids);
			return ack(ids);
		},
		onError: (count, err) => errors.push([count, err]),
	});
	return { batcher, sent, errors };
}

describe("createAckBatcher", () => {
	beforeEach(() => vi.useFakeTimers());
	afterEach(() => vi.useRealTimers());

	it("test_add_when_the_buffer_reaches_100_then_it_flushes_at_once", async () => {
		const { batcher, sent } = setup();
		for (let i = 0; i < 100; i++) batcher.add(`id-${i}`);
		await batcher.flush();

		expect(sent).toHaveLength(1);
		expect(sent[0]).toHaveLength(100);
	});

	it("test_add_when_250ms_pass_after_the_last_id_then_it_flushes", async () => {
		const { batcher, sent } = setup();
		batcher.add("a");
		await vi.advanceTimersByTimeAsync(200);
		batcher.add("b");
		await vi.advanceTimersByTimeAsync(200);
		expect(sent).toHaveLength(0);

		await vi.advanceTimersByTimeAsync(60);

		expect(sent).toEqual([["a", "b"]]);
	});

	it("test_flush_when_called_on_a_heartbeat_then_it_sends_what_is_buffered", async () => {
		const { batcher, sent } = setup();
		batcher.add("a");
		await batcher.flush();

		expect(sent).toEqual([["a"]]);
	});

	it("test_flush_when_nothing_is_buffered_then_it_makes_no_request", async () => {
		const { batcher, sent } = setup();
		await batcher.flush();

		expect(sent).toHaveLength(0);
	});

	it("test_flush_when_the_ack_fails_then_it_reports_the_count_once_and_does_not_throw", async () => {
		const failure = new Error("503");
		const { batcher, errors } = setup(async () => {
			throw failure;
		});
		batcher.add("a");
		batcher.add("b");
		await batcher.flush();

		expect(errors).toEqual([[2, failure]]);
	});

	it("test_flush_when_the_ack_is_aborted_then_nothing_is_reported", async () => {
		const abort = new Error("aborted");
		abort.name = "AbortError";
		const { batcher, errors } = setup(async () => {
			throw abort;
		});
		batcher.add("a");
		await batcher.flush();

		expect(errors).toEqual([]);
	});

	it("test_close_when_ids_are_buffered_then_it_sends_them_and_cancels_the_timer", async () => {
		const { batcher, sent } = setup();
		batcher.add("a");
		await batcher.close();
		await vi.advanceTimersByTimeAsync(1000);

		expect(sent).toEqual([["a"]]);
	});

	it("test_flush_when_a_batch_is_in_flight_then_it_waits_for_it", async () => {
		let release: () => void = () => {};
		const { batcher, sent } = setup(
			() => new Promise<void>((resolve) => (release = resolve)),
		);
		batcher.add("a");
		const done = vi.fn();
		void batcher.flush().then(done);
		await vi.advanceTimersByTimeAsync(0);
		expect(sent).toEqual([["a"]]);
		expect(done).not.toHaveBeenCalled();

		release();
		await vi.advanceTimersByTimeAsync(0);

		expect(done).toHaveBeenCalled();
	});

	it("test_flush_when_the_reporter_throws_then_later_flushes_still_send", async () => {
		const sent: string[][] = [];
		const batcher = createAckBatcher({
			ack: async (ids) => {
				sent.push(ids);
				if (sent.length === 1) throw new Error("503");
			},
			onError: () => {
				throw new Error("stderr closed");
			},
		});
		batcher.add("a");
		await batcher.flush();
		batcher.add("b");
		await batcher.flush();

		expect(sent).toEqual([["a"], ["b"]]);
	});

	it("test_flush_when_a_request_never_answers_then_it_reports_that_batch_and_sends_the_next", async () => {
		const sent: string[][] = [];
		const errors: Array<[number, unknown]> = [];
		const batcher = createAckBatcher({
			ack: (ids) => {
				sent.push(ids);
				return ids[0] === "a" ? new Promise<void>(() => {}) : Promise.resolve();
			},
			onError: (count, err) => errors.push([count, err]),
			requestTimeoutMs: 3000,
		});
		batcher.add("a");
		void batcher.flush();
		batcher.add("b");
		const second = batcher.flush();

		await vi.advanceTimersByTimeAsync(2900);
		expect(sent).toEqual([["a"]]);
		expect(errors).toEqual([]);

		await vi.advanceTimersByTimeAsync(200);
		await second;

		expect(sent).toEqual([["a"], ["b"]]);
		expect(errors).toHaveLength(1);
		expect(errors[0]?.[0]).toBe(1);
		expect(errors[0]?.[1]).toBeInstanceOf(DeadlineError);
	});

	it("test_close_when_the_final_request_stalls_then_it_gives_up_after_the_timeout", async () => {
		const batcher = createAckBatcher({
			ack: () => new Promise<void>(() => {}),
			onError: () => {},
			closeTimeoutMs: 3000,
		});
		batcher.add("a");
		const done = vi.fn();
		void batcher.close().then(done);
		await vi.advanceTimersByTimeAsync(2900);
		expect(done).not.toHaveBeenCalled();

		await vi.advanceTimersByTimeAsync(200);

		expect(done).toHaveBeenCalled();
	});
});

describe("markDeliveredAs", () => {
	it("test_markDeliveredAs_when_called_then_it_posts_the_ids_acting_as_the_agent", async () => {
		const markDelivered = vi.fn(async () => ({ marked: 2 }));
		const client = { markDelivered } as unknown as HttpClient;

		await markDeliveredAs(client, "agent-1", ["a", "b"]);

		expect(markDelivered).toHaveBeenCalledWith("agent-1", ["a", "b"], {
			[ACTING_AGENT_HEADER]: "agent-1",
		});
	});
});

describe("ackFailureNotice", () => {
	it("test_ackFailureNotice_when_given_an_error_then_the_cause_follows_the_fixed_sentence", () => {
		expect(ackFailureNotice(3, new Error("403 forbidden"))).toBe(
			"rine: could not mark 3 message(s) delivered; they may be shown again (403 forbidden)",
		);
	});
});
