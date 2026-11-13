import * as fs from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { classifyOperatorRow } from "../src/operator-classify.js";
import {
	HOURS_AGO,
	NOW,
	OperatorWorld,
	SELF_ID,
	instant,
} from "./operator-fixture.js";

describe("operator ledger", () => {
	let w: OperatorWorld;
	beforeEach(() => {
		w = new OperatorWorld();
	});
	afterEach(() => w.close());

	it("test_ledger_when_a_wake_saw_the_row_and_the_read_follows_then_both_are_operator_and_the_next_read_is_history", async () => {
		const wake = await w.consoleRow({}, { rendersText: false });
		const read = { ...wake, rendersText: true };
		expect(await classifyOperatorRow(w.context(), wake)).toEqual({
			senderClass: "operator",
			reason: "new",
		});
		expect(await classifyOperatorRow(w.context(), read)).toEqual({
			senderClass: "operator",
			reason: "redelivered",
		});
		expect(await classifyOperatorRow(w.context(), read)).toEqual({
			senderClass: "operator_history",
			reason: "already_rendered",
		});
	});

	it("test_ledger_when_the_same_row_is_delivered_twice_before_rendering_then_both_are_operator", async () => {
		const row = await w.consoleRow({}, { rendersText: false });
		await classifyOperatorRow(w.context(), row);
		expect((await classifyOperatorRow(w.context(), row)).senderClass).toBe(
			"operator",
		);
	});

	it("test_ledger_when_a_rendered_row_is_read_again_then_history", async () => {
		const row = await w.consoleRow();
		expect((await classifyOperatorRow(w.context(), row)).senderClass).toBe(
			"operator",
		);
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "operator_history",
			reason: "already_rendered",
		});
	});

	it("test_ledger_when_the_read_ciphertext_differs_from_the_woken_one_then_other_and_warns", async () => {
		const woken = await w.consoleRow(
			{ nonce: "n-sub" },
			{ rendersText: false },
		);
		const substituted = await w.consoleRow({ nonce: "n-sub" });
		await classifyOperatorRow(w.context(), woken);
		expect(await classifyOperatorRow(w.context(), substituted)).toEqual({
			senderClass: "other",
			reason: "substituted",
		});
		expect(w.warn).toHaveBeenCalledOnce();
	});

	it("test_ledger_when_the_file_is_lost_then_the_window_still_bounds_a_replay", async () => {
		const stale = await w.consoleRow({
			nonce: "n-old",
			issued_at: HOURS_AGO(30),
		});
		await classifyOperatorRow(w.context(), stale);
		for (const f of fs.readdirSync(w.dir))
			if (f.startsWith("operator_ledger_")) fs.rmSync(join(w.dir, f));
		expect(await classifyOperatorRow(w.context(), stale)).toEqual({
			senderClass: "operator_history",
			reason: "expired",
		});
	});

	it("test_ledger_when_the_file_is_torn_then_the_row_is_data_the_file_is_kept_and_it_warns", async () => {
		const path = join(w.dir, `operator_ledger_${SELF_ID}.json`);
		fs.writeFileSync(path, "{not json");
		const row = await w.consoleRow();
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "other",
			reason: "ledger_unavailable",
		});
		expect(w.warn).toHaveBeenCalledOnce();
		expect(w.warn.mock.calls[0]?.[0]).toContain(path);
		expect(fs.readFileSync(path, "utf8")).toBe("{not json");
	});

	it("test_ledger_when_an_entry_is_malformed_then_the_row_is_data_and_the_file_is_kept", async () => {
		const path = join(w.dir, `operator_ledger_${SELF_ID}.json`);
		const body = JSON.stringify({ v: 1, entries: { n: { row_id: 7 } } });
		fs.writeFileSync(path, body);
		const verdict = await classifyOperatorRow(
			w.context(),
			await w.consoleRow(),
		);
		expect(verdict.reason).toBe("ledger_unavailable");
		expect(fs.readFileSync(path, "utf8")).toBe(body);
	});

	it("test_ledger_when_the_nonce_is_proto_then_a_second_delivery_is_not_new", async () => {
		const row = await w.consoleRow({ nonce: "__proto__" });
		expect((await classifyOperatorRow(w.context(), row)).reason).toBe("new");
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "operator_history",
			reason: "already_rendered",
		});
	});

	it("test_ledger_when_the_agent_id_differs_only_in_case_then_both_share_one_ledger", async () => {
		const row = await w.consoleRow();
		const upper = w.context({ selfAgentId: SELF_ID.toUpperCase() });
		expect((await classifyOperatorRow(upper, row)).senderClass).toBe(
			"operator",
		);
		expect(await classifyOperatorRow(w.context(), row)).toEqual({
			senderClass: "operator_history",
			reason: "already_rendered",
		});
	});

	it("test_ledger_when_another_process_holds_the_lock_then_the_event_loop_keeps_running", async () => {
		const lock = join(w.dir, `operator_ledger_${SELF_ID}.json.lock`);
		const held = JSON.stringify({
			pid: 1,
			acquired_at: Date.now(),
			token: "x",
		});
		fs.writeFileSync(lock, `${held}\n`);
		let ticks = 0;
		const timer = setInterval(() => ticks++, 10);
		const verdict = classifyOperatorRow(w.context(), await w.consoleRow());
		await new Promise((resolve) => setTimeout(resolve, 200));
		fs.rmSync(lock);
		const result = await verdict;
		clearInterval(timer);
		expect(ticks).toBeGreaterThan(5);
		expect(result.senderClass).toBe("operator");
	});

	it("test_ledger_when_a_holder_is_six_seconds_old_then_its_lock_is_waited_for_not_taken", async () => {
		const lock = join(w.dir, `operator_ledger_${SELF_ID}.json.lock`);
		const held = JSON.stringify({
			pid: 1,
			acquired_at: Date.now() - 6_000,
			token: "slow",
		});
		fs.writeFileSync(lock, `${held}\n`);
		const verdict = classifyOperatorRow(w.context(), await w.consoleRow());
		await new Promise((resolve) => setTimeout(resolve, 200));
		expect(fs.readFileSync(lock, "utf8")).toBe(`${held}\n`);
		fs.rmSync(lock);
		expect((await verdict).senderClass).toBe("operator");
	});

	it("test_ledger_when_it_cannot_be_written_then_other_and_warns", async () => {
		const row = await w.consoleRow();
		const notADir = join(w.dir, "file");
		fs.writeFileSync(notADir, "");
		const verdict = await classifyOperatorRow(
			w.context({ configDir: notADir }),
			row,
		);
		expect(verdict).toEqual({
			senderClass: "other",
			reason: "ledger_unavailable",
		});
		expect(w.warn).toHaveBeenCalledOnce();
	});

	it("test_ledger_when_entries_pass_the_window_then_they_are_pruned_on_the_next_write", async () => {
		const old = await w.consoleRow({
			nonce: "n-prune",
			issued_at: HOURS_AGO(23),
		});
		await classifyOperatorRow(w.context(), old);
		const threeDays = 3 * 24 * 3_600_000;
		const later = await w.consoleRow({
			nonce: "n-later",
			issued_at: instant(threeDays - 60_000),
		});
		await classifyOperatorRow(w.context({ now: () => NOW + threeDays }), later);
		const file = JSON.parse(
			fs.readFileSync(join(w.dir, `operator_ledger_${SELF_ID}.json`), "utf8"),
		);
		expect(Object.keys(file.entries)).not.toContain("n-prune");
	});
});
