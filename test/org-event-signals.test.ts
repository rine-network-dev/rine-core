import { describe, expect, it } from "vitest";
import { signalClass } from "../src/org-event-signals.js";
import fixture from "./fixtures/governance-signals.json" with { type: "json" };

describe("signalClass", () => {
	it.each(
		fixture.cases.map((c) => [c.kind, JSON.stringify(c.detail), c] as const),
	)(
		"test_signal_class_when_%s_with_%s_then_the_server_fixture_class",
		(_kind, _detail, c) => {
			expect(signalClass(c.kind, c.detail)).toBe(c.class);
		},
	);

	it("test_signal_class_when_an_exit_is_added_to_an_agent_with_history_then_a_record", () => {
		for (const kind of fixture.exit_alert_kinds) {
			expect(signalClass(kind, { [fixture.history_field]: true })).toBe(
				"record",
			);
			expect(signalClass(kind, {})).toBe("record");
		}
	});

	it("test_signal_class_when_our_agents_keep_posting_then_a_record", () => {
		const kind = "group.postable_changed";
		expect(signalClass(kind, { [fixture.postable_field]: true })).toBe("record");
		expect(signalClass(kind, { [fixture.postable_field]: false })).toBe("alert");
	});

	it("test_signal_class_when_the_fixture_lists_kinds_then_each_has_its_class", () => {
		for (const kind of fixture.alert_kinds)
			expect(signalClass(kind, {})).toBe("alert");
		for (const kind of fixture.summary_kinds)
			expect(signalClass(kind, {})).toBe("summary");
	});
});
