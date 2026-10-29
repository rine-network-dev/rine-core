import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type ReadGap, ReadGapReason, gapToJson } from "../src/org-reader/gaps.js";
import { messageToJson, pageToJson, readMessage } from "../src/org-reader/page.js";
import {
	type Row,
	isParseFailure,
	ownAgentId,
	parseRow,
	pythonIsoformat,
} from "../src/org-reader/rows.js";
import { divergences } from "./org-reader-recorded.js";

const FIXTURES = join(import.meta.dirname, "fixtures", "org-reader-parity");
const MICROS_2026 = Date.UTC(2026, 9, 24, 12, 0, 10) * 1000;

function rawRow(over: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		id: "ID-Mixed-Case",
		created_at: "2026-10-24T12:00:10.000000Z",
		type: "rine.v1.dm",
		direction: "received",
		from: { agent_id: "agent-a", handle: "a@x", org_id: "org-a", own: false },
		to: { agent_id: "agent-b", handle: null, org_id: "org-b", own: true },
		group: null,
		conversation_id: "conv-c",
		encryption_version: "hpke-hybrid-v2",
		payload: { encrypted_payload: "AQID", self_encrypted_payload: "BAUG", key_gen: 2 },
		...over,
	};
}

function parsed(over: Record<string, unknown> = {}): Row {
	const result = parseRow(rawRow(over));
	if (isParseFailure(result)) throw new Error("expected a row");
	return result;
}

describe("pythonIsoformat", () => {
	it("renders_z_as_plus_zero_and_omits_zero_microseconds", () => {
		expect(pythonIsoformat(MICROS_2026, 0)).toBe("2026-10-24T12:00:10+00:00");
	});

	it("keeps_a_non_zero_microsecond_field_padded_to_six_digits", () => {
		expect(pythonIsoformat(MICROS_2026 + 178779, 0)).toBe("2026-10-24T12:00:10.178779+00:00");
		expect(pythonIsoformat(MICROS_2026 + 5, 0)).toBe("2026-10-24T12:00:10.000005+00:00");
	});

	it("renders_the_wall_clock_at_a_non_utc_offset", () => {
		expect(pythonIsoformat(MICROS_2026, 120)).toBe("2026-10-24T14:00:10+02:00");
		expect(pythonIsoformat(MICROS_2026, -330)).toBe("2026-10-24T06:30:10-05:30");
	});

	it("rolls_the_date_over_when_the_offset_crosses_midnight", () => {
		const late = Date.UTC(2026, 11, 31, 23, 30, 0) * 1000;
		expect(pythonIsoformat(late, 60)).toBe("2027-01-01T00:30:00+01:00");
	});
});

describe("parseRow", () => {
	it("keeps_ids_exactly_as_sent", () => {
		const row = parsed();
		expect(row.id).toBe("ID-Mixed-Case");
		expect(row.sender.agentId).toBe("agent-a");
		expect(row.recipient?.agentId).toBe("agent-b");
		expect(row.conversationId).toBe("conv-c");
	});

	it("decodes_both_ciphertexts_and_the_key_generation", () => {
		const row = parsed();
		expect([...row.ciphertext]).toEqual([1, 2, 3]);
		expect([...(row.selfCiphertext ?? [])]).toEqual([4, 5, 6]);
		expect(row.keyGen).toBe(2);
	});

	it("reads_the_time_at_microsecond_precision_and_keeps_the_original_string", () => {
		const a = parsed({ created_at: "2026-10-24T12:00:10.000001Z" });
		const b = parsed({ created_at: "2026-10-24T12:00:10.000002Z" });
		expect(b.createdAtMicros - a.createdAtMicros).toBe(1);
		expect(a.createdAt).toBe("2026-10-24T12:00:10.000001Z");
	});

	it("takes_the_offset_from_the_created_at_text", () => {
		const row = parsed({ created_at: "2026-10-24T14:00:10+02:00" });
		expect(row.offsetMinutes).toBe(120);
		expect(row.createdAtMicros).toBe(MICROS_2026);
		expect(parsed().offsetMinutes).toBe(0);
	});

	it("treats_absent_optionals_as_null", () => {
		const row = parsed({ to: null, payload: { encrypted_payload: "AQID" } });
		expect(row.recipient).toBeNull();
		expect(row.selfCiphertext).toBeNull();
		expect(row.keyGen).toBeNull();
		expect(row.groupId).toBeNull();
	});

	it("reads_the_group_id_and_handle", () => {
		const row = parsed({ group: { id: "group-a", handle: "g@x" } });
		expect([row.groupId, row.groupHandle]).toEqual(["group-a", "g@x"]);
		expect(parsed({ group: { id: "group-a" } }).groupHandle).toBeNull();
	});

	it("names_the_sender_as_the_own_agent_unless_only_the_recipient_is_ours", () => {
		expect(ownAgentId(parsed())).toBe("agent-b");
		expect(ownAgentId(parsed({ from: { agent_id: "agent-a", handle: null, org_id: "O", own: true } }))).toBe("agent-a");
		expect(ownAgentId(parsed({ to: null }))).toBe("agent-a");
	});

	const malformed: [string, Record<string, unknown>][] = [
		["id_missing", { id: undefined }],
		["conversation_id_missing", { conversation_id: undefined }],
		["created_at_missing", { created_at: undefined }],
		["created_at_a_number", { created_at: 1761307210 }],
		["created_at_not_a_time", { created_at: "yesterday" }],
		["created_at_without_offset", { created_at: "2026-10-24T12:00:10" }],
		["from_missing", { from: undefined }],
		["from_a_string", { from: "agent" }],
		["from_agent_id_missing", { from: { handle: null, org_id: "O", own: false } }],
		["from_org_id_missing", { from: { agent_id: "A", handle: null, own: false } }],
		["from_own_not_a_boolean", { from: { agent_id: "A", handle: null, org_id: "O", own: "yes" } }],
		["group_a_string", { group: "g" }],
		["group_id_missing", { group: { handle: "g" } }],
		["payload_missing", { payload: undefined }],
		["ciphertext_missing", { payload: {} }],
		["ciphertext_a_number", { payload: { encrypted_payload: 7 } }],
		["ciphertext_not_base64url", { payload: { encrypted_payload: "a b!" } }],
		["ciphertext_padding_in_the_middle", { payload: { encrypted_payload: "AQ=ID" } }],
		["ciphertext_impossible_length", { payload: { encrypted_payload: "AQIDB" } }],
		["own_copy_not_base64url", { payload: { encrypted_payload: "AQID", self_encrypted_payload: "***" } }],
		["key_gen_a_fraction", { payload: { encrypted_payload: "AQID", key_gen: 1.5 } }],
		["key_gen_negative", { payload: { encrypted_payload: "AQID", key_gen: -1 } }],
		["key_gen_beyond_safe_integer", { payload: { encrypted_payload: "AQID", key_gen: 2 ** 53 } }],
	];

	it.each(malformed)("returns_a_failure_carrying_the_id_when_%s", (_name, over) => {
		const result = parseRow(rawRow(over));
		expect(isParseFailure(result)).toBe(true);
		expect((result as { id: string | null }).id).toBe(over.id === undefined && "id" in over ? null : "ID-Mixed-Case");
	});

	it("decodes_a_padded_ciphertext_as_python_does", () => {
		const row = parseRow(rawRow({ payload: { encrypted_payload: "AQI=", self_encrypted_payload: "AQ==" } }));
		expect(isParseFailure(row)).toBe(false);
		const ok = row as { ciphertext: Uint8Array; selfCiphertext: Uint8Array | null };
		expect([...ok.ciphertext]).toEqual([1, 2]);
		expect([...(ok.selfCiphertext ?? [])]).toEqual([1]);
	});

	it("returns_a_failure_without_an_id_when_the_item_is_not_an_object", () => {
		for (const item of [null, "row", 4, [], undefined]) {
			expect(parseRow(item)).toEqual({ malformed: true, id: null });
		}
	});

	it("returns_a_failure_when_a_nested_object_is_an_array_or_a_key_gen_is_negative", () => {
		const id = "ID-Mixed-Case";
		expect(parseRow(rawRow({ from: [] }))).toEqual({ malformed: true, id });
		expect(parseRow(rawRow({ group: [] }))).toEqual({ malformed: true, id });
		expect(parseRow(rawRow({ payload: { encrypted_payload: "AQID", key_gen: -1 } }))).toEqual({ malformed: true, id });
	});

	it("keeps_a_retired_encryption_version_verbatim", () => {
		const row = parseRow(rawRow({ encryption_version: "hpke-hybrid-v1" }));
		expect(row).toMatchObject({ encryptionVersion: "hpke-hybrid-v1" });
	});

	it("reads_each_known_direction", () => {
		for (const direction of ["sent", "received", "internal"]) {
			expect(parseRow(rawRow({ direction }))).toMatchObject({ direction });
		}
	});

	it("treats_a_direction_outside_the_servers_closed_set_as_malformed", () => {
		expect(parseRow(rawRow({ direction: "sideways" }))).toEqual({ malformed: true, id: "ID-Mixed-Case" });
		expect(divergences.map((d) => d.id)).toContain("closed-direction-set");
	});

	it("returns_a_failure_without_an_id_when_the_id_is_not_a_string", () => {
		expect(parseRow(rawRow({ id: 12, type: undefined }))).toEqual({ malformed: true, id: null });
	});
});

interface RecordedRead {
	exchanges: { path: string; body: { items?: Record<string, unknown>[] } }[];
	page?: { items: Record<string, unknown>[]; findings: (ReadGap & { group_id: string })[]; next_cursor: string | null };
}

function fixtureFiles(): string[] {
	return ["org-reader", "org-reader-open", "hostile"].flatMap((dir) =>
		readdirSync(join(FIXTURES, dir))
			.filter((name) => name.endsWith(".json") && name !== "divergences.json")
			.map((name) => join(FIXTURES, dir, name)),
	);
}

describe("shapes recorded from the Python reader", () => {
	it("serialises_recorded_items_and_pages_as_python_did_leaving_only_the_malformed_row_fixtures_unopened", () => {
		let items = 0;
		const skipped: string[] = [];
		for (const file of fixtureFiles()) {
			const recorded = JSON.parse(readFileSync(file, "utf8")) as { reads: RecordedRead[] };
			for (const read of recorded.reads) {
				if (read.page === undefined) continue;
				const raw = new Map(
					read.exchanges.flatMap((e) => (e.path === "/org/activity" ? (e.body.items ?? []) : []))
						.filter((item): item is Record<string, unknown> => typeof item === "object" && item !== null)
						.map((item) => [item.id, item] as const),
				);
				const messages = [];
				for (const want of read.page.items) {
					const row = parseRow(raw.get(want.id));
					if (isParseFailure(row)) {
						skipped.push(`${file.split("/").slice(-2).join("/")}#${want.id}`);
						continue;
					}
					const message = readMessage(row, {
						epoch: want.epoch as number | null,
						text: want.text as string | null,
						verification: want.verification as never,
						equivocation: want.equivocation as boolean,
						gap: want.gap as ReadGap | null,
					});
					expect(messageToJson(message), file).toEqual(want);
					messages.push(message);
					items++;
				}
				if (messages.length === read.page.items.length) {
					const findings = read.page.findings.map(({ group_id: groupId, ...gap }) => ({ groupId, gap }));
					const page = { items: messages, findings, nextCursor: read.page.next_cursor };
					expect(pageToJson(page), file).toEqual(read.page);
				}
			}
		}
		expect(skipped.sort()).toEqual([
			"hostile/malformed-row-created-at-without-offset.json#5018228a-1d8d-5a14-a36e-b2a11e150e74",
			"hostile/malformed-row-key-gen-beyond-safe-integer.json#82091ccb-16b1-5322-a04b-6aeb98436e48",
		]);
		expect(items).toBeGreaterThan(100);
	});
});

interface RecordedCase {
	reads: (RecordedRead & { raised?: string })[];
}

/** The cases Python tolerates and the TypeScript reader refuses, per the `strict-row-fields` divergence. */
const STRICT_ROW_CASES = ["malformed-row-created-at-without-offset", "malformed-row-key-gen-beyond-safe-integer"];

function activityItems(read: RecordedRead): unknown[] {
	return read.exchanges.flatMap((e) =>
		e.path === "/org/activity" && Array.isArray(e.body?.items) ? e.body.items : [],
	);
}

describe("row parsing replayed over the recorded hostile cases", () => {
	const dirs = ["org-reader", "org-reader-open", "hostile"];
	const strictRowFields = divergences.some((d) => d.id === "strict-row-fields");

	it("refuses_a_feed_row_exactly_where_python_refused_it_or_a_divergence_says_otherwise", () => {
		const refused = new Set<string>();
		const expected = new Set<string>();
		for (const dir of dirs) {
			for (const file of fixtureFiles().filter((f) => f.includes(`/${dir}/`))) {
				const name = file.slice(file.lastIndexOf("/") + 1, -".json".length);
				const recorded = JSON.parse(readFileSync(file, "utf8")) as RecordedCase;
				for (const read of recorded.reads) {
					if (activityItems(read).some((item) => isParseFailure(parseRow(item)))) refused.add(name);
					const rowLevel = /^malformed-(row-|page-item-)/.test(name);
					if (rowLevel && read.raised !== undefined) expected.add(name);
				}
			}
		}
		const differences = [
			...[...refused].filter((n) => !expected.has(n)),
			...[...expected].filter((n) => !refused.has(n)),
		];
		expect(differences.sort()).toEqual(strictRowFields ? STRICT_ROW_CASES : []);
		expect(refused.size).toBeGreaterThan(25);
	});

	it("opens_every_row_of_every_non_malformed_case", () => {
		for (const file of fixtureFiles().filter((f) => !/\/malformed-/.test(f))) {
			const recorded = JSON.parse(readFileSync(file, "utf8")) as RecordedCase;
			for (const read of recorded.reads) {
				for (const item of activityItems(read)) expect(isParseFailure(parseRow(item)), file).toBe(false);
			}
		}
	});

	it("preserves_the_recorded_feed_order_and_uses_only_typed_gap_reasons", () => {
		const reasons = new Set<string>(Object.values(ReadGapReason));
		for (const file of fixtureFiles()) {
			const recorded = JSON.parse(readFileSync(file, "utf8")) as RecordedCase;
			for (const read of recorded.reads) {
				if (read.page === undefined) continue;
				const fed = activityItems(read).map((item) => (item as { id: string }).id);
				const shown = read.page.items.map((item) => item.id as string);
				expect(fed.filter((id) => shown.includes(id)), file).toEqual(shown);
				const found = read.page.findings.map(({ group_id: groupId, ...gap }) => {
					expect(typeof groupId, file).toBe("string");
					return gap;
				});
				for (const gap of [...found, ...read.page.items.flatMap((i) => (i.gap ? [i.gap as ReadGap] : []))]) {
					expect(reasons.has(gap.reason), file).toBe(true);
					expect(gapToJson(gap), file).toEqual(gap);
				}
			}
		}
	});
});
