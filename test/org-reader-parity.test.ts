import { describe, expect, it } from "vitest";
import { ORG_READ_MAX_CHAIN_STEPS } from "../src/org-reader/sender-key.js";
import {
	divergences,
	type RecordedCase,
	type RecordedRead,
	type Replayed,
	recordedCases,
	replayRead,
} from "./org-reader-recorded.js";

const ruled = (id: string) => divergences.find((entry) => entry.id === id);

/** What a replay came to, in the words of the gap and verification vocabulary. */
function outcome(replayed: Replayed): string {
	if ("threw" in replayed) return `threw ${replayed.threw.constructor.name}`;
	const { items, findings } = replayed.page as {
		items: { gap: { reason: string } | null; verification: string | null }[];
		findings: { reason: string }[];
	};
	const shown = items.map((item) => item.gap?.reason ?? item.verification ?? "verified");
	const found = findings.map((finding) => `finding ${finding.reason}`);
	return [...(shown.length > 0 ? shown : ["no rows"]), ...found].join(", ");
}

/** The group each finding on a replayed page names, in order; empty when the replay threw. */
function findingGroups(replayed: Replayed): unknown[] {
	if ("threw" in replayed) return [];
	const { findings } = replayed.page as { findings: { group_id?: unknown }[] };
	return findings.map((finding) => finding.group_id);
}

const FORGED = "EscrowForged, finding EscrowForged";
const UNREADABLE = "Unreadable";

/**
 * The hostile cases where the TypeScript reader answers differently from Python on purpose: the case,
 * the ruling in `divergences.json` that allows it, and what the TypeScript reader returns. Python
 * raised on most of these, so they are compared by category and never by exception class.
 */
const DIVERGENT: Record<string, readonly [ruling: string, outcome: string]> = {
	"malformed-escrow-branch-missing": ["malformed-escrow-row", FORGED],
	"malformed-escrow-created-at-missing": ["malformed-escrow-row", FORGED],
	"malformed-escrow-created-at-without-offset": ["strict-row-fields", FORGED],
	"malformed-escrow-epoch-missing": ["malformed-escrow-row", "NoEscrow"],
	"malformed-escrow-fp-missing": ["malformed-escrow-row", FORGED],
	"malformed-escrow-sealed-missing": ["malformed-escrow-row", FORGED],
	"malformed-escrow-signature-missing": ["malformed-escrow-row", FORGED],
	"malformed-escrow-uploader-key-gen-beyond-safe-integer": ["strict-row-fields", FORGED],
	"malformed-escrow-uploader-key-gen-fraction": ["strict-row-fields", FORGED],
	"malformed-escrow-uploader-key-gen-missing": ["malformed-escrow-row", FORGED],
	"malformed-escrow-uploader-missing": ["malformed-escrow-row", FORGED],
	"malformed-page-a-list": ["malformed-page-envelope", "threw MalformedPageError"],
	"malformed-page-escrow-row-null": ["malformed-escrow-row", "NoEscrow"],
	"malformed-page-escrow-rows-null": ["malformed-page-envelope", "threw MalformedPageError"],
	"malformed-page-escrow-without-rows": ["malformed-page-envelope", "threw MalformedPageError"],
	"malformed-page-item-a-string": ["malformed-activity-row", "no rows"],
	"malformed-page-item-null": ["malformed-activity-row", "no rows"],
	"malformed-page-items-null": ["malformed-page-envelope", "threw MalformedPageError"],
	"malformed-page-without-items": ["malformed-page-envelope", "threw MalformedPageError"],
	"malformed-row-ciphertext-a-number": ["malformed-activity-row", UNREADABLE],
	"malformed-row-ciphertext-missing": ["malformed-activity-row", UNREADABLE],
	"malformed-row-ciphertext-not-base64": ["strict-row-fields", UNREADABLE],
	"malformed-row-conversation-id-missing": ["malformed-activity-row", UNREADABLE],
	"malformed-row-created-at-a-number": ["malformed-activity-row", UNREADABLE],
	"malformed-row-created-at-missing": ["malformed-activity-row", UNREADABLE],
	"malformed-row-created-at-not-a-time": ["malformed-activity-row", UNREADABLE],
	"malformed-row-created-at-without-offset": ["strict-row-fields", UNREADABLE],
	"malformed-row-direction-missing": ["malformed-activity-row", UNREADABLE],
	"malformed-row-encryption-version-missing": ["malformed-activity-row", UNREADABLE],
	"malformed-row-from-a-string": ["malformed-activity-row", UNREADABLE],
	"malformed-row-from-agent-id-missing": ["malformed-activity-row", UNREADABLE],
	"malformed-row-from-missing": ["malformed-activity-row", UNREADABLE],
	"malformed-row-from-org-id-missing": ["malformed-activity-row", UNREADABLE],
	"malformed-row-from-own-missing": ["malformed-activity-row", UNREADABLE],
	"malformed-row-group-a-string": ["malformed-activity-row", UNREADABLE],
	"malformed-row-id-missing": ["malformed-activity-row", "no rows"],
	"malformed-row-key-gen-beyond-safe-integer": ["strict-row-fields", UNREADABLE],
	"malformed-row-key-gen-fraction": ["malformed-activity-row", UNREADABLE],
	"malformed-row-key-gen-negative": ["malformed-activity-row", UNREADABLE],
	"malformed-row-key-gen-string": ["malformed-activity-row", UNREADABLE],
	"malformed-row-payload-a-string": ["malformed-activity-row", UNREADABLE],
	"malformed-row-payload-missing": ["malformed-activity-row", UNREADABLE],
	"malformed-row-type-missing": ["malformed-activity-row", UNREADABLE],
};

const honest = [...recordedCases("org-reader"), ...recordedCases("org-reader-open")];
const hostile = recordedCases("hostile");
const branchScoped = (recorded: RecordedCase) => recorded.reader?.branch != null;

describe("the reader replayed over the recorded honest reads", () => {
	it("covers_three_orgs_in_each_of_the_closed_and_open_lanes", () => {
		expect(honest.map((recorded) => recorded.name)).toEqual([
			"read-1", "read-2", "read-3", "read-1", "read-2", "read-3",
		]);
	});

	for (const [index, recorded] of honest.entries()) {
		it(`reads_${index < 3 ? "closed" : "open"}_${recorded.name}_as_python_did`, async () => {
			for (const read of recorded.reads) {
				const replayed = await replayRead(recorded, read);
				expect(replayed).toEqual({ page: read.page });
			}
		});
	}
});

describe("the reader replayed over the recorded hostile corpus", () => {
	const ordinary = hostile.filter((recorded) => !(recorded.name in DIVERGENT) && !branchScoped(recorded));

	it("covers_every_recorded_case", () => {
		expect(hostile.length).toBe(122);
		expect(ordinary.length + Object.keys(DIVERGENT).length + hostile.filter(branchScoped).length).toBe(122);
	});

	for (const recorded of ordinary) {
		it(`reads_${recorded.name}_as_python_did`, async () => {
			for (const read of recorded.reads) {
				expect(read.raised, "an ordinary case is one Python returned a page for").toBeUndefined();
				expect(await replayRead(recorded, read)).toEqual({ page: read.page });
			}
		});
	}

	it("allows_each_difference_only_under_a_ruling_the_divergence_file_records", () => {
		for (const [name, [ruling]] of Object.entries(DIVERGENT)) {
			expect(hostile.map((recorded) => recorded.name), name).toContain(name);
			expect(["malformed-input"], name).toContain(ruled(ruling)?.decision);
		}
	});

	it("names_in_the_strict_row_fields_ruling_exactly_the_cases_that_cite_it", () => {
		const citing = Object.entries(DIVERGENT).filter(([, [ruling]]) => ruling === "strict-row-fields");
		expect(citing.map(([name]) => name).sort()).toEqual([...(ruled("strict-row-fields")?.cases ?? [])].sort());
	});

	for (const [name, [, expected]] of Object.entries(DIVERGENT)) {
		it(`answers_${name}_in_its_own_way_and_not_as_python_did`, async () => {
			const recorded = hostile.find((candidate) => candidate.name === name) as RecordedCase;
			for (const read of recorded.reads) {
				const replayed = await replayRead(recorded, read);
				expect(outcome(replayed)).toBe(expected);
				for (const group of findingGroups(replayed))
					expect(group, "a finding names the group it is about").toMatch(/^[0-9a-f-]{36}$/);
				expect(replayed).not.toEqual({ page: read.page });
			}
		});
	}
});

describe("hostile cases read with a branch key", () => {
	const scoped = hostile.filter(branchScoped);

	it("are_the_recorded_divergence_because_the_reader_holds_the_org_key_only", () => {
		expect(scoped.map((recorded) => recorded.name).sort()).toEqual(ruled("branch-key-reader")?.cases?.sort());
		expect(ruled("branch-key-reader")?.decision).toBe("not-built");
	});

	for (const recorded of scoped) {
		it(`reads_${recorded.name}_differently_from_a_reader_scoped_to_one_branch`, async () => {
			for (const read of recorded.reads)
				expect(await replayRead(recorded, read)).not.toEqual({ page: read.page });
		});
	}
});

describe("the replay holds the reader to the recording", () => {
	const recorded = honest[0] as RecordedCase;
	const read = recorded.reads[0] as RecordedRead;

	it("fails_when_the_reader_asks_with_other_parameters", async () => {
		const exchanges = read.exchanges.map((exchange) =>
			exchange.query?.limit === undefined
				? exchange
				: { ...exchange, query: { ...exchange.query, limit: "7" } },
		);
		await expect(replayRead(recorded, { ...read, exchanges })).rejects.toThrow(/asked/);
	});

	it("fails_when_a_recorded_answer_goes_unserved", async () => {
		const extra = read.exchanges[read.exchanges.length - 1] as RecordedRead["exchanges"][number];
		await expect(replayRead(recorded, { ...read, exchanges: [...read.exchanges, extra] })).rejects.toThrow(
			/unserved/,
		);
	});
});

describe("the sender-key chain bound", () => {
	it("equals_the_bound_the_python_reader_walks", () => {
		expect(ORG_READ_MAX_CHAIN_STEPS).toBe(10_000);
	});
});
