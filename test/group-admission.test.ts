/**
 * The admission vocabulary: that every reason has a sentence, that the
 * sentences say the true thing, and that an unfamiliar token cannot crash a
 * report.
 *
 * The one these exist for is `not_applicable`. An open group mints no voucher
 * because it needs none, so every entry of a plural invite into one comes back
 * `skipped/not_applicable` — and the same code path then DMs those agents. A
 * surface printing the raw token says "skipped" about somebody it just invited
 * in.
 */
import { describe, expect, it } from "vitest";

import {
	GROUP_ADMISSION_SKIP_REASONS,
	type GroupAdmissionReport,
	admittedAgentIds,
	admissionHeadline,
	groupAdmissionSkipSentence,
	mlsAdmissionSkipSentence,
} from "../src/group-admission.js";
import type { MlsAdmissionSkipReason } from "../src/mls-admission.js";

/** Every member of the MLS enum, named so adding one fails to compile here. */
const MLS_SKIP_REASONS: MlsAdmissionSkipReason[] = [
	"no_key_package",
	"already_in_group",
	"rejected_by_server",
];

describe("groupAdmissionSkipSentence", () => {
	it("answers every reason the server can send with a sentence of its own", () => {
		const sentences = GROUP_ADMISSION_SKIP_REASONS.map(
			groupAdmissionSkipSentence,
		);
		expect(new Set(sentences).size).toBe(GROUP_ADMISSION_SKIP_REASONS.length);
		for (const sentence of sentences) {
			expect(sentence).not.toMatch(/^[a-z_]+$/);
			expect(sentence).not.toMatch(/not recognised/);
		}
	});

	it("says an open group's skip is not a refusal, because those agents were invited in", () => {
		const sentence = groupAdmissionSkipSentence("not_applicable");
		expect(sentence).toMatch(/open enrollment/);
		expect(sentence).toMatch(/may join/);
	});

	it("quotes back a reason it does not know rather than throwing or hiding it", () => {
		expect(groupAdmissionSkipSentence("some_future_reason")).toContain(
			"some_future_reason",
		);
	});

	it("says so plainly when there is no reason at all", () => {
		expect(groupAdmissionSkipSentence(undefined)).toBe("no reason given");
		expect(groupAdmissionSkipSentence(null)).toBe("no reason given");
	});
});

describe("mlsAdmissionSkipSentence", () => {
	it("answers every reason a batched admission can record", () => {
		for (const reason of MLS_SKIP_REASONS) {
			const sentence = mlsAdmissionSkipSentence(reason);
			expect(sentence).not.toMatch(/not recognised/);
			expect(sentence.length).toBeGreaterThan(reason.length);
		}
	});

	it("keeps the two vocabularies apart — an MLS reason is not a group reason", () => {
		expect(groupAdmissionSkipSentence("no_key_package")).toContain(
			"not recognised",
		);
		expect(mlsAdmissionSkipSentence("not_applicable")).toContain(
			"not recognised",
		);
	});
});

describe("admittedAgentIds", () => {
	const report = (
		entries: GroupAdmissionReport["entries"],
	): GroupAdmissionReport => ({
		invited: entries.filter((e) => e.status === "invited").length,
		skipped: entries.filter((e) => e.status === "skipped").length,
		entries,
	});

	it("counts an open group's not_applicable entries as reached", () => {
		expect(
			admittedAgentIds(
				report([
					{ agent_id: "a", status: "skipped", reason: "not_applicable" },
					{ agent_id: "b", status: "skipped", reason: "not_applicable" },
				]),
			),
		).toEqual(["a", "b"]);
	});

	it("leaves out the entries nobody may act on", () => {
		expect(
			admittedAgentIds(
				report([
					{ agent_id: "a", status: "invited", reason: null },
					{ agent_id: "b", status: "skipped", reason: "agent_revoked" },
					{ agent_id: "c", status: "skipped", reason: "already_a_member" },
				]),
			),
		).toEqual(["a"]);
	});

	it("never reports an open group's whole roster as achieving nothing", () => {
		// 🔴 The regression gate for the headline. The server answers
		// `not_applicable` for EVERY valid agent on an open group, so
		// `invited`/`skipped` read "0 invited, 2 skipped" there — always —
		// while the very same call DMs both of them an invitation notice. Six
		// surfaces printed that line directly above per-agent lines saying they
		// may join whenever they like.
		const open = report([
			{ agent_id: "a", status: "skipped", reason: "not_applicable" },
			{ agent_id: "b", status: "skipped", reason: "not_applicable" },
		]);
		const head = admissionHeadline(open);
		expect(head).toContain("2 of 2 reached");
		expect(head).not.toContain("skipped");
		expect(head).not.toContain("0 of 2");
	});

	it("still says how many invitations there are to accept", () => {
		const closed = report([
			{ agent_id: "a", status: "invited", reason: null },
			{ agent_id: "b", status: "skipped", reason: "agent_revoked" },
		]);
		expect(admissionHeadline(closed)).toBe(
			"1 of 2 reached; 1 new invitation to accept.",
		);
	});

	it("counts a nomination as reached, because it holds a seat like an invitation", () => {
		// `pending` and `invited` are one population to the 500-member
		// ceiling, so a nominee occupies a ratchet-tree seat from the moment the
		// row is filed. An admission that reported them as unreached would say
		// the group has room it does not have.
		expect(
			admittedAgentIds(
				report([
					{ agent_id: "a", status: "nominated", reason: null },
					{ agent_id: "b", status: "skipped", reason: "already_a_member" },
				]),
			),
		).toEqual(["a"]);
	});

	it("never offers a nomination as an invitation to accept", () => {
		// 🔴 The regression gate for this. A nomination seats nobody and may be
		// denied, so "2 new invitations to accept" is a falsehood about the two
		// rows printed directly beneath it — which is the whole reason the
		// server answers a third status rather than reusing `invited`.
		const nominations = report([
			{ agent_id: "a", status: "nominated", reason: null },
			{ agent_id: "b", status: "nominated", reason: null },
		]);
		expect(admissionHeadline(nominations)).toBe(
			"2 of 2 reached; 2 new nominations awaiting a vote.",
		);
	});

	it("states both clauses when one batch produced both, invitations first", () => {
		const mixed = report([
			{ agent_id: "a", status: "invited", reason: null },
			{ agent_id: "b", status: "nominated", reason: null },
		]);
		expect(admissionHeadline(mixed)).toBe(
			"2 of 2 reached; 1 new invitation to accept; 1 new nomination awaiting a vote.",
		);
	});
});
