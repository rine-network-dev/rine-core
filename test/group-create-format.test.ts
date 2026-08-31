/**
 * `createdGroupMls` — the answer a client gives about the group it just made.
 *
 * 🔴 The whole point of this function is the ORDER of its four arms, and the
 * order exists because three of the four states are field-for-field identical on
 * the group row: only the create RESULT tells them apart. So every arm is
 * enumerated here, and each asserts the WHOLE object — a `toContain` on the note
 * would have passed on every wrong answer the ordering exists to prevent.
 *
 * It arrived in this package as two byte-identical copies in `rine-mastra` and
 * `rine-eve`, neither of which had a test that could see the other drift.
 */
import { describe, expect, it } from "vitest";
import { MLS_PENDING_SELF_CLEAR_SECONDS } from "../src/crypto/mls-init-in-flight.js";
import {
	type CreatedGroupMlsFields,
	MLS_FOUNDING_FAILED_MODE,
	MLS_FOUNDING_FAILED_NOTE,
	createdGroupMls,
} from "../src/group-create-format.js";
import { unfoundedGroupNote } from "../src/mls-recovery-format.js";

/** A created group nothing has founded: closed, meant for MLS, no latch. */
function created(
	overrides: Partial<CreatedGroupMlsFields> = {},
): CreatedGroupMlsFields {
	return {
		enrollment_policy: "closed",
		mls_enabled: true,
		mls_group_id: null,
		mls_pending: false,
		...overrides,
	};
}

const ADMISSION = { epoch: 1, commits: 1, added: 0, outcomes: [] };

describe("createdGroupMls — the four arms, in order", () => {
	it("a founding that landed says MLS, even when the row it left says otherwise", () => {
		// The re-read after the init was refused, so this is the PRE-init row:
		// every MLS predicate on it reads "never founded" while the tree exists
		// and the server refuses a sender-key send into the group.
		expect(createdGroupMls(created({ mlsAdmission: ADMISSION }))).toEqual({
			mode: "MLS",
			note: "",
		});
	});

	it("a founding that did not land gets its own sentence, never the unfounded note", () => {
		// 🔴 `unfoundedGroupNote` promises the messages ARE sealed with sender
		// keys. If this init's POST reached the server the group is frozen and
		// that promise is false, so the two sentences must not be interchangeable.
		const answer = createdGroupMls(created({ mlsInit: { ok: false } }));
		expect(answer).toEqual({
			mode: MLS_FOUNDING_FAILED_MODE,
			note: MLS_FOUNDING_FAILED_NOTE,
		});
		expect(answer.note).not.toContain("sealed with sender keys");
		expect(answer.note).toContain(
			`within ${Math.round(MLS_PENDING_SELF_CLEAR_SECONDS / 60)} minutes`,
		);
	});

	it("the landed arm wins over the failed one when a caller hands it both", () => {
		// Not reachable through the SDK's own create, and asserted anyway: the
		// ordering is the contract, and a later edit that swapped the two arms
		// would otherwise change what a founded group is called with no test red.
		expect(
			createdGroupMls(
				created({ mlsAdmission: ADMISSION, mlsInit: { ok: false } }),
			),
		).toEqual({ mode: "MLS", note: "" });
	});

	it("a group created for an MLS it has not got says so, in the shared words", () => {
		expect(createdGroupMls(created())).toEqual({
			mode: "sender-key",
			note: unfoundedGroupNote(),
		});
	});

	it("the mode field never repeats what the note already said", () => {
		// The parenthetical a list row uses is an abbreviation OF this note. A
		// head that carries the sentence and the abbreviation says one fact twice
		// in two phrasings, which is what a model parrots back instead of acting.
		expect(createdGroupMls(created()).mode).not.toContain("never founded");
	});

	it("an ordinary sender-key group is given no note it was never promised", () => {
		expect(createdGroupMls(created({ mls_enabled: false }))).toEqual({
			mode: "sender-key",
			note: "",
		});
	});

	it("an open group is given no note either — it never had a tree to found", () => {
		expect(createdGroupMls(created({ enrollment_policy: "open" }))).toEqual({
			mode: "sender-key",
			note: "",
		});
	});

	it("the default arm still answers MLS for a latched group", () => {
		// `mls_enabled` false keeps the never-founded arm above from claiming it,
		// so this reaches the last arm with a real latch — the case that arm's
		// two-answer question exists for.
		expect(
			createdGroupMls(
				created({ mls_enabled: false, mls_group_id: "mls-latch-abc" }),
			),
		).toEqual({ mode: "MLS", note: "" });
	});

	it("the default arm answers MLS during an init still in flight", () => {
		// A send in this window already takes the MLS branch, so "sender-key"
		// here would state the opposite of what the group is doing.
		expect(
			createdGroupMls(created({ mls_enabled: false, mls_pending: true })),
		).toEqual({ mode: "MLS", note: "" });
	});
});

describe("createdGroupMls — the repair word reaches exactly one arm", () => {
	it("names the caller's founding verb on the never-founded arm", () => {
		const answer = createdGroupMls(created(), "cli-resume-admission");
		expect(answer).toEqual({
			mode: "sender-key",
			note: unfoundedGroupNote("cli-resume-admission"),
		});
		expect(answer.note).toContain("rine group resume-admission");
	});

	it("defaults to naming no verb, which is an answer and not a silence", () => {
		expect(createdGroupMls(created()).note).toContain(
			"No verb on this surface founds it",
		);
	});

	it("is ignored by the failed arm, whose two ways out the row cannot tell apart", () => {
		expect(
			createdGroupMls(
				created({ mlsInit: { ok: false } }),
				"cli-resume-admission",
			),
		).toEqual({
			mode: MLS_FOUNDING_FAILED_MODE,
			note: MLS_FOUNDING_FAILED_NOTE,
		});
	});

	it("refuses a repair word no table maps, rather than rendering `undefined`", () => {
		expect(() =>
			// biome-ignore lint/suspicious/noExplicitAny: a JavaScript caller has no compile step.
			createdGroupMls(created(), "not-a-verb" as any),
		).toThrow(/Unknown repair verb/);
	});
});
