/**
 * The group-rule sentences are the server's, byte for
 * byte, pinned to `fixtures/group-rules.json`; a refused group is refused
 * before anything is sealed; an unknown value never throws.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { GROUP_ADMISSION_SKIP_REASONS } from "../src/group-admission.js";
import {
	GroupPostingRefusedError,
	PostingRefusal,
	assertGroupPostable,
	postingLine,
	unreadableByOrgsSentence,
} from "../src/group-postable.js";
import { RuleRefusal } from "../src/org-rules-types.js";

const fixture = JSON.parse(
	readFileSync(
		new URL("./fixtures/group-rules.json", import.meta.url).pathname,
		"utf8",
	),
) as {
	skip_reason: string;
	posting_refusals: string[];
	codes: string[];
	sentences: {
		posting_refused: Record<string, string>;
		posting_line: { foreign_open_group: string; refused_members: string };
		unreadable: { one: string; many: string };
	};
};

const GROUP = "c3d4e5f6-a7b8-9012-cdef-123456789012";

describe("the group-rule vocabulary matches the server fixture", () => {
	it("test_vocabulary_when_the_server_adds_a_token_then_the_client_knows_it", () => {
		expect([...GROUP_ADMISSION_SKIP_REASONS]).toContain(fixture.skip_reason);
		expect(Object.values(PostingRefusal).sort()).toEqual(
			[...fixture.posting_refusals].sort(),
		);
		const codes = Object.values(RuleRefusal) as string[];
		for (const code of fixture.codes) expect(codes).toContain(code);
	});
});

describe("assertGroupPostable", () => {
	for (const reason of fixture.posting_refusals) {
		it(`test_post_when_the_group_says_${reason}_then_it_refuses_in_the_server_words`, () => {
			let thrown: unknown;
			try {
				assertGroupPostable({ id: GROUP, posting_refused: reason as never });
			} catch (err) {
				thrown = err;
			}
			expect(thrown).toBeInstanceOf(GroupPostingRefusedError);
			const err = thrown as GroupPostingRefusedError;
			expect(err.message).toBe(fixture.sentences.posting_refused[reason]);
			expect(err.code).toBe("group_posting_refused");
			expect(err.groupId).toBe(GROUP);
		});
	}

	it("test_post_when_nothing_is_refused_then_it_passes", () => {
		expect(() => assertGroupPostable({ id: GROUP })).not.toThrow();
		expect(() =>
			assertGroupPostable({ id: GROUP, posting_refused: null }),
		).not.toThrow();
	});

	it("test_post_when_the_value_is_one_a_newer_server_added_then_it_leaves_the_refusal_to_the_server", () => {
		expect(() =>
			assertGroupPostable({ id: GROUP, posting_refused: "from_the_future" }),
		).not.toThrow();
	});
});

describe("unreadableByOrgsSentence", () => {
	it("test_unreadable_when_one_org_cannot_read_then_the_singular_sentence", () => {
		expect(unreadableByOrgsSentence(1)).toBe(fixture.sentences.unreadable.one);
	});

	it("test_unreadable_when_several_orgs_cannot_read_then_the_plural_sentence", () => {
		expect(unreadableByOrgsSentence(2)).toBe(
			fixture.sentences.unreadable.many.replace("{n}", "2"),
		);
	});

	it("test_unreadable_when_none_or_absent_then_nothing_is_said", () => {
		expect(unreadableByOrgsSentence(0)).toBeUndefined();
		expect(unreadableByOrgsSentence(null)).toBeUndefined();
		expect(unreadableByOrgsSentence(undefined)).toBeUndefined();
	});
});

describe("postingLine", () => {
	it("test_line_when_the_group_is_foreign_and_open_then_the_fixture_line", () => {
		expect(postingLine({ posting_refused: "foreign_open_group" })).toBe(
			fixture.sentences.posting_line.foreign_open_group,
		);
	});

	it("test_line_when_members_are_refused_then_it_counts_them", () => {
		expect(
			postingLine({
				posting_refused: "refused_members",
				refused_members: ["a", "b", "c"],
			}),
		).toBe(fixture.sentences.posting_line.refused_members.replace("{k}", "3"));
	});

	it("test_line_when_posting_is_allowed_then_there_is_no_line", () => {
		expect(postingLine({})).toBeNull();
		expect(postingLine({ posting_refused: null })).toBeNull();
	});
});
