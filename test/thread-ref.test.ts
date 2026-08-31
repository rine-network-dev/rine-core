/**
 * The local contract for naming a transcript: exactly one reference, and a
 * conversation reference the wire would actually read as a UUID.
 *
 * Everything here is decided offline, which is the point — these are the two
 * mistakes that used to cost a round trip and come back as a framework 422.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
	THREAD_REF_SURFACES,
	notAConversationUuidRefusal,
	resolveThreadRef,
	threadRefRequiredRefusal,
} from "../src/thread-ref.js";

const CONV = "11111111-2222-3333-4444-555555555555";

describe("resolveThreadRef", () => {
	it("returns the group when a group alone is named", () => {
		expect(resolveThreadRef({ group: "#ops@acme" })).toEqual({
			kind: "group",
			ref: "#ops@acme",
		});
	});

	it("returns the conversation when a conversation alone is named", () => {
		expect(resolveThreadRef({ conversationId: CONV })).toEqual({
			kind: "conversation",
			conversationId: CONV,
		});
	});

	it("refuses both references in one sentence naming both parameters", () => {
		expect(() =>
			resolveThreadRef({ group: "#ops@acme", conversationId: CONV }),
		).toThrow(
			"Name exactly one of group (a group handle, name or UUID) or " +
				"conversationId (a conversation UUID).",
		);
	});

	it("refuses neither reference in the same sentence", () => {
		// One mistake — the call did not say which of two things it wanted read —
		// so one sentence. Two wordings would be two things to keep in step.
		expect(() => resolveThreadRef({})).toThrow(threadRefRequiredRefusal());
		expect(threadRefRequiredRefusal()).toBe(
			threadRefRequiredRefusal(THREAD_REF_SURFACES.sdk),
		);
	});

	it("reads an empty reference as one nobody gave", () => {
		// `--group ""` survives a shell and an untyped tool payload; reading it as
		// given would answer a caller about a value they never passed.
		expect(() => resolveThreadRef({ group: "", conversationId: CONV })).not.toThrow();
		expect(() => resolveThreadRef({ group: "  ", conversationId: "" })).toThrow(
			threadRefRequiredRefusal(),
		);
	});

	it("refuses a group named to the conversation parameter, and says where to put it", () => {
		// 🔴 The placeholder ban, second rung. This sentence used to print
		// `group=#logistics@acme.rine.network`, and the Python twin's docstring
		// defended it in the product — *"a worked example teaches the spelling; a
		// template invites a placeholder"*, an argument since retired.
		// It still names the parameter that takes a group and still lists the
		// three spellings that parameter accepts; what it no longer does is hand
		// the caller a domain to paste.
		expect(() => resolveThreadRef({ conversationId: "#ops@acme" })).toThrow(
			'conversationId must be a conversation UUID; "#ops@acme" is not one. ' +
				"To read a group, name the group instead — group takes a group's " +
				"whole handle, a bare group name, or its UUID.",
		);
	});

	it("shows no handle of its own, whichever surface is asking", () => {
		// 🔴 The ban, asserted as a ban: the test above pins one wording and would
		// stay green if a later edit swapped `#logistics@acme…` for a different
		// invented handle inside a reworded sentence. The caller's own reference
		// is quoted back — it is the one `@` a refusal composed with no roster and
		// no client may legitimately carry — so the probe is run on a value that
		// has none, across all three surface spellings.
		for (const surface of Object.values(THREAD_REF_SURFACES)) {
			expect(notAConversationUuidRefusal("ops", surface)).not.toContain("@");
		}
	});

	it("spells the parameters the way the calling surface takes them", () => {
		expect(() => resolveThreadRef({}, THREAD_REF_SURFACES.cli)).toThrow(
			"Name exactly one of --group (a group handle, name or UUID) or " +
				"<conversation-id> (a conversation UUID).",
		);
		expect(notAConversationUuidRefusal("x", THREAD_REF_SURFACES.tool)).toContain(
			"conversation_id must be a conversation UUID",
		);
	});

	it("accepts every spelling the wire reads as a UUID", () => {
		// 🔴 A pre-flight may only refuse what the wire would have refused. The
		// server types this path parameter `uuid.UUID`, which has always accepted
		// these three alongside the canonical one — refusing them here would be a
		// capability removal wearing a validation fix.
		for (const spelling of [
			CONV.replace(/-/g, ""),
			`urn:uuid:${CONV}`,
			`{${CONV}}`,
		]) {
			expect(resolveThreadRef({ conversationId: spelling })).toEqual({
				kind: "conversation",
				conversationId: spelling,
			});
		}
	});
});

describe("the Python twin", () => {
	// The two stacks share no module, so the binding is a test — the same shape
	// `rine-sdk/tests/test_actor_contract.py` uses in the other direction for the
	// placeholder list. A sentence that drifted would send a caller on one stack
	// to a spelling the other refuses, and nothing else would notice.
	const py = readFileSync(
		new URL("../../rine-sdk/src/rine/thread_words.py", import.meta.url).pathname,
		"utf8",
	);

	/** Join a Python implicit-concatenation of string literals into one string. */
	function joined(block: string): string {
		return (block.match(/(['"])(?:\\.|(?!\1).)*\1/g) ?? [])
			.map((lit) => lit.slice(1, -1).replace(/\\(.)/g, "$1"))
			.join("");
	}

	it("says the same sentence about naming exactly one reference", () => {
		const block = py.match(/TRANSCRIPT_REFERENCE_REQUIRED = \(([\s\S]*?)\n\)/);
		expect(block?.[1]).toBeTruthy();
		expect(threadRefRequiredRefusal(THREAD_REF_SURFACES.tool)).toBe(
			joined(block?.[1] ?? ""),
		);
	});

	it("says the same sentence about a conversation reference that is not one", () => {
		const block = py.match(/def not_a_conversation_uuid[\s\S]*?return \(([\s\S]*?)\n {4}\)/);
		expect(block?.[1]).toBeTruthy();
		expect(notAConversationUuidRefusal("x", THREAD_REF_SURFACES.tool)).toBe(
			joined(block?.[1] ?? "").replace("{value}", "x"),
		);
	});

	it("reads a group's transcript from the same route", () => {
		expect(py).toContain('f"/groups/{group_id}/messages"');
	});
});
