// Item 18's sentence — the one place the bytes exist.
//
// `resolveToUuid` completes a short handle before WebFinger sees it and answers
// with a UUID, never the spelling it resolved, so the substitution is invisible
// at every call site by construction. Four surfaces now report it and none of
// them may hold the wording: the CLI writes a stderr line, `@rine-network/mcp`
// hangs it on a result object as `handle_completion`, and `rine-mastra` /
// `rine-eve` lead their string answer with it. A surface decides only WHERE the
// sentence goes.
//
// 🔴 So this suite is what those four are pinned against. Each surface derives
// its expectation from these functions rather than retyping them — the drift a
// cross-package byte comparison structurally cannot see is four copies agreeing
// with each other and none of them agreeing with `normalizeHandle`.

import { describe, expect, it } from "vitest";
import {
	handleCompletionNote,
	handleCompletionNotes,
} from "../src/handle-completion.js";
import { normalizeHandle } from "../src/resolve-handle.js";

/** What gets typed: the org half without its domain. */
const TYPED = "kofi@acme";
/** What the lookup actually used. */
const COMPLETED = "kofi@acme.rine.network";

describe("handleCompletionNote — one spelling", () => {
	it("names the caller's spelling and the one the lookup used", () => {
		expect(handleCompletionNote(TYPED)).toBe(
			`Note: '${TYPED}' was completed to '${COMPLETED}' before the lookup.`,
		);
	});

	// 🔴 The caller's own two strings and no third handle — not this
	// agent's own, not an example org for a model to copy.
	it("quotes two handles and invents no third", () => {
		const note = handleCompletionNote(TYPED) ?? "";
		expect(note.match(/@[a-z0-9.-]+/g)).toEqual([
			"@acme",
			"@acme.rine.network",
		]);
	});

	it("says nothing when the spelling was already whole", () => {
		expect(handleCompletionNote(COMPLETED)).toBeUndefined();
	});

	// `resolveToUuid` refuses a bare name outright rather than completing it, so
	// there is no substitution here to report even though the spelling is short.
	it("says nothing for a bare name, which names no org to complete", () => {
		expect(handleCompletionNote("kofi")).toBeUndefined();
	});

	it("says nothing for a UUID, which names no domain to complete", () => {
		expect(
			handleCompletionNote("11111111-1111-1111-1111-111111111111"),
		).toBeUndefined();
	});

	// 🔴 The completion rule is CALLED, never restated. A second copy of it here
	// could disagree with the lookup and announce a substitution that never
	// happened — or miss one that did. Driven by `normalizeHandle` itself: a
	// domain that already carries a dot is left alone by it, so this must be
	// silent whatever that rule grows into.
	it("is silent exactly where normalizeHandle is a no-op", () => {
		for (const spelling of [
			"kofi@acme.co.uk",
			"kofi@localhost.test",
			"kofi",
			"#team@acme.rine.network",
		]) {
			expect(normalizeHandle(spelling)).toBe(spelling);
			expect(handleCompletionNote(spelling)).toBeUndefined();
		}
	});

	it("reports exactly what normalizeHandle produced", () => {
		const note = handleCompletionNote("ada@ops") ?? "";
		expect(note).toContain(`'${normalizeHandle("ada@ops")}'`);
	});
});

describe("handleCompletionNotes — a batch", () => {
	// A plural verb — a founding roster, a batch invite — is where a silent
	// completion does the most damage: one wrong agent among twenty seats itself
	// unnoticed. A caller who named five and mistyped two needs to see which two.
	it("gives every completed spelling its own sentence, in the order named", () => {
		expect(handleCompletionNotes(["ana@acme", "ben@ops"])).toBe(
			`${handleCompletionNote("ana@acme")} ${handleCompletionNote("ben@ops")}`,
		);
	});

	it("names only the spellings that were rewritten", () => {
		const note = handleCompletionNotes([
			"ana@acme.rine.network",
			"ben@ops",
			"11111111-1111-1111-1111-111111111111",
		]);
		expect(note).toBe(handleCompletionNote("ben@ops"));
	});

	// The same spelling twice in one roster is ONE substitution. Repeating the
	// sentence reads as two different agents having been rewritten.
	it("says a repeated spelling once", () => {
		expect(handleCompletionNotes(["ana@acme", "ana@acme"])).toBe(
			handleCompletionNote("ana@acme"),
		);
	});

	it("says nothing when every spelling was already whole", () => {
		expect(
			handleCompletionNotes(["ana@acme.rine.network", "ben@ops.example.com"]),
		).toBeUndefined();
	});

	it("says nothing for an empty batch", () => {
		expect(handleCompletionNotes([])).toBeUndefined();
	});
});
