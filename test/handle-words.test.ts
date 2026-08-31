import { describe, expect, it } from "vitest";
import { JOIN_TAKES_A_HANDLE_OR_AN_ID } from "../src/group-join-words.js";
import { GROUP_HANDLE_PARTS } from "../src/handle-words.js";

describe("GROUP_HANDLE_PARTS", () => {
	// 🔴 The one binding between the shared clause and the ratified sentence that
	// cannot compose it. `JOIN_TAKES_A_HANDLE_OR_AN_ID` is parsed as a single
	// string literal by the backend twin gate, so it restates the clause by hand;
	// without this assertion a re-pin on either side diverges with every suite on
	// both stacks green, and `rine-mcp`'s two composing copies would then be
	// saying something the join refusal no longer says.
	it("is the clause the ratified join refusal spells out by hand", () => {
		expect(JOIN_TAKES_A_HANDLE_OR_AN_ID).toContain(GROUP_HANDLE_PARTS);
	});

	// The placeholder ban is why the clause exists at all: it describes the handle
	// instead of printing one, so nothing in it can be pasted back or filled in.
	it("prints nothing a model could paste back, and no slot to fill", () => {
		expect(GROUP_HANDLE_PARTS).not.toContain("@");
		expect(GROUP_HANDLE_PARTS).not.toMatch(/example|<|>|\{[a-zA-Z_]/);
	});

	// A clause, not a sentence: its three readers set it in three different
	// punctuations, so it may neither open with a capital nor close itself.
	it("carries no terminator of its own", () => {
		expect(GROUP_HANDLE_PARTS.endsWith(".")).toBe(false);
		expect(GROUP_HANDLE_PARTS[0]).toBe(GROUP_HANDLE_PARTS[0]?.toLowerCase());
	});
});
