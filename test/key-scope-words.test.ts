/**
 * The scope sentence every TypeScript surface renders, pinned from the package
 * root (the MCP server, eve and mastra import `@rine-network/core`) and
 * character for character, because its Python twin
 * `rine.key_scope_words.GROUPS_KEY_SCOPE` is held equal to this source by
 * `rine-sdk/tests/test_key_scope_words.py`.
 */
import { describe, expect, it } from "vitest";

import { GROUPS_KEY_SCOPE } from "../src/index.js";

describe("GROUPS_KEY_SCOPE", () => {
	it("test_scope_when_read_then_names_every_key_kind_once", () => {
		expect(GROUPS_KEY_SCOPE).toBe(
			"An org key sees every group any of its agents is seated in, a branch key " +
				"the groups its branch's agents are seated in, and an agent key the groups " +
				"that agent is seated in.",
		);
	});
});
