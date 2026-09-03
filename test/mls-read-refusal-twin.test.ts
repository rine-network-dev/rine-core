/**
 * The binding between `rine-core/src/mls-read-refusal.ts` and its Python twin
 * `rine-sdk/src/rine/mls_read_words.py`.
 *
 * 🔴 This suite exists because the sentence shipped as two hand-typed copies —
 * one in the CLI's decrypt renderer, one in the Python client's — bound by
 * nothing at all. Seventy words, identical but for the remedy clause, in two
 * files no gate compares: `ci.sh` reaches `rine-sdk/tests/contract/` only, and
 * no contract test covers this string. The predictable next move is a session
 * re-pinning the remedy to name `group sync`'s new top-up, editing the copy it
 * is looking at, and shipping two SDKs that give contradicting advice about one
 * failure while every suite stays green.
 *
 * `mls-recovery-twin.test.ts`'s pattern, for its reason: read the other stack's
 * SOURCE, never a rendered fixture, because a fixture regenerated from whichever
 * stack was edited last is a mirror rather than a binding.
 *
 * What is bound, and why each: the sentence, rendered with Python's own
 * placeholder names substituted for the arguments, because that is the whole of
 * what the two stacks must agree on; and each stack's remedy clause separately,
 * because the remedy is the half deliberately NOT identical — an unread
 * difference there is indistinguishable from a drift, and a remedy that stopped
 * naming its surface's own verb is a move the reader cannot complete.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { cliSyncRemedy, mlsReadRefusal } from "../src/mls-read-refusal.js";

const py = readFileSync(
	new URL("../../rine-sdk/src/rine/mls_read_words.py", import.meta.url)
		.pathname,
	"utf8",
);

/**
 * The joined string literals of one Python function's `return`.
 *
 * Takes the whole function body from its `return` onward — the two shapes here
 * are a parenthesised implicit concatenation and a single f-string, and a
 * pattern that knew only the first is how a twin suite comes to silently bind
 * one of the two things it names.
 */
function pyReturn(fn: string): string {
	const at = py.indexOf(`def ${fn}(`);
	expect(at, `no ${fn} in mls_read_words.py`).toBeGreaterThan(-1);
	const next = py.indexOf("\ndef ", at + 1);
	const body = py.slice(at, next === -1 ? py.length : next);
	const ret = body.indexOf("\n    return ");
	expect(ret, `no ${fn} return in mls_read_words.py`).toBeGreaterThan(-1);
	return (body.slice(ret).match(/(['"])(?:\\.|(?!\1).)*\1/g) ?? [])
		.map((lit) => lit.slice(1, -1).replace(/\\(.)/g, "$1"))
		.join("");
}

describe("the Python twin of the unopenable-read sentence", () => {
	it("says the same seventy words on both stacks", () => {
		// Rendered with Python's f-string placeholders as the arguments, so the
		// comparison covers the interpolation POSITIONS too: a stack that moved
		// the group id or the remedy into a different clause fails here even
		// though every word still matches.
		expect(mlsReadRefusal("{group_id}", "{remedy}")).toBe(
			pyReturn("mls_read_refusal"),
		);
	});

	it("keeps each surface's remedy in its own vocabulary", () => {
		// Not byte-twins, on purpose, and each is still pinned: a terminal is
		// told to run a command and a caller holding a client object is told to
		// call a method. `rine group sync` and `groups.sync` are the only verbs
		// on either surface that republish key packages, which is what makes
		// them the remedy rather than merely a sync.
		expect(cliSyncRemedy("g1")).toBe("Run `rine group sync g1`");
		expect(pyReturn("sdk_sync_remedy")).toBe('Call groups.sync("{group_id}")');
	});

	it("reads as one sentence once a surface's own remedy is substituted", () => {
		// The clause is spliced mid-sentence, so a remedy that were a bare verb
		// rather than an imperative clause would read "…no key can ever open.
		// sync to catch this agent's group state up". Both surfaces' real
		// output is checked, not the composer's placeholder rendering.
		const cli = mlsReadRefusal("g1", cliSyncRemedy("g1"));
		expect(cli).toContain(
			"Run `rine group sync g1` to catch this agent's group state up",
		);
		expect(mlsReadRefusal("g1", 'Call groups.sync("g1")')).toContain(
			`Call groups.sync("g1") to catch this agent's group state up`,
		);
	});
});
