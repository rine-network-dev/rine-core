/**
 * The binding between `rine-core/src/mls-recovery-format.ts` and its Python
 * twin `rine-sdk/src/rine/format.py`.
 *
 * 🔴 This suite exists because there was none. The two modules were twins **by
 * convention only**: every doc comment on both sides claimed they were "sentence
 * for sentence identical", and nothing checked it. They had already drifted —
 * the TypeScript refusal ended its list of accepted repair words with a full
 * stop and the Python one did not — and the drift shipped.
 *
 * The pattern is `test/thread-ref.test.ts`'s: the two stacks share no module, so
 * the binding is a test that reads the other stack's source. It reads the
 * *source* rather than a rendered fixture on purpose — a fixture regenerated
 * from whichever stack was edited last is a mirror, not a binding.
 *
 * What is bound, and why each: the note, because it is the one wording of the
 * fact; the sender-keys head the note is appended to, because the never-founded
 * summary is composed out of it on both stacks and it is the pair the audit
 * actually named — the first version of this suite bound the note alone and
 * the drift survived it; the verb map, because a surface's spelling of its own
 * founding verb is the token both clause tables derive from; both derived
 * tables, because that derivation is what makes the second table safe to add;
 * the refusal's tail, because that is where the drift was; and the three
 * recovery heads, because one of them was reworded and a one-sided rewording is
 * a successful recovery graded as a broken surface by two matrix drivers.
 *
 * 🔴 It therefore binds TWO modules to one Python file — `group-format.ts` for
 * the head, `mls-recovery-format.ts` for everything else — and the file name
 * names only the second. The pair a twin suite binds is what its assertions
 * read, never what its path suggests; that gap is how the first version came to
 * bind a pair nobody had reported drifting.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { GroupRead } from "../src/api-types.js";
import { groupEncryption } from "../src/group-format.js";
import {
	MLS_NEVER_FOUNDED_NOTE,
	type UnfoundedGroupRepair,
	describeMlsRecovery,
	mlsNeverFoundedSync,
	unfoundedGroupNote,
} from "../src/mls-recovery-format.js";

const py = readFileSync(
	new URL("../../rine-sdk/src/rine/format.py", import.meta.url).pathname,
	"utf8",
);

/** Join a Python implicit-concatenation of string literals into one string. */
function joined(block: string): string {
	return (block.match(/(['"])(?:\\.|(?!\1).)*\1/g) ?? [])
		.map((lit) => lit.slice(1, -1).replace(/\\(.)/g, "$1"))
		.join("");
}

/** The joined literals of a Python source region, or a failure naming it. */
function pySource(what: string, pattern: RegExp): string {
	const block = py.match(pattern);
	expect(block?.[1], `no ${what} in rine-sdk/src/rine/format.py`).toBeTruthy();
	return joined(block?.[1] ?? "");
}

/** A module-level `_NAME = "…"` constant, f-string prefix and all. */
function pyConst(name: string): string {
	return pySource(name, new RegExp(`\\n${name} = f?(.+)`));
}

const REPAIRS: UnfoundedGroupRepair[] = [
	"cli-resume-admission",
	"sdk-resume-admission",
	"tool-group-reclaim",
	"none",
];

/**
 * The Python verb map, parsed from its source: `null` is a surface whose
 * nearest verb refuses instead of founding.
 */
const PY_VERBS = new Map<string, string | null>(
	(
		py.match(
			/_REPAIR_VERBS: dict\[UnfoundedGroupRepair, str \| None\] = \{([\s\S]*?)\n\}/,
		)?.[1] ?? ""
	)
		.split("\n")
		.map((line) => line.match(/"([^"]+)":\s*(?:"([^"]*)"|None)/))
		.filter((m): m is RegExpMatchArray => m !== null)
		.map((m): [string, string | null] => [m[1] ?? "", m[2] ?? null]),
);

describe("the Python twin — the fact itself", () => {
	it("words the never-founded state in exactly the same sentence", () => {
		expect(MLS_NEVER_FOUNDED_NOTE).toBe(
			pySource(
				"MLS_NEVER_FOUNDED_NOTE",
				/MLS_NEVER_FOUNDED_NOTE = \(([\s\S]*?)\n\)/,
			),
		);
	});
});

describe("the Python twin — the head the note is appended to", () => {
	// 🔴 The audit named `group-format.ts` ⇄ `format.py` as the unbound, already
	// drifted pair. The suite written for it bound `mls-recovery-format.ts`
	// instead — the note, and none of the head the note is appended to — so the
	// drift it found outlived the test written to catch it: `Sender Keys — NOT
	// post-quantum.` on this stack against `Sender Keys, which are NOT
	// post-quantum.` on the other, in the FIRST sentence a never-founded group
	// gets on every surface of both stacks.
	//
	// Bound through the RENDERED summary rather than through the two constants,
	// for the reason the verb map is: a head that reached the constant but not
	// the sentence, or reached it behind a different separator, is exactly the
	// failure this is for.
	const NEVER_FOUNDED = {
		id: "88888888-8888-8888-8888-888888888888",
		name: "standup",
		handle: "#standup@acme.rine.network",
		enrollment_policy: "closed",
		mls_enabled: true,
		mls_group_id: null,
		mls_pending: false,
	} as unknown as GroupRead;

	it("opens the never-founded summary on the same sentence, for every repair word", () => {
		const pyHead = pyConst("_SENDER_KEYS_HEAD");
		for (const repair of REPAIRS) {
			expect(groupEncryption(NEVER_FOUNDED, repair).summary).toBe(
				`${pyHead} ${unfoundedGroupNote(repair)}`,
			);
		}
	});

	it("composes it the same way over there — head, one space, then the note", () => {
		// The assertion above pairs Python's head with TypeScript's composition.
		// This one reads Python's composition, so a stack that kept the head and
		// stopped prefixing it cannot pass both.
		expect(py).toContain(
			'return f"{_SENDER_KEYS_HEAD} {unfounded_group_note(repair)}"',
		);
	});
});

describe("the Python twin — the founding verb, spelled once per surface", () => {
	// The map is the token both clause tables derive from. A stack that spelled
	// `resume_admission()` without its parentheses, or `rine group resume` for
	// `rine group resume-admission`, would send a caller to a verb that does not
	// exist — and both tables would carry the mistake identically, so neither
	// table's own test could see it.
	it("names the same four repair words, in the same order", () => {
		expect([...PY_VERBS.keys()]).toEqual(REPAIRS);
	});

	it("spells every verb the way the other stack spells it", () => {
		// Read back out of the rendered clause rather than out of a TypeScript
		// constant: the clause is what an operator sees, and a verb that reached
		// the map but not the sentence is the failure this binds against.
		for (const [repair, verb] of PY_VERBS) {
			const said = mlsNeverFoundedSync(repair as UnfoundedGroupRepair);
			if (verb === null) {
				expect(said).toContain("No verb on this surface founds it");
			} else {
				expect(said).toContain(`Run ${verb} on it to found its MLS state`);
			}
		}
	});
});

describe("the Python twin — both derived clause tables", () => {
	const syncVerb = pyConst("_SYNC_VERB_CLAUSE");
	const stateVerb = pyConst("_STATE_VERB_CLAUSE");
	const noVerb = pyConst("_NO_VERB_HERE");
	const resolve = (clause: string) => clause.replace("{_NO_VERB_HERE}", noVerb);
	const syncNoVerb = resolve(pyConst("_SYNC_NO_VERB_CLAUSE"));
	const stateNoVerb = resolve(pyConst("_STATE_NO_VERB_CLAUSE"));

	function pyClause(
		repair: UnfoundedGroupRepair,
		verbTemplate: string,
		noVerbClause: string,
	): string {
		const verb = PY_VERBS.get(repair) ?? null;
		return verb === null
			? noVerbClause
			: verbTemplate.replace("{verb}", verb);
	}

	it("says the same thing after a sync, for every repair word", () => {
		for (const repair of REPAIRS) {
			expect(mlsNeverFoundedSync(repair)).toBe(
				MLS_NEVER_FOUNDED_NOTE + pyClause(repair, syncVerb, syncNoVerb),
			);
		}
	});

	it("says the same thing about the group itself, for every repair word", () => {
		for (const repair of REPAIRS) {
			expect(unfoundedGroupNote(repair)).toBe(
				MLS_NEVER_FOUNDED_NOTE + pyClause(repair, stateVerb, stateNoVerb),
			);
		}
	});

	it("never tells a renderer to repeat a sync nobody ran", () => {
		// The whole reason the second table exists. Every clause in the first one
		// ends on a sync — "then run the sync again", "before this sync has
		// anything to catch up" — which is false in a surface that is describing a
		// group rather than reporting a recovery.
		for (const repair of REPAIRS) {
			expect(unfoundedGroupNote(repair)).not.toContain("sync");
			expect(mlsNeverFoundedSync(repair)).toContain("sync");
		}
	});
});

describe("the Python twin — the refusal, where the drift actually was", () => {
	it("lists the accepted words in the same sentence, down to the full stop", () => {
		// 🔴 The one byte this suite was written to catch, already shipped: the
		// TypeScript refusal ended `…, none.` and the Python one ended `…, none`.
		// One event, two spellings, and nothing looked.
		const pyMessage = pySource(
			"the unknown-repair refusal",
			/raise ValueError\(\n?\s*f(".*")\n?\s*\)/,
		);
		const afterVerb = pyMessage.split("{repair!r}")[1];
		expect(afterVerb, "the refusal no longer echoes the word it refused").toBeTruthy();
		const tail = (afterVerb ?? "").replace("{expected}", REPAIRS.join(", "));

		let thrown = "";
		try {
			mlsNeverFoundedSync("resume-admission" as never);
		} catch (err) {
			thrown = (err as Error).message;
		}

		expect(thrown).not.toBe("");
		expect(thrown.slice(thrown.indexOf(" — "))).toBe(tail);
	});

	it("refuses on both tables, so neither renders a word it has no clause for", () => {
		expect(() => unfoundedGroupNote("resume-admission" as never)).toThrow(
			/Unknown repair verb/,
		);
	});
});

describe("the Python twin — the three recovery heads", () => {
	// The empty-scan head was reworded. Two matrix drivers `^`-anchor on these
	// sentences and report a miss as the refusal, so a rewording that lands on
	// one stack and not the other grades a working surface as broken — on
	// whichever stack was not edited.
	//
	// Both arms where the scan ran now close on `{scan_tail}` over there — the
	// shortfall clause, when the one page the scan reads fell short, and then the
	// sentence naming the next action. It is resolved out of Python's own two
	// pieces rather than out of TypeScript constants, the `{_NO_VERB_HERE}`
	// precedent above: a stack that kept the clause and stopped appending it, or
	// appended it behind a different separator, is exactly what this is for.
	//
	// 🔴 Including the SEPARATOR, which is why Python's own `scan_tail = f"…"`
	// statement is read rather than re-composed here. A version of this block
	// joined the two pieces in TypeScript — `${pyUnscanned} ${pyScanDone}` — so
	// the single space it claimed to pin was a copy the test had written itself,
	// and dropping the space on the Python side alone reddened nothing.
	const pyScanDone = pySource("_SCAN_DONE", /_SCAN_DONE = \(([\s\S]*?)\n\)/);
	const pyUnscanned = (unscanned: number) =>
		pySource(
			"_unscanned_clause",
			/def _unscanned_clause[\s\S]*?\n    return \(\n([\s\S]*?)\n    \)/,
		).replace("{unscanned}", String(unscanned));
	const PY_SCAN_TAIL = pySource(
		"the scan_tail composition",
		/\n    scan_tail = f(.+)/,
	);
	const scanTail = (unscanned?: number) =>
		PY_SCAN_TAIL.replace(
			"{_unscanned_clause(result.unscanned)}",
			unscanned === undefined ? "" : pyUnscanned(unscanned),
		).replace("{_SCAN_DONE}", pyScanDone);
	const arm = (what: string, pattern: RegExp, unscanned?: number) =>
		pySource(what, pattern)
			.replace("{group_ref}", "#ops")
			.replace("{result.ingested}", "2")
			.replace("{scan_tail}", scanTail(unscanned));

	const EMPTY_ARM =
		/if result\.ingested == 0:[\s\S]*?return with_note\(\n([\s\S]*?)\n\s*\)/;
	const INSTALLED_ARM =
		/\n    return with_note\(\n([\s\S]*?)\n    \)\n\n\ndef describe_mls_recovery/;

	it("says the same thing when the scan found nothing", () => {
		expect(
			describeMlsRecovery("#ops", {
				regime: "sender-key",
				ingested: 0,
				retired: false,
			}),
		).toBe(arm("the empty-scan arm", EMPTY_ARM));
	});

	it("says the same thing when it installed keys", () => {
		expect(
			describeMlsRecovery("#ops", {
				regime: "sender-key",
				ingested: 2,
				retired: false,
			}),
		).toBe(arm("the installed arm", INSTALLED_ARM));
	});

	it("names the next action in the same words, on both arms where the scan ran", () => {
		// The g4 defect: the answer ended on a description of state, and a model
		// handed it to its user as if it were what the group said. One stack
		// naming the next action and the other not is the same defect, halved.
		for (const ingested of [0, 2]) {
			expect(
				describeMlsRecovery("#ops", {
					regime: "sender-key",
					ingested,
					retired: false,
				}),
			).toContain(pyScanDone);
		}
	});

	it("states the same shortfall when the scan's one page fell short", () => {
		expect(
			describeMlsRecovery("#ops", {
				regime: "sender-key",
				ingested: 0,
				retired: false,
				unscanned: 136,
			}),
		).toBe(arm("the empty-scan arm", EMPTY_ARM, 136));

		expect(
			describeMlsRecovery("#ops", {
				regime: "sender-key",
				ingested: 2,
				retired: false,
				unscanned: 7,
			}),
		).toBe(arm("the installed arm", INSTALLED_ARM, 7));
	});

	it("says the same thing when this agent's keys were retired", () => {
		expect(
			describeMlsRecovery("#ops", {
				regime: "sender-key",
				ingested: 0,
				retired: true,
			}),
		).toBe(
			arm(
				"the retired arm",
				/if result\.retired:[\s\S]*?return with_note\(\n([\s\S]*?)\n\s*\)/,
			),
		);
	});
});
