/**
 * The reclamation sentence four TypeScript surfaces share.
 *
 * Every expectation here is the exact string the Python twin
 * (`rine-sdk/src/rine/admission_words.py:describe_mls_reclamation`) returns for
 * the same report, minus the leading space it carries because it appends to an
 * admission headline. Two stacks answering the same event with two different
 * sentences is the drift this one implementation stops, so a wording change
 * lands in both files in the same commit — and this file is where a one-sided
 * change is caught.
 */
import { describe, expect, it } from "vitest";
import type { MlsRecoveryResult } from "../src/mls-ops-resync.js";
import {
	MLS_NEVER_FOUNDED_NOTE,
	describeMlsReclamation,
	describeMlsRecovery,
	joinLines,
	mlsInitInFlightSync,
	mlsNeverFoundedSync,
} from "../src/mls-recovery-format.js";

const REPLAYED: MlsRecoveryResult = {
	regime: "mls",
	rung: "replay",
	fromEpoch: 4,
	epoch: 9,
	behind: 5,
	processed: 5,
	evicted: false,
};

describe("describeMlsReclamation", () => {
	it("says nothing when no pass ran", () => {
		expect(describeMlsReclamation(undefined)).toBe("");
	});

	it("reports what it retired, and states who pays for it", () => {
		expect(
			describeMlsReclamation({
				found: 3,
				reclaimed: 2,
				commits: 2,
				epoch: 9,
			}),
		).toBe(
			"Reclaimed 2 of 3 orphaned leaves in 2 commit(s), now at epoch 9;" +
				" each Remove commit is O(N) and is billed to every member.",
		);
	});

	it("distinguishes a clean tree from a pass nobody ran", () => {
		// "nobody asked" and "there was nothing there" are different facts, and
		// only one of them means the tree is clean.
		expect(
			describeMlsReclamation({
				found: 0,
				reclaimed: 0,
				commits: 0,
				epoch: 4,
			}),
		).toBe("Every leaf belongs to a member or to an unanswered invitation.");
	});

	it("passes a refusal through in the pass's own words", () => {
		// The decline detail names the agents that made the orphan set
		// unattributable; summarising it here would drop the only actionable part.
		const detail =
			"Reclaimed nothing: 2 agent(s) this group entitles to a seat publish no" +
			" readable signing key (a, b), so their leaves cannot be told apart from" +
			" an orphan's.";
		expect(
			describeMlsReclamation({
				found: 0,
				reclaimed: 0,
				commits: 0,
				epoch: 4,
				declined: { reason: "identity_unknown", detail },
			}),
		).toBe(detail);
	});

	it("never calls the pass admin-initiated or admin-gated", () => {
		// Posting the Remove commit takes membership and no role beyond
		// it, so any member may run one; the deterrent is the O(N) cost.
		const said = describeMlsReclamation({
			found: 1,
			reclaimed: 1,
			commits: 1,
			epoch: 2,
		});
		expect(said).not.toMatch(/admin-initiated|admin-gated/);
	});
});

describe("describeMlsRecovery", () => {
	it("selects the arm on the regime, not on which fields are present", () => {
		// A sender-key result carries no rung at all. Nothing here may reach it by
		// asking what a result happens to hold — the discriminant is the contract.
		const said = describeMlsRecovery("#ops", {
			regime: "sender-key",
			ingested: 2,
			retired: false,
		});
		expect(said).toContain("installed 2 sender key(s)");
		expect(said).not.toContain("Replayed");
		expect(said).not.toContain("Resynced");
		expect(said).not.toContain("epoch chain to catch up");
	});

	it("says what an installed key does and does not reach", () => {
		// The vocabulary rule: an ingested distribution carries the
		// sender's chain key at the index it was distributed at, and a chain key
		// only ratchets forward. Anything that reads as "you can now read the
		// backlog" is false, and anything that reads as a re-key or a rotation is
		// a forward-secrecy claim this regime does not make.
		const said = describeMlsRecovery("#ops", {
			regime: "sender-key",
			ingested: 1,
			retired: false,
		});
		expect(said).toContain("stays unreadable");
		expect(said).toContain("nothing was committed");
		expect(said).not.toMatch(/re-key|rekey|rotat|heals the group|backlog/i);
	});

	it("tells an empty inbox from a retired one, and only one has a remedy", () => {
		const nothingWaiting = describeMlsRecovery("#ops", {
			regime: "sender-key",
			ingested: 0,
			retired: false,
		});
		const retired = describeMlsRecovery("#ops", {
			regime: "sender-key",
			ingested: 0,
			retired: true,
		});
		expect(nothingWaiting).toContain("nothing new was installed");
		expect(nothingWaiting).toContain("next post to the group");
		// 🔴 It reports the counter, never an inventory of the inbox.
		// `fetchAndIngestPendingSKDistributions` counts what it INSTALLED and
		// reaches zero with distributions still listed — already installed, no
		// server-authenticated sender, a refused envelope, or past its
		// un-paginated `limit: 100`.
		expect(nothingWaiting).not.toContain("none were waiting");
		// 🔴 The head used to open `Recovered group #ops:` on a scan that
		// recovered nothing, and its own next clause said so — a success verb
		// contradicted one sentence later. It names the work that ran instead.
		expect(nothingWaiting).not.toContain("Recovered group");
		expect(nothingWaiting.startsWith("Scanned group #ops for sender keys:")).toBe(
			true,
		);
		expect(retired).toContain("retired here");
		expect(retired).toContain("needs an invitation");
		// 🔴 The gate fails closed, so `retired` also covers a membership read
		// that never got an answer. The sentence must not state the server's
		// verdict as fact, and must not rule out the retry that fixes that case.
		expect(retired).not.toContain("does not name this agent a member");
		expect(retired).toContain("run the sync again");
		expect(retired).not.toBe(nothingWaiting);
	});

	it("tells an operator whether the empty scan was the lever they wanted", () => {
		// 🔴 The empty arm was the only one of the three with no forward half: the
		// retired arm ends on a next step, the installed arm on what is readable
		// now, and this one ended on a clause about keys that have not been minted
		// yet — which reads as "nothing further is available". An operator runs
		// this verb BECAUSE something will not open, so the answer has to say that
		// the sync moved nothing and is not what is holding the read.
		const said = describeMlsRecovery("#ops", {
			regime: "sender-key",
			ingested: 0,
			retired: false,
		});

		expect(said).toContain("local state is unchanged");
		expect(said).toContain("opened here before opens now");
		// 🔴 And it stops there. The forward half used to go on to rule the
		// scan out as the lever — "whatever does not is not waiting on a key
		// this scan could have installed" — which the zero cannot support: a
		// distribution past the un-paginated hundred-row fetch IS waiting on
		// exactly such a key, and no later sync reaches it either, so the
		// sentence sent that operator to wait for a post instead.
		expect(said).not.toContain("this scan could have installed");
		// It states that nothing changed — never that anything was repaired.
		expect(said).not.toMatch(/re-key|rekey|rotat|heals the group|backlog/i);
	});

	it("names the next action once the scan has run, on both arms that ran one", () => {
		// 🔴 The g4 defect, measured twice at 0.00: the sync succeeded, and the
		// model handed this very sentence to its user AS IF IT WERE WHAT THE GROUP
		// SAID, never reading the group. So the answer says both halves — that it
		// is not a message from the group, and what to read instead.
		for (const ingested of [0, 3]) {
			const said = describeMlsRecovery("#ops", {
				regime: "sender-key",
				ingested,
				retired: false,
			});
			expect(said).toContain("This sync is finished");
			expect(said).toContain("nothing here is a message from the group");
			expect(said).toContain("read the group's own messages next");
		}
	});

	it("does not send a retired agent to messages it has just been refused", () => {
		// Nothing was installed there and nothing could be, so the group's messages
		// are the same refusal one step further on. That arm has its own next step.
		const retired = describeMlsRecovery("#ops", {
			regime: "sender-key",
			ingested: 0,
			retired: true,
		});
		expect(retired).not.toContain("read the group's own messages next");
	});

	it("states the shortfall when the scan's one page did not cover the inbox", () => {
		// The scan reads `limit: 100` and follows no cursor. Past that page keys
		// are never installed and the messages they cover stay sealed, and the
		// answer used to report that partial pass as a whole one. The number is the
		// server's own `total` minus the page, so it costs no extra request.
		const short = describeMlsRecovery("#ops", {
			regime: "sender-key",
			ingested: 0,
			retired: false,
			unscanned: 136,
		});

		expect(short).toContain("136 older sender-key distribution(s)");
		// 🔴 It states the count and then states what the count is NOT. The listing
		// holds every distribution this agent was ever sent, so most of what is
		// behind that page is material installed long ago — the first version
		// called those rows unopened and hinted a needed key was among them, which
		// was the inbox-inventory claim this arm was reworded twice for, arriving
		// on every healthy sync an agent past a hundred distributions ever ran.
		expect(short).toContain("a count of rows this pass did not read");
		expect(short).toContain("not a count of keys it is missing");
		expect(short).not.toContain("stayed unopened");
		expect(short).not.toMatch(/unreadable because|are missing|will not open/);
	});

	it("says nothing about a shortfall when there is none", () => {
		for (const ingested of [0, 3]) {
			for (const unscanned of [undefined, 0]) {
				const said = describeMlsRecovery("#ops", {
					regime: "sender-key",
					ingested,
					retired: false,
					unscanned,
				});
				expect(said).not.toContain("did not read");
				expect(said).not.toContain("older sender-key distribution(s)");
			}
		}
	});

	it("keeps each clause in its place when a shortfall and a note meet", () => {
		// The three-clause composition, which nothing asserted: the shortfall
		// clause, then the next action, then the note on its own line.
		//
		// 🔴 The note ends on the founding verb and lands AFTER the sentence
		// sending the reader to the group's messages. That order is deliberate and
		// it is the ordering the Python twin composes; it is pinned here so a
		// change to it is a decision somebody takes rather than a side effect of
		// appending one more clause.
		const warned = mlsNeverFoundedSync("tool-group-reclaim");
		const said = describeMlsRecovery("#ops", {
			regime: "sender-key",
			ingested: 2,
			retired: false,
			unscanned: 136,
			mlsNeverFoundedNote: warned,
		});

		const [head, ...rest] = said.split("\n");
		expect(rest.join("\n")).toBe(warned);
		expect(head?.indexOf("136 older sender-key distribution(s)")).toBeLessThan(
			head?.indexOf("This sync is finished") ?? -1,
		);
		expect(head?.endsWith("read the group's own messages next.")).toBe(true);
	});

	it("never reports an MLS eviction for a group that has no ratchet tree", () => {
		// An eviction is an MLS Remove commit. An open group's removal is the
		// server's delivery filter, so appending that sentence here would report
		// an event of a kind this regime cannot produce.
		for (const ingested of [0, 3]) {
			for (const retired of [false, true]) {
				const said = describeMlsRecovery("#ops", {
					regime: "sender-key",
					ingested,
					retired,
				});
				expect(said).not.toContain("removed from the group by a commit");
			}
		}
	});

	it("leaves the MLS arms saying exactly what they said before", () => {
		expect(describeMlsRecovery("#ops", REPLAYED)).toBe(
			"Replayed 5 commit(s) for group #ops: it was behind by 5 epoch(s), and" +
				" is now at epoch 9. Nothing was committed.",
		);
		expect(describeMlsRecovery("#ops", { ...REPLAYED, evicted: true })).toContain(
			"removed from the group by a commit it just replayed",
		);
	});
});

describe("mlsInitInFlightSync", () => {
	it("names the group, the wait and the fact that it clears itself", () => {
		const said = mlsInitInFlightSync("#ops");
		expect(said).toContain("#ops");
		expect(said).toContain("still founding its MLS state");
		expect(said).toContain("run the sync again");
	});

	it("promises neither an epoch chain nor sender keys, because it has neither", () => {
		// The state both arms of `recoverGroup` would otherwise get wrong: no MLS
		// latch yet, and not a sender-key group either.
		const said = mlsInitInFlightSync("#ops");
		expect(said).toContain("no epoch chain to catch up with yet");
		expect(said).toContain("no sender keys to install");
	});
});

describe("mlsNeverFoundedSync", () => {
	it("says what the group was created for, and what it is doing instead", () => {
		const said = mlsNeverFoundedSync();
		expect(said).toContain("was created to run MLS");
		expect(said).toContain("ratchet tree was never founded");
		expect(said).toContain("sealed with sender keys");
	});

	it("claims neither a failure nor an unusable group, because neither is knowable", () => {
		// A founding that died and one that was never attempted leave identical
		// rows, and the group carries messages fine — on sender keys. Both are
		// claims an earlier draft of this sentence made and could not support.
		const said = mlsNeverFoundedSync();
		expect(said).not.toContain("failed");
		expect(said).not.toContain("cannot carry");
	});

	it("names no group, because it is appended to a sentence that already did", () => {
		// The `MLS_EVICTED_BY_COMMIT` shape. A second identifier in one answer is
		// what makes two stacks' output differ, and this sentence is rendered by
		// two callers that name the group in different words.
		expect(mlsNeverFoundedSync()).toBe(
			MLS_NEVER_FOUNDED_NOTE +
				" No verb on this surface founds it: a member has to found the group's" +
				" MLS state before this sync has anything to catch up.",
		);
	});

	it("names no verb unless the surface said it has one", () => {
		expect(mlsNeverFoundedSync()).toContain(
			"No verb on this surface founds it",
		);
		expect(mlsNeverFoundedSync()).not.toContain("resume");
	});

	it("names the founding verb in each surface's own spelling", () => {
		// One operation, four spellings. Every one of them is a verb this lane
		// verified reaches the founding path on the surface that passes it —
		// naming a verb that refuses is what `notAnMlsGroupResume` exists to stop.
		expect(mlsNeverFoundedSync("cli-resume-admission")).toContain(
			"Run rine group resume-admission on it to found its MLS state",
		);
		expect(mlsNeverFoundedSync("sdk-resume-admission")).toContain(
			"Run resume_admission() on it to found its MLS state",
		);
		expect(mlsNeverFoundedSync("tool-group-reclaim")).toContain(
			"Run rine_group_reclaim on it to found its MLS state",
		);
	});

	it("refuses a repair word it has no clause for, instead of rendering one", () => {
		// 🔴 This is a published export on `@rine-network/core`, so a caller
		// outside TypeScript's reach can hand it anything. `Record` lookup plus
		// string concatenation put the literal text `undefined` at the end of an
		// operator's warning — a near-miss of the union ("resume-admission" for
		// "sdk-resume-admission") was all it took — while the Python twin raised
		// on the same input. One event, two behaviours, and the silent one was the
		// one that reached a user.
		expect(() =>
			mlsNeverFoundedSync("resume-admission" as never),
		).toThrow(/Unknown repair verb/);
		expect(() => mlsNeverFoundedSync("resume-admission" as never)).toThrow(
			/sdk-resume-admission/,
		);
	});

	it("keeps one head sentence under every repair, so only the remedy differs", () => {
		for (const repair of [
			"cli-resume-admission",
			"sdk-resume-admission",
			"tool-group-reclaim",
			"none",
		] as const) {
			expect(
				mlsNeverFoundedSync(repair).startsWith(MLS_NEVER_FOUNDED_NOTE),
			).toBe(true);
		}
	});
});

describe("describeMlsRecovery — the never-founded warning rides on the answer", () => {
	const NOTE = mlsNeverFoundedSync("cli-resume-admission");

	it("appends the warning to each of the three sender-key answers", () => {
		const answers = [
			{ regime: "sender-key", ingested: 3, retired: false },
			{ regime: "sender-key", ingested: 0, retired: false },
			{ regime: "sender-key", ingested: 0, retired: true },
		] as const;

		for (const answer of answers) {
			const said = describeMlsRecovery("#ops", {
				...answer,
				mlsNeverFoundedNote: NOTE,
			});
			expect(said.split("\n")).toHaveLength(2);
			expect(said.split("\n")[1]).toBe(NOTE);
		}
	});

	it("🔴 leaves every head sentence byte-identical, because two drivers anchor on them", () => {
		// `scripts/mls-matrix/driver_framework_ts_admin.mjs` and
		// `scripts/mls-matrix/container_admin.py` decide whether the surface
		// answered at all by `^`-anchored regexes on these three heads. A reworded
		// or prefixed head is reported as the refusal — a success graded RED.
		const answers = [
			{ regime: "sender-key", ingested: 3, retired: false },
			{ regime: "sender-key", ingested: 0, retired: false },
			{ regime: "sender-key", ingested: 0, retired: true },
		] as const;

		for (const answer of answers) {
			const plain = describeMlsRecovery("#ops", answer);
			const warned = describeMlsRecovery("#ops", {
				...answer,
				mlsNeverFoundedNote: NOTE,
			});
			expect(warned.startsWith(`${plain}\n`)).toBe(true);
		}
	});

	it("says nothing extra on a group that is simply a sender-key group", () => {
		const said = describeMlsRecovery("#ops", {
			regime: "sender-key",
			ingested: 1,
			retired: false,
		});

		expect(said).not.toContain("never founded");
		expect(said.split("\n")).toHaveLength(1);
	});
});

/**
 * The seam four sites used to hand-roll, and the case none of them asserted.
 *
 * The recorded failure mode of a hand-rolled copy is getting the empty case
 * backwards, which emits a LEADING BLANK LINE into an operator's answer — and
 * `driver_framework_ts_admin.mjs` and `container_admin.py` match these answers'
 * heads with `^`-anchored regexes, so a blank first line is read as the surface
 * refusing: a successful recovery graded as a broken one. Nothing asserted it
 * before this block. Its Python twin is `TestJoinLines` in
 * `rine-sdk/tests/test_format.py`.
 */
describe("joinLines", () => {
	it("returns the head alone when there is no tail", () => {
		expect(joinLines("head", "")).toBe("head");
		expect(joinLines("head", undefined)).toBe("head");
	});

	it("returns the tail alone, with NO leading newline, when there is no head", () => {
		expect(joinLines("", "tail")).toBe("tail");
	});

	it("answers empty for two empty halves", () => {
		expect(joinLines("", "")).toBe("");
		expect(joinLines("", undefined)).toBe("");
	});

	it("puts exactly one newline between two present halves", () => {
		expect(joinLines("head", "tail")).toBe("head\ntail");
	});

	it("never opens or closes an answer on a blank line", () => {
		for (const first of ["", "head"]) {
			for (const second of ["", undefined, "tail"]) {
				const said = joinLines(first, second);
				expect(said.startsWith("\n")).toBe(false);
				expect(said.endsWith("\n")).toBe(false);
			}
		}
	});

	it("leaves both halves byte-identical — it joins, it never normalises", () => {
		expect(joinLines("head.", " tail ")).toBe("head.\n tail ");
	});
});
