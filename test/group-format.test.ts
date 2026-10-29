/**
 * `groupEncryption` — the answer to "what is this group encrypted with".
 *
 * 🔴 This suite exists because there was none. `groupEncryption` is read by the
 * CLI's group table and `--json`, by the MCP inspect verb, and by
 * `retirementMessage`, and it decided all of it from `enrollment_policy` alone —
 * which is one column answering for FOUR different groups. Three of them were
 * told they ran post-quantum MLS while their messages carried `sender-key-v1`.
 *
 * So every row a real group can be in is enumerated here, and each asserts the
 * WHOLE object: a truth table with a row missing is how the four collapsed into
 * one in the first place, and a `toContain` on the summary would have passed on
 * every one of the wrong answers.
 */
import { describe, expect, it } from "vitest";
import type { GroupRead } from "../src/api-types.js";
import { MLS_CIPHER_SUITE_XWING } from "../src/crypto/mls.js";
import { encryptionLine, groupEncryption } from "../src/group-format.js";
import type { MlsAdmissionResult } from "../src/mls-admission.js";
import { emptyReport } from "../src/mls-escrow-report.js";
import {
	MLS_NEVER_FOUNDED_NOTE,
	unfoundedGroupNote,
} from "../src/mls-recovery-format.js";

/** A suite value this client has no name for. */
const UNKNOWN_SUITE = 0x0001;

function group(overrides: Partial<GroupRead> = {}): GroupRead {
	return {
		id: "88888888-8888-8888-8888-888888888888",
		name: "standup",
		handle: "#standup@acme.rine.network",
		description: null,
		enrollment_policy: "closed",
		visibility: "private",
		isolated: false,
		vote_duration_hours: 24,
		member_count: 3,
		created_at: "2026-08-01T00:00:00Z",
		mls_enabled: true,
		mls_group_id: "mls-latch-abc",
		mls_pending: false,
		mls_cipher_suite: MLS_CIPHER_SUITE_XWING,
		...overrides,
	} as GroupRead;
}

/** A group created to run MLS whose ratchet tree was never founded. */
const NEVER_FOUNDED = group({
	mls_group_id: null,
	mls_pending: false,
	mls_cipher_suite: null,
});

/** What a founding that LANDED returned: one commit, the creator's own leaf. */
const ADMISSION: MlsAdmissionResult = {
	epoch: 1,
	commits: 1,
	added: 1,
	outcomes: [
		{
			agentId: "11111111-1111-1111-1111-111111111111",
			status: "added",
		},
	],
	escrow: emptyReport(),
};

describe("groupEncryption — a founded MLS group", () => {
	it("reports the suite the server actually recorded", () => {
		expect(groupEncryption(group())).toEqual({
			regime: "mls",
			version: "mls-v1",
			post_quantum: true,
			pending: false,
			mls_never_founded: false,
			summary:
				"MLS (RFC 9420) on rine's post-quantum X-Wing ciphersuite.",
		});
	});

	it("shows a suite it does not know by number, never post-quantum and never labelled", () => {
		const unknown = groupEncryption(
			group({ mls_cipher_suite: UNKNOWN_SUITE }),
		);

		expect(unknown.post_quantum).toBe(false);
		expect(unknown.summary).toBe("MLS (RFC 9420) on ciphersuite 0x0001.");
		expect(unknown.summary).not.toMatch(/classical/i);
		expect(unknown.regime).toBe("mls");
	});
});

describe("groupEncryption — a group still founding its tree", () => {
	// The init window. `mls_group_id` has not latched, but the server refuses a
	// sender-key send into this group, so `mls-v1` really is what its messages
	// will carry and there is nothing else it could be carrying meanwhile.
	const inFlight = group({ mls_group_id: null, mls_pending: true });

	it("is an MLS group with the tree still pending", () => {
		expect(groupEncryption(inFlight)).toEqual({
			regime: "mls",
			version: "mls-v1",
			post_quantum: true,
			pending: true,
			mls_never_founded: false,
			summary:
				"MLS (RFC 9420) on rine's post-quantum X-Wing ciphersuite." +
				" The group's ratchet tree is not founded yet.",
		});
	});

	it("takes the one suite rine speaks while the group has none", () => {
		// A group still founding carries no `mls_cipher_suite`.
		const noSuite = groupEncryption({ ...inFlight, mls_cipher_suite: null });

		expect(noSuite.post_quantum).toBe(true);
		expect(noSuite.pending).toBe(true);
	});
});

describe("groupEncryption — a tree that was never founded", () => {
	it("reports the sender keys it runs AND the MLS it has not got", () => {
		// 🔴 The row this whole change is about. Before it, every field below was
		// its opposite: `regime: "mls"`, `version: "mls-v1"`, `post_quantum: true`
		// — on a group whose every message carries `sender-key-v1`. `version` is
		// documented as the `encryption_version` the messages carry, so that was
		// not an approximation but a straight falsehood.
		expect(groupEncryption(NEVER_FOUNDED)).toEqual({
			regime: "sender-key",
			version: "sender-key-v1",
			post_quantum: false,
			pending: false,
			mls_never_founded: true,
			summary: `Sender Keys — NOT post-quantum. ${unfoundedGroupNote()}`,
		});
	});

	it("names the caller's own founding verb when the caller has one", () => {
		// One operation, spelled differently per surface. The CLI can act on this
		// answer — `rine group resume-admission` branches to the init on an
		// unlatched group — so the CLI's copy of the sentence says so.
		const said = groupEncryption(
			NEVER_FOUNDED,
			"cli-resume-admission",
		).summary;

		expect(said).toContain(MLS_NEVER_FOUNDED_NOTE);
		expect(said).toContain(
			"Run rine group resume-admission on it to found its MLS state.",
		);
	});

	it("names no verb, rather than somebody else's, on a surface that has none", () => {
		// 🔴 `"none"` is an answer and not a silence: six surfaces have no verb
		// that founds a group, and the sentence they get says so. Naming a verb
		// that refuses is the failure the repair word exists to prevent.
		const said = groupEncryption(NEVER_FOUNDED).summary;

		expect(said).toContain("No verb on this surface founds it");
		expect(said).not.toContain("resume");
		expect(said).not.toContain("rine_group_reclaim");
	});

	it("never tells a reader to repeat a sync nobody ran", () => {
		// The reason this clause comes from its own table. Every clause the SYNC
		// renders ends on one — "then run the sync again", "before this sync has
		// anything to catch up" — and here nobody has run a sync at all.
		for (const repair of [
			"cli-resume-admission",
			"sdk-resume-admission",
			"tool-group-reclaim",
			"none",
		] as const) {
			expect(groupEncryption(NEVER_FOUNDED, repair).summary).not.toContain(
				"sync",
			);
		}
	});

	it("says the same thing the sync verb says, to the byte", () => {
		// Two surfaces, one group, one sentence: `rine group show` calling this
		// group post-quantum MLS while `rine group sync` called it sender-key is
		// the contradiction this row closes. The shared constant is what keeps
		// them from drifting apart again.
		expect(groupEncryption(NEVER_FOUNDED).summary).toContain(
			MLS_NEVER_FOUNDED_NOTE,
		);
	});

	it("does not call the group broken, frozen, or unable to carry a message", () => {
		// 🔴 All three were said, and all three are false: the server does not
		// freeze this group, `POST /messages` succeeds on it, and its send path
		// mints and fans out sender keys. The defect is a silent downgrade.
		const said = groupEncryption(NEVER_FOUNDED).summary;

		expect(said).not.toMatch(/broken|frozen|failed|cannot carry|holds no keys/i);
	});
});

describe("groupEncryption — a founding this client watched land", () => {
	// 🔴 The row is byte for byte {@link NEVER_FOUNDED}, and that is the whole
	// difficulty: `groups.create` mints the group BEFORE its MLS init, so the row
	// a create holds after a refused confirming re-read carries no latch, no
	// pending flag and no suite. Every predicate reads it as a tree that was
	// never founded. The admission is what the founding returned and exists
	// nowhere else — the same field, asked in the same place, as its Python twin
	// `rine.format.group_encryption` and as `createdGroupMls`.
	const LANDED = { ...NEVER_FOUNDED, mlsAdmission: ADMISSION };

	it("reports the MLS the founding just gave the group", () => {
		expect(groupEncryption(LANDED, "cli-resume-admission")).toEqual({
			regime: "mls",
			version: "mls-v1",
			post_quantum: true,
			pending: false,
			mls_never_founded: false,
			summary: "MLS (RFC 9420) on rine's post-quantum X-Wing ciphersuite.",
		});
	});

	it("does not send the operator to found a tree it has just founded", () => {
		// The defect, stated as the sentence the operator read: `rine group create`
		// told them the ratchet tree was never founded and named the verb that
		// founds one, seconds after founding it, and `--json` said
		// `mls_never_founded: true` about the same group.
		const said = groupEncryption(LANDED, "cli-resume-admission").summary;

		expect(said).not.toContain(MLS_NEVER_FOUNDED_NOTE);
		expect(said).not.toContain("resume-admission");
		expect(groupEncryption(LANDED).mls_never_founded).toBe(false);
	});

	it("calls the tree founded, not still founding", () => {
		// The other answer this must not give. An init in flight is `pending: true`
		// and says the tree is not founded yet; this founding's commit landed, so
		// the group is neither pending nor waiting on anything.
		const said = groupEncryption(LANDED).summary;

		expect(groupEncryption(LANDED).pending).toBe(false);
		expect(said).not.toContain("not founded yet");
	});

	it("takes the one suite rine speaks, the row having none to report", () => {
		// Same fallback as the group still founding its tree: the row predates
		// the init, so it carries no `mls_cipher_suite`.
		expect(groupEncryption(LANDED).post_quantum).toBe(true);
	});

	it("leaves the row-only answer exactly where it was without one", () => {
		// 🔴 The regression this arm most plausibly causes. Every read path — the
		// MCP inspect verb, `rine group get`, `retirementMessage` — passes a row
		// that carries no admission and must keep the never-founded answer, which
		// is the one this whole file exists to protect.
		expect(groupEncryption({ ...NEVER_FOUNDED, mlsAdmission: undefined })).toEqual(
			groupEncryption(NEVER_FOUNDED),
		);
		expect(groupEncryption(NEVER_FOUNDED).mls_never_founded).toBe(true);
	});

	it("reaches the line an operator reads, not just the object", () => {
		expect(encryptionLine(LANDED, "cli-resume-admission")).toBe(
			"Encryption: MLS (RFC 9420) on rine's post-quantum X-Wing ciphersuite.",
		);
	});
});

describe("groupEncryption — the groups that were always sender-key", () => {
	it("leaves an open group exactly where it was", () => {
		// 🔴 The regression this change most plausibly causes. An open group
		// carries `mls_enabled: true` from birth and has the same null latch as a
		// never-founded one, so an answer keyed off the latch alone would tell
		// every open group it was created to run MLS and never got it.
		const open = groupEncryption(
			group({
				enrollment_policy: "open",
				mls_group_id: null,
				mls_cipher_suite: null,
			}),
		);

		expect(open).toEqual({
			regime: "sender-key",
			version: "sender-key-v1",
			post_quantum: false,
			pending: false,
			mls_never_founded: false,
			summary: expect.stringContaining("open-enrollment groups by design"),
		});
		expect(open.summary).not.toContain(MLS_NEVER_FOUNDED_NOTE);
	});

	it("answers for a closed group that opted out of MLS at create time", () => {
		// The row nobody named: `enrollment_policy: "closed"` with
		// `mls_enabled: false` is legal on the wire and this group really is a
		// sender-key group. Reading the policy alone called it post-quantum MLS,
		// and `groupMlsNeverFounded` is false for it — so it needs its own arm and
		// not the warning.
		const optedOut = groupEncryption(
			group({
				mls_enabled: false,
				mls_group_id: null,
				mls_cipher_suite: null,
			}),
		);

		expect(optedOut).toEqual({
			regime: "sender-key",
			version: "sender-key-v1",
			post_quantum: false,
			pending: false,
			mls_never_founded: false,
			summary: expect.stringContaining("NOT post-quantum"),
		});
		expect(optedOut.summary).not.toContain(MLS_NEVER_FOUNDED_NOTE);
	});

	it("blames no enrollment policy for the regime, because two policies land here", () => {
		// The summary used to say a group runs sender keys BECAUSE its enrollment
		// is open. A closed group that opted out of MLS reaches the same arm, so
		// that reason is now one example rather than the rule.
		const said = groupEncryption(
			group({ mls_enabled: false, mls_group_id: null }),
		).summary;

		expect(said).toContain("whenever it has no ratchet tree");
	});

	it("names the closed-without-MLS group too, as its Python twin does", () => {
		// 🔴 Twin drift, caught by an audit: this summary explained the state by
		// open enrollment alone while `rine.format._ENCRYPTION_WORDS["sender-key"]`
		// named both ways to be here. On a CLOSED `--no-mls` group the operator was
		// told their private group's encryption is explained by who can join it —
		// a misstatement about the policy, on the one row with no open enrollment
		// to blame. Both stacks now state both ways and the removal fact.
		const said = groupEncryption(
			group({ mls_enabled: false, mls_group_id: null }),
		).summary;

		expect(said).toContain("open-enrollment groups by design");
		expect(said).toContain("a closed group created without MLS too");
		expect(said).toContain("rine's delivery filter");
	});

	it("lets the latch outrank the intent flag, because the latch is the traffic", () => {
		// `mls_enabled: false` on a group that HAS a ratchet tree is a
		// contradiction the server should never write, and if it ever does, the
		// latch is the half that says what the messages carry. This is the reason
		// the arms are the shared predicates rather than a reading of
		// `mls_enabled` first.
		expect(groupEncryption(group({ mls_enabled: false })).regime).toBe("mls");
	});
});

describe("encryptionLine", () => {
	it("is the summary an operator reads, with no second opinion in it", () => {
		expect(encryptionLine(NEVER_FOUNDED)).toBe(
			`Encryption: ${groupEncryption(NEVER_FOUNDED).summary}`,
		);
	});

	it("carries the caller's repair verb through to the line it prints", () => {
		// The CLI prints this line and can act on it; a line that dropped the verb
		// on its way through would send the one caller who has a remedy looking
		// for it somewhere else.
		expect(encryptionLine(NEVER_FOUNDED, "cli-resume-admission")).toBe(
			`Encryption: ${groupEncryption(NEVER_FOUNDED, "cli-resume-admission").summary}`,
		);
		expect(encryptionLine(NEVER_FOUNDED, "cli-resume-admission")).toContain(
			"Run rine group resume-admission",
		);
	});
});
