/**
 * The not-a-member clause, pinned in the package that owns it.
 *
 * This is the TypeScript half of a three-way pin. The other two are the
 * server's `rine.api.group_member_words` and the Python SDK's
 * `rine.group_words`, and `tests/test_client-server-contract_group0.py`
 * compares all three by parsing this file's source. That gate is what stops the
 * copies drifting; what this file adds is the reason a surface may rely on the
 * clause at all, stated where a reader of `rine-core` will find it.
 *
 * The shape matters as much as the value: the contract gate reads the constant
 * as a single string literal, so it must stay one — not a template literal, not
 * a concatenation, and not assembled from parts.
 */

import { describe, expect, it } from "vitest";

// From the PACKAGE ROOT, never from the declaring module, for the reason
// `vote-words.test.ts` states: the CLI and the MCP server import
// `@rine-network/core`, so a constant missing from the barrel is one they could
// only re-declare — which is the situation this module exists to end.
import {
	ACTING_AGENT_HEADER,
	NOT_A_MEMBER_CLAUSE,
	SEATED_SIBLING_CLAUSE,
	namesASeatedSibling,
	unseatedGroupSendRefusal,
} from "../src/index.js";

/** The refusals the server actually sends, as `group_member_words` builds them. */
const ARM_ONE_SIBLING =
	"agent ops-bot is not a member of this group; your agent sales-bot is" +
	" — retry with X-Rine-Agent: sales@acme.rine.network";
const ARM_NO_SIBLING =
	"agent ops-bot is not a member of this group, and no agent of your org is" +
	" — a member must invite one of your agents before this org can act in it";
const ARM_SEVERAL_SIBLINGS =
	"agent ops-bot is not a member of this group; these agents of yours are" +
	" — retry with X-Rine-Agent set to one of them:\n" +
	"  - sales-bot (sales@acme.rine.network)";
const ARM_CLOSED_NO_ADMIN =
	"this group's enrollment is closed and no agent of your org is an admin of it" +
	" — an existing admin must issue the invitation";

describe("NOT_A_MEMBER_CLAUSE", () => {
	it("is the phrase the server puts in every arm of the refusal", () => {
		expect(NOT_A_MEMBER_CLAUSE).toBe("is not a member of this group");
	});

	it("matches each arm as a substring, because the rest of the sentence varies", () => {
		// Equality would fail on every real refusal: the arms name the acting
		// agent and whichever sibling holds a seat, so no two are alike. A
		// surface discriminating on this must use `includes`.
		expect(ARM_ONE_SIBLING.includes(NOT_A_MEMBER_CLAUSE)).toBe(true);
		expect(ARM_NO_SIBLING.includes(NOT_A_MEMBER_CLAUSE)).toBe(true);
		expect(ARM_ONE_SIBLING).not.toBe(NOT_A_MEMBER_CLAUSE);
	});

	it("does not match the closed-group admin refusal", () => {
		// A distinct refusal on purpose: when a closed group's admin check
		// fails there is no sibling to name and the remedy is not a header
		// change, so a surface must not offer one. The membership gate runs
		// first, so only a SEATED non-admin ever reads this sentence.
		expect(ARM_CLOSED_NO_ADMIN.includes(NOT_A_MEMBER_CLAUSE)).toBe(false);
	});
});

describe("namesASeatedSibling", () => {
	it("names the header the server tells the caller to set", () => {
		// The clause is one literal because the cross-stack gate parses it as
		// one; this is what binds the header inside it to the constant every
		// other part of this package sends.
		expect(SEATED_SIBLING_CLAUSE.endsWith(ACTING_AGENT_HEADER)).toBe(true);
	});

	it("is true of both arms that name an agent to act as", () => {
		expect(namesASeatedSibling(ARM_ONE_SIBLING)).toBe(true);
		expect(namesASeatedSibling(ARM_SEVERAL_SIBLINGS)).toBe(true);
	});

	it("is FALSE of the arm where no agent of the org is seated", () => {
		// The arm a genuinely evicted agent reads: same family, no remedy the
		// caller can perform, and nobody to retry as. A surface that treated
		// it as a sibling refusal would suppress the eviction explanation
		// exactly where eviction is what happened.
		expect(ARM_NO_SIBLING.includes(NOT_A_MEMBER_CLAUSE)).toBe(true);
		expect(namesASeatedSibling(ARM_NO_SIBLING)).toBe(false);
	});

	it("is false of a refusal from another family", () => {
		expect(namesASeatedSibling(ARM_CLOSED_NO_ADMIN)).toBe(false);
		expect(namesASeatedSibling("Access denied")).toBe(false);
	});
});

/** The one call this stack composes the refusal for, spelled once. */
const REFUSED = {
	group: "ops@acme.rine.network",
	agent: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
};

/** The clause every arm opens with, and the one every arm closes with. */
const HEAD =
	"Refusing to send to ops@acme.rine.network: agent" +
	" a1b2c3d4-e5f6-7890-abcd-ef1234567890 holds no seat in that group.";
const TAIL = "Nothing was sent, and no sender key was distributed.";

describe("unseatedGroupSendRefusal", () => {
	it("names the group, the one seated agent of the caller's org, and the move", () => {
		expect(
			unseatedGroupSendRefusal({
				...REFUSED,
				seated: ["sales@acme.rine.network"],
			}),
		).toBe(
			`${HEAD} Agents of your org seated there: sales@acme.rine.network.` +
				" Send this message again as one of them: the acting agent is chosen" +
				" with --agent on the rine CLI, agent on every other surface." +
				` ${TAIL}`,
		);
	});

	it("lists every seated agent when the caller has more than one", () => {
		expect(
			unseatedGroupSendRefusal({
				...REFUSED,
				seated: ["sales@acme.rine.network", "billing@acme.rine.network"],
			}),
		).toBe(
			"Refusing to send to ops@acme.rine.network: agent" +
				" a1b2c3d4-e5f6-7890-abcd-ef1234567890 holds no seat in that group." +
				" Agents of your org seated there: sales@acme.rine.network," +
				" billing@acme.rine.network. Send this message again as one of them:" +
				" the acting agent is chosen with --agent on the rine CLI, agent on" +
				" every other surface. Nothing was sent, and no sender key was" +
				" distributed.",
		);
	});

	it("says an empty list means nobody to act as, and asks for an invitation", () => {
		expect(unseatedGroupSendRefusal({ ...REFUSED, seated: [] })).toBe(
			`${HEAD} No agent of your org holds a seat there either, so there is` +
				" nobody to send as: a member must invite one of your agents before" +
				` this org can post to the group. ${TAIL}`,
		);
	});

	it("says a missing list is a missing answer, and claims no seat either way", () => {
		// `null` is not the empty array: an agent list this client could not read
		// says nothing about whether the org holds a seat, so this arm may not
		// print the "nobody to send as" verdict the empty one earns.
		const unknown = unseatedGroupSendRefusal({ ...REFUSED, seated: null });
		expect(unknown).toBe(
			`${HEAD} rine could not read your org's agent list, so it cannot say` +
				" which of your agents is seated there: read the group's members and" +
				` send again as one of yours that is listed. ${TAIL}`,
		);
		expect(unknown).not.toContain("nobody to send as");
	});

	it("🔴 satisfies NEITHER cross-stack predicate, on any arm", () => {
		// The constraint this refusal is built around. `NOT_A_MEMBER_CLAUSE` is a
		// discriminator two stacks branch on — `rine-mcp`'s eviction re-wording
		// through `namesASeatedSibling`, and the three Python wrappers through
		// `rine.group_words.is_not_a_member` — and both were written about a
		// refusal the SERVER sends. A client-composed sentence carrying the phrase
		// would claim those branches with every suite green, which is why this
		// refusal says "holds no seat" instead.
		for (const seated of [["sales@acme.rine.network"], [], null]) {
			const refusal = unseatedGroupSendRefusal({ ...REFUSED, seated });
			expect(refusal.includes(NOT_A_MEMBER_CLAUSE)).toBe(false);
			expect(refusal.includes(SEATED_SIBLING_CLAUSE)).toBe(false);
			expect(namesASeatedSibling(refusal)).toBe(false);
		}
	});
});
