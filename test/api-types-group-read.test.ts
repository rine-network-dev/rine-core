/**
 * Which group-row fields a reader may find missing, and which it may not.
 *
 * They are compile-time-only facts here — `rine-core` types raw server JSON
 * through `as GroupRead` casts and validates none of it at runtime, so a
 * runtime assertion would measure the fixture and nothing else. **The
 * assertions are therefore the `@ts-expect-error` directives below.** A test
 * that passes cannot demonstrate a type error; what demonstrates it is `tsc`
 * failing with "Unused '@ts-expect-error' directive" the moment a field is
 * dropped, softened, or hardened.
 *
 * `conversation_id` is REQUIRED: the server emits it on all four `GroupRead`
 * routes even when the value is `null`.
 *
 * `member_agent_ids` and `is_own_org` are OPTIONAL, and that is not a softer
 * version of the same claim — it is the release order written into the type.
 * The server deploys before the clients, so a current client talking to a
 * deployment that predates those two fields gets no key at all, and
 * `undefined` ("this build cannot tell you") is a different fact from `[]`/
 * `false` ("none of yours"). Every renderer guards accordingly; these
 * directives are what stops a later reader deleting a guard as dead code,
 * because an unguarded read is the one thing that must not compile.
 */

import { describe, expect, it } from "vitest";
import type { GroupMemberRead, GroupRead } from "../src/api-types.js";

const BASE = {
	id: "33333333-3333-4333-8333-333333333333",
	name: "dev",
	handle: "#dev@acme.rine.network",
	description: null,
	enrollment_policy: "closed",
	visibility: "private",
	isolated: false,
	vote_duration_hours: 72,
	member_count: 1,
	created_at: "2026-04-11T12:00:00Z",
	member_agent_ids: [],
};

const MEMBER_BASE = {
	id: "44444444-4444-4444-8444-444444444444",
	group_id: "33333333-3333-4333-8333-333333333333",
	agent_id: "55555555-5555-4555-8555-555555555555",
	role: "member",
	joined_at: "2026-04-11T12:00:00Z",
};

describe("GroupRead.conversation_id", () => {
	it("cannot be omitted — a group row always states its thread, or null", () => {
		// @ts-expect-error the key is always emitted, so omitting it is
		// the defect. Softening this to `conversation_id?` makes this directive
		// unused and fails the build.
		const omitted: GroupRead = { ...BASE };

		// Both arms of the field, and only these two. `null` is a fact —
		// nothing has been said in the group yet — never an error.
		const silent: GroupRead = { ...BASE, conversation_id: null };
		const spoken: GroupRead = {
			...BASE,
			conversation_id: "66666666-6666-4666-8666-666666666666",
		};

		// The directive above is the assertion; this keeps the three bindings
		// live so none of them is elided.
		expect([omitted, silent, spoken]).toHaveLength(3);
	});
});

describe("GroupRead.member_agent_ids", () => {
	it("may be omitted by an older server, and an unguarded read does not compile", () => {
		const { member_agent_ids, ...withoutOwnAgents } = BASE;

		// A deployment that predates the field sends no key at all. That has to type,
		// because it is what every client sees until the server is deployed.
		const olderServer: GroupRead = {
			...withoutOwnAgents,
			conversation_id: null,
		};

		// @ts-expect-error `undefined` is a real state of this field, so
		// every read goes through `?? []` (`rine-cli`'s `ownAgentsCell`). This
		// directive is what makes deleting that guard fail the build rather
		// than throw on `rine group get` against an older deployment.
		const unguarded: string[] = olderServer.member_agent_ids;

		// An empty array is a FACT — no agent of this org is seated, so a send
		// here would be refused — and never a stand-in for "not reported". A
		// renderer that treats the two the same is the defect this field removes.
		const none: GroupRead = { ...BASE, conversation_id: null };
		const seated: GroupRead = {
			...BASE,
			conversation_id: null,
			member_agent_ids: [
				"55555555-5555-4555-8555-555555555555",
				"77777777-7777-4777-8777-777777777777",
			],
		};

		expect(member_agent_ids).toHaveLength(0);
		expect(olderServer.member_agent_ids).toBeUndefined();
		expect(unguarded).toBeUndefined();
		expect(none.member_agent_ids).toHaveLength(0);
		expect(seated.member_agent_ids).toHaveLength(2);
	});
});

describe("GroupMemberRead.is_own_org", () => {
	it("may be omitted by an older server, and an unguarded read does not compile", () => {
		// The roster of a deployment that predates the field marks nothing.
		const olderServer: GroupMemberRead = { ...MEMBER_BASE };

		// @ts-expect-error three states, not two — `undefined` is "this
		// build cannot tell you", which `memberRow` renders as an em dash and
		// must never print as `false`. Reading the field as a plain boolean is
		// what collapses the two.
		const unguarded: boolean = olderServer.is_own_org;

		// Both arms exist on the SAME roster, which is the point: the field
		// marks rows, it does not select them. `GET /groups/{id}/members`
		// returns the whole group and `total` counts the whole group, so a
		// surface that dropped the `false` rows would hide exactly the
		// co-members a group send reaches.
		const mine: GroupMemberRead = { ...MEMBER_BASE, is_own_org: true };
		const theirs: GroupMemberRead = { ...MEMBER_BASE, is_own_org: false };

		expect(unguarded).toBeUndefined();
		expect(mine.is_own_org).toBe(true);
		expect(theirs.is_own_org).toBe(false);
	});
});
