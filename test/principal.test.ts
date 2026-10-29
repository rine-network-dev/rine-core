import { describe, expect, it } from "vitest";
import {
	type Principal,
	PrincipalKind,
	parsePrincipal,
	principalString,
} from "../src/principal.js";

const ORG_ID = "22222222-2222-4222-8222-222222222222";
const AGENT_ID = "11111111-1111-4111-8111-111111111111";

const SHAPES: Principal[] = [
	{ kind: PrincipalKind.Org, orgId: ORG_ID },
	{ kind: PrincipalKind.Branch, orgId: ORG_ID, name: "main" },
	{ kind: PrincipalKind.Agent, agentId: AGENT_ID },
	{ kind: PrincipalKind.Reader, orgId: ORG_ID },
	{ kind: PrincipalKind.Reader, orgId: ORG_ID, name: "main" },
];

describe("principalString", () => {
	it.each([
		[{ kind: PrincipalKind.Org, orgId: ORG_ID }, `org:${ORG_ID}`],
		[
			{ kind: PrincipalKind.Branch, orgId: ORG_ID, name: "main" },
			`branch:${ORG_ID}:main`,
		],
		[{ kind: PrincipalKind.Agent, agentId: AGENT_ID }, `agent:${AGENT_ID}`],
		[{ kind: PrincipalKind.Reader, orgId: ORG_ID }, `reader:${ORG_ID}`],
		[
			{ kind: PrincipalKind.Reader, orgId: ORG_ID, name: "main" },
			`reader:${ORG_ID}:main`,
		],
	] as [Principal, string][])("renders %o as %s", (principal, text) => {
		expect(principalString(principal)).toBe(text);
	});
});

describe("parsePrincipal", () => {
	it.each(SHAPES)("round-trips %o", (principal) => {
		expect(parsePrincipal(principalString(principal))).toEqual(principal);
	});

	it.each([
		["org", "wrong kind"],
		["owner:" + ORG_ID, "unknown kind"],
		["org:not-a-uuid", "non-canonical uuid"],
		["org:22222222-2222-4222-8222-22222222222", "short uuid"],
		["org:22222222-2222-4222-8222-22222222222Z", "non-hex uuid"],
		["org:22222222222242228222222222222222", "uuid without dashes"],
		["agent:not-a-uuid", "non-canonical agent id"],
		[`branch:${ORG_ID}:Main`, "uppercase branch name"],
		[`branch:${ORG_ID}:`, "empty branch name"],
		[`branch:${ORG_ID}:${"a".repeat(33)}`, "over-long branch name"],
		[`branch:${ORG_ID}`, "branch without a name"],
		[`reader:${ORG_ID}:Main`, "bad reader branch name"],
		[`org:${ORG_ID}:extra`, "org with a trailing segment"],
		[`agent:${AGENT_ID}:extra`, "agent with a trailing segment"],
		[`branch:${ORG_ID}:main:extra`, "branch with an extra segment"],
		[`reader:${ORG_ID}:main:extra`, "reader with an extra segment"],
		["", "empty string"],
	])("refuses %s (%s)", (text) => {
		expect(() => parsePrincipal(text)).toThrow("invalid principal");
	});
});
