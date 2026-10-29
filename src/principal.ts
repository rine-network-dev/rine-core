// The four principal kinds a token request can name. A closed union,
// so no caller compares a kind against a bare string.
import { BRANCH_NAME_RE } from "./crypto/derive.js";
import { CANONICAL_UUID_RE } from "./uuid.js";

/** The branch every org starts with and an agent joins by default. */
export const MAIN_BRANCH = "main";

export const PrincipalKind = {
	Org: "org",
	Branch: "branch",
	Agent: "agent",
	Reader: "reader",
} as const;
export type PrincipalKind = (typeof PrincipalKind)[keyof typeof PrincipalKind];

export type Principal =
	| { kind: typeof PrincipalKind.Org; orgId: string }
	| { kind: typeof PrincipalKind.Branch; orgId: string; name: string }
	| { kind: typeof PrincipalKind.Agent; agentId: string }
	/** `name` absent is the org reader, present is a branch reader. */
	| { kind: typeof PrincipalKind.Reader; orgId: string; name?: string };

export function principalString(principal: Principal): string {
	switch (principal.kind) {
		case PrincipalKind.Org:
			return `org:${principal.orgId}`;
		case PrincipalKind.Branch:
			return `branch:${principal.orgId}:${principal.name}`;
		case PrincipalKind.Agent:
			return `agent:${principal.agentId}`;
		case PrincipalKind.Reader:
			return principal.name === undefined
				? `reader:${principal.orgId}`
				: `reader:${principal.orgId}:${principal.name}`;
	}
}

function uuid(text: string | undefined): string {
	if (text === undefined || !CANONICAL_UUID_RE.test(text)) {
		throw new Error("invalid principal");
	}
	return text;
}

function branchName(text: string | undefined): string {
	if (text === undefined || !BRANCH_NAME_RE.test(text)) {
		throw new Error("invalid principal");
	}
	return text;
}

/** Inverse of {@link principalString}; throws `invalid principal` on any other shape. */
export function parsePrincipal(text: string): Principal {
	const [kind, first, second, ...rest] = text.split(":");
	if (rest.length > 0) throw new Error("invalid principal");
	switch (kind) {
		case PrincipalKind.Org:
			if (second !== undefined) throw new Error("invalid principal");
			return { kind: PrincipalKind.Org, orgId: uuid(first) };
		case PrincipalKind.Agent:
			if (second !== undefined) throw new Error("invalid principal");
			return { kind: PrincipalKind.Agent, agentId: uuid(first) };
		case PrincipalKind.Branch:
			return {
				kind: PrincipalKind.Branch,
				orgId: uuid(first),
				name: branchName(second),
			};
		case PrincipalKind.Reader:
			return second === undefined
				? { kind: PrincipalKind.Reader, orgId: uuid(first) }
				: {
						kind: PrincipalKind.Reader,
						orgId: uuid(first),
						name: branchName(second),
					};
		default:
			throw new Error("invalid principal");
	}
}
