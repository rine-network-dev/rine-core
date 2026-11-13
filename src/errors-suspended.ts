import type { RineErrorBody } from "./errors.js";

/**
 * Why the server holds a principal: its org is frozen, its branch is suspended or the
 * agent itself is suspended. Stated once; every reader of a hold refusal uses these.
 */
export const HoldCode = {
	OrgFrozen: "org_frozen",
	BranchSuspended: "branch_suspended",
	AgentSuspended: "agent_suspended",
} as const;
export type HoldCode = (typeof HoldCode)[keyof typeof HoldCode];

/**
 * The governance refusals that are not holds: a stopped `new_agents` rule, a branch facing its
 * organisation's suspension, a change during rine's freeze and a delegated key outside its scope.
 * Each is a 403 carrying the code in `error`.
 */
export const GovernanceRefusal = {
	NewAgentsStopped: "new_agents_stopped",
	SuspendedByOrg: "suspended_by_org",
	OperatorFrozen: "operator_frozen",
	DelegateScope: "delegate_scope",
} as const;
export type GovernanceRefusal =
	(typeof GovernanceRefusal)[keyof typeof GovernanceRefusal];

/** The hold codes as a `Set`, so a hostile code such as `"constructor"` can never match. */
const HOLD_CODES: ReadonlySet<string> = new Set(Object.values(HoldCode));

/**
 * The hold a failed response names, or `undefined` when it names none. A bearer route
 * refuses a held caller with a 403 carrying the hold in `error`; the token mint refuses
 * with a 400 `unauthorized_client` carrying it in `reason`.
 */
export function holdOf(
	status: number,
	body: RineErrorBody | undefined,
): HoldCode | undefined {
	if (body === undefined) return undefined;
	let code: unknown;
	if (status === 403) code = body.error;
	else if (status === 400 && body.error === "unauthorized_client")
		code = body.reason;
	return typeof code === "string" && HOLD_CODES.has(code)
		? (code as HoldCode)
		: undefined;
}
