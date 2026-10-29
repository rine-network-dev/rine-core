import type { RineErrorBody } from "./errors.js";

/** Which principal the server named when it refused a revoked caller. */
export const RevokedScope = { Agent: "agent", Branch: "branch" } as const;
export type RevokedScope = (typeof RevokedScope)[keyof typeof RevokedScope];

/**
 * The `error` codes the server uses for a revoked principal, on a bearer route
 * (`error`), on the token mint (`reason` beside `error: "invalid_client"`) and on
 * an escrow upload's 422. Stated once: every other module reads these values.
 */
export const RevokedCode = {
	Agent: "agent_revoked",
	Branch: "branch_revoked",
} as const;
export type RevokedCode = (typeof RevokedCode)[keyof typeof RevokedCode];

/**
 * The revoked-principal codes mapped to their scope. A `Map` and not an object
 * literal, so a hostile code such as `"constructor"` or `"__proto__"` can never
 * match an inherited property.
 */
const SCOPE_OF_CODE = new Map<string, RevokedScope>([
	[RevokedCode.Agent, RevokedScope.Agent],
	[RevokedCode.Branch, RevokedScope.Branch],
]);

/** The scope a revoked-principal code names, or `undefined` for any other text. */
export function scopeOfRevokedCode(code: unknown): RevokedScope | undefined {
	return typeof code === "string" ? SCOPE_OF_CODE.get(code) : undefined;
}

/**
 * The scope a failed response names as revoked, or `undefined` when it names
 * none. Only a 401 names a revoked principal: the same code on any other status
 * stays an ordinary API error (the escrow layer reads a 422 on its own). The token mint carries the scope in
 * `reason` beside `error: "invalid_client"`; a bearer route carries it in
 * `error` itself.
 */
export function revokedScope(
	status: number,
	body: RineErrorBody | undefined,
): RevokedScope | undefined {
	if (status !== 401 || body === undefined) return undefined;
	return scopeOfRevokedCode(body.error === "invalid_client" ? body.reason : body.error);
}
