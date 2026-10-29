/**
 * The loss a revoked principal means for the escrow work in flight.
 *
 * Three refusals say the same thing from three places: the branch key read
 * answering 410, a 401 naming the revoked principal, and the 422 an escrow
 * route answers when the acting branch or agent is revoked. Each arrives as a
 * different error, and each means the escrow can never be stored, so this is
 * the one place that turns any of them into the {@link EscrowLoss} a give-up
 * records. A code is read only at the statuses the routes pair it with (410 and
 * 422): the same code on any other status is not the server's refusal of the
 * upload and gives up nothing.
 *
 * The Python twin is `rine/_mls/escrow_revoked.py`.
 */
import {
	PrincipalRevokedError,
	RevokedScope,
	RineApiError,
	scopeOfRevokedCode,
} from "./errors.js";
import { EscrowLoss } from "./mls-escrow-gap.js";
import { BranchRevokedError } from "./mls-escrow-key.js";

/** The statuses an escrow route pairs with a revoked principal: gone (410) or an unprocessable acting principal (422). */
const REVOKED_STATUSES: ReadonlySet<number> = new Set([410, 422]);

function lossOfScope(scope: RevokedScope): EscrowLoss {
	return scope === RevokedScope.Agent ? EscrowLoss.AgentRevoked : EscrowLoss.BranchRevoked;
}

/**
 * The loss a revoked principal means, or `undefined` when the error says nothing
 * about a revocation and the caller should treat it as an ordinary failure.
 */
export function revokedLoss(error: unknown): EscrowLoss | undefined {
	if (error instanceof BranchRevokedError) return EscrowLoss.BranchRevoked;
	if (error instanceof PrincipalRevokedError) return lossOfScope(error.scope);
	if (error instanceof RineApiError && REVOKED_STATUSES.has(error.status)) {
		const scope = scopeOfRevokedCode(error.code);
		return scope === undefined ? undefined : lossOfScope(scope);
	}
	return undefined;
}
