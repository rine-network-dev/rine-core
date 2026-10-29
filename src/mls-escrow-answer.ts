/**
 * What the server's refusal of one pending escrow upload means for that file.
 * Four outcomes, closed: the slot already holds this agent's own row (the send
 * gate asks for nothing more), the server will never take it, it may yet, or the
 * server is unavailable or throttling and the whole sweep should wait.
 *
 * The server says "never" with a distinct `error` code on a 4xx, and the client
 * sorts by that pair: a bare 403 or 404 with no code is a proxy, an old server or
 * a mis-attributed refusal, so it is retried under the attempt cap and never
 * given up on sight; a code on any other status (a 200, a 5xx from an
 * intermediary) is not the server's refusal of this file and gives up nothing.
 *
 * A revoked principal is the one refusal that is not about the file: the 401 the
 * server answers a revoked agent or branch carries no escrow code, but no later
 * attempt can succeed, so it is refused whatever the code says.
 */
import { PrincipalRevokedError, type RineApiError, RevokedCode } from "./errors.js";

/** The `error` code of the 409 for a slot the uploader already filled with other bytes. */
const ESCROW_SLOT_TAKEN_CODE = "escrow_slot_taken";

/** The `error` codes the escrow routes answer for a refusal that will never change. */
export const EscrowTerminalCode = {
	/** No seat span of the uploader covers the epoch. */
	NoSeat: "escrow_no_seat",
	/** The group is gone. */
	GroupNotFound: "group_not_found",
	/** The uploader's branch has been revoked. */
	BranchRevoked: RevokedCode.Branch,
	/** The uploader has been revoked. */
	AgentRevoked: RevokedCode.Agent,
	/** The uploader already has the most forks of one epoch the server stores. */
	ForkLimit: "escrow_fork_limit",
} as const;
export type EscrowTerminalCode =
	(typeof EscrowTerminalCode)[keyof typeof EscrowTerminalCode];

const TERMINAL_CODES: readonly string[] = Object.values(EscrowTerminalCode);

export const EscrowAnswer = {
	/** The slot is filled: the pending file is done. */
	Stored: "stored",
	/** The server will never take it: give the file up. */
	Refused: "refused",
	/** It may yet be accepted: keep the file for the next pass. */
	Retry: "retry",
	/** The server is down or throttling: keep the file and stop uploading, as for a network failure. */
	Backoff: "backoff",
} as const;
export type EscrowAnswer = (typeof EscrowAnswer)[keyof typeof EscrowAnswer];

/** A status that says the server, not the file, is the problem. */
function isUnavailable(status: number): boolean {
	return status === 429 || status >= 500;
}

/** A status the server pairs with a refusal of one request: a 4xx other than a throttle. */
function isRefusalStatus(status: number): boolean {
	return status >= 400 && status < 500 && status !== 429;
}

/** Sort a refusal: the slot is already filled, never going to be, may yet be, or the server needs a pause. */
export function classifyRefusal(err: RineApiError): EscrowAnswer {
	// A revoked principal is refused whatever the code says: the 401 carries no
	// escrow code, and no later attempt can succeed.
	if (err instanceof PrincipalRevokedError) return EscrowAnswer.Refused;
	if (err.code !== undefined && isRefusalStatus(err.status)) {
		if (err.code === ESCROW_SLOT_TAKEN_CODE) return EscrowAnswer.Stored;
		if (TERMINAL_CODES.includes(err.code)) return EscrowAnswer.Refused;
	}
	return isUnavailable(err.status) ? EscrowAnswer.Backoff : EscrowAnswer.Retry;
}
