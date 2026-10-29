import type { GapReason } from "./mls-escrow-gap.js";

/** The stable code of {@link EscrowGapError}; the Python twin's `ESCROW_GAP_CODE`. */
export const ESCROW_GAP_CODE = "mls_escrow_gap";

/**
 * A send at an epoch whose read escrow can never exist.
 *
 * The core reported the epoch as a gap and the drain filed a marker before
 * saving, so a message sent at it would be unreadable to the org after a
 * recovery. Raised instead of sending; a later epoch sends normally. A
 * `too_many_leaves` gap is retried once after the orphaned leaves are reclaimed,
 * before this reaches the caller.
 */
export class EscrowGapError extends Error {
	readonly code = ESCROW_GAP_CODE;

	constructor(
		readonly groupId: string,
		readonly epoch: number,
		readonly reason: GapReason,
	) {
		super(
			`group ${groupId} epoch ${epoch} has no org read escrow (${reason}), so a ` +
				"message sent now would be unreadable to the org after a recovery. Wait for " +
				"the next epoch (any commit) and send again.",
		);
		this.name = "EscrowGapError";
	}
}

/** The stable code of {@link OrgMismatchError}. */
export const ORG_MISMATCH_CODE = "RINE_ORG_MISMATCH";

/** The stable code of {@link AgentIdMismatchError}. */
export const AGENT_ID_MISMATCH_CODE = "RINE_AGENT_ID_MISMATCH";

/**
 * The server names a different org than the one this profile was created under.
 *
 * Raised by `whoami()` before anything is trusted: a server that answers with
 * another org's id is either misconfigured or an impersonation, and every key
 * pin in this profile belongs to the org it recorded.
 */
export class OrgMismatchError extends Error {
	readonly code = ORG_MISMATCH_CODE;

	constructor(
		readonly localOrgId: string,
		readonly serverOrgId: string,
	) {
		super(
			`This profile belongs to org ${localOrgId}, but the server answered as org ` +
				`${serverOrgId}. Check the API URL and the profile name; nothing was changed.`,
		);
		this.name = "OrgMismatchError";
	}
}

/**
 * The server created an agent under a different id than the one the client minted.
 *
 * The agent id is bound into the keys and certificates the client built before
 * the request, so a different id makes all of them unusable. Nothing was saved.
 */
export class AgentIdMismatchError extends Error {
	readonly code = AGENT_ID_MISMATCH_CODE;

	constructor(
		readonly mintedId: string,
		readonly serverId: string,
	) {
		super(
			`The server created the agent as ${serverId}, but this client minted ${mintedId}. ` +
				"The keys were bound to the minted id, so none were saved and no profile was " +
				"written. Retry the create; if it repeats, report it.",
		);
		this.name = "AgentIdMismatchError";
	}
}

function hasCode(err: unknown, code: string): boolean {
	return (err as { code?: unknown } | null | undefined)?.code === code;
}

/**
 * True for an {@link EscrowGapError}, matched on its code. Like
 * {@link isGroupIdentityMismatchError}, the answer that survives a bundler
 * loading two copies of this package, and what `rine-ts-sdk` widens
 * `instanceof RineError` with: the Python twins are `CryptoError`s, so a
 * consumer's `catch (e) { if (e instanceof RineError) … }` must hold here too.
 */
export function isEscrowGapError(err: unknown): boolean {
	return hasCode(err, ESCROW_GAP_CODE);
}

/** True for an {@link OrgMismatchError}, matched on its code. */
export function isOrgMismatchError(err: unknown): boolean {
	return hasCode(err, ORG_MISMATCH_CODE);
}

/** True for an {@link AgentIdMismatchError}, matched on its code. */
export function isAgentIdMismatchError(err: unknown): boolean {
	return hasCode(err, AGENT_ID_MISMATCH_CODE);
}
