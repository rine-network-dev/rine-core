/**
 * The typed escrow outcome a drain, a settle or a sweep hands back.
 *
 * It is merged into the sync, join, admission, removal and reseat results so a
 * caller sees the escrow work done on its behalf without reading prose: the
 * epochs that have no escrow, why sealing was not attempted when it was not, and
 * what still waits unsealed. The Python twin is `rine/_mls/escrow_report.py`,
 * with the same names.
 */
import type { EscrowBacklog } from "@rine-network/mls";
import { RevokedCode } from "./errors-revoked.js";
import { type DrainGap, EscrowLoss } from "./mls-escrow-gap.js";
import { takeUnreported } from "./mls-escrow-handoff.js";
import { revokedLoss } from "./mls-escrow-revoked.js";

/** Why sealing was not attempted, if it was not. */
export const EscrowDeferral = {
	/** No verified escrow key could be read; the exports stay queued. */
	KeyUnavailable: "key_unavailable",
	/** The branch's key is revoked (410); the sweep records a gap and discards the exports. */
	BranchRevoked: RevokedCode.Branch,
	/** The agent itself is revoked; the sweep records a gap and discards the exports. */
	AgentRevoked: RevokedCode.Agent,
} as const;
export type EscrowDeferral = (typeof EscrowDeferral)[keyof typeof EscrowDeferral];

/** What one drain did, and what it could not do. */
export interface DrainOutcome {
	/** Epochs sealed and written to the pending store by this call. */
	sealed: number;
	/** Pending files the server now holds, uploaded or already stored, and deleted by this call. */
	uploaded: number;
	/**
	 * Upload failures. A file the server may yet accept stays on its retry
	 * schedule; one it refused for good, or refused for the sixteenth time, is
	 * given up (its epoch filed as a gap) and listed here once.
	 */
	failures: Error[];
	/**
	 * Epochs that have no escrow, each filed as a local gap marker: by the drain
	 * before the group was saved, or by the sweep before it deleted what it gave up.
	 */
	gaps: DrainGap[];
	/**
	 * Set when sealing was not attempted (no verified escrow key, or a revoked
	 * branch or agent). The exports stay in the saved snapshot, up to the group's
	 * cap, whatever the reason: the overflow becomes gaps in the core. A revoked
	 * branch's or agent's snapshots are then given up by the sweep.
	 */
	deferred?: Error;
	/** Set with `deferred` when the exports were kept: what waits in the snapshot for the next drain. */
	backlog?: EscrowBacklog;
}

/** A drain's outcome before anything has been sealed or uploaded. */
export function emptyOutcome(): DrainOutcome {
	return { sealed: 0, uploaded: 0, failures: [], gaps: [] };
}

/** What a result reports of the escrow work done on its behalf. */
export interface EscrowReport {
	/** Epochs with no escrow. */
	gaps: DrainGap[];
	/** Why sealing was not attempted, if it was not. */
	deferral?: EscrowDeferral;
	/** Exports still waiting unsealed in the saved snapshot. */
	queued: number;
	/** Exports the native queue dropped (overflow). */
	dropped: number;
	/** Old-state snapshots parked in `escrow-backlog/` awaiting the sweep. */
	backlogged: number;
}

/** A report with nothing to say. */
export function emptyReport(): EscrowReport {
	return { gaps: [], queued: 0, dropped: 0, backlogged: 0 };
}

/** The deferral an error that stopped sealing names. */
export function deferralFor(error: Error): EscrowDeferral {
	const revoked = revokedLoss(error);
	if (revoked === EscrowLoss.BranchRevoked) return EscrowDeferral.BranchRevoked;
	if (revoked === EscrowLoss.AgentRevoked) return EscrowDeferral.AgentRevoked;
	return EscrowDeferral.KeyUnavailable;
}

/**
 * The epochs a result reports as having no escrow, with the reason of each, in
 * one line (`4 (refused), 5 (agent_revoked)`); empty when there are none. For a
 * surface that prints a result, so a lost epoch is named and not only counted.
 */
export function describeEscrowGaps(gaps: readonly DrainGap[]): string {
	return gaps.map(({ epoch, reason }) => `${epoch} (${reason})`).join(", ");
}

/** The report of one drain's outcome. */
export function reportOf(
	outcome: Pick<DrainOutcome, "gaps" | "deferred" | "backlog">,
): EscrowReport {
	const backlog: EscrowBacklog | undefined = outcome.backlog;
	return {
		gaps: [...outcome.gaps],
		...(outcome.deferred === undefined
			? {}
			: { deferral: deferralFor(outcome.deferred) }),
		queued: backlog?.queued ?? 0,
		dropped: backlog?.dropped ?? 0,
		backlogged: 0,
	};
}

/**
 * The report of one drain of `groupId`, with the epochs a background sweep lost
 * for that group ahead of the drain's own. Each is reported once: taking them
 * clears the handoff, so only a drain whose result reaches a caller uses this.
 */
export function reportDrain(
	actor: { configDir: string; agentId: string },
	groupId: string,
	outcome: Pick<DrainOutcome, "gaps" | "deferred" | "backlog">,
): EscrowReport {
	const carried = takeUnreported(actor.configDir, actor.agentId, groupId);
	return reportOf({ ...outcome, gaps: [...carried, ...outcome.gaps] });
}

/**
 * Fold two reports into one: gaps concatenate and counts sum. The deferral is
 * the first report's when it has one: the first reason sealing was skipped is
 * the one that explains the queue.
 */
export function mergeReports(first: EscrowReport, second: EscrowReport): EscrowReport {
	const deferral = first.deferral ?? second.deferral;
	return {
		gaps: [...first.gaps, ...second.gaps],
		...(deferral === undefined ? {} : { deferral }),
		queued: first.queued + second.queued,
		dropped: first.dropped + second.dropped,
		backlogged: first.backlogged + second.backlogged,
	};
}
