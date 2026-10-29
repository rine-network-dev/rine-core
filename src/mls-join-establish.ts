import type { GroupRead } from "./api-types.js";
import { groupIsMls } from "./crypto/group-predicates.js";
import { loadMlsState } from "./crypto/mls-state.js";
import { formatError } from "./errors.js";
import type { HttpClient } from "./http.js";
import { externalJoinMlsGroup } from "./mls-external-join.js";
import { processMlsWelcomes } from "./mls-ops-join.js";
import { retakeOwnSeat, welcomeKept } from "./mls-stranded-seat.js";
import { isMlsWelcomeRefusedError } from "./mls-welcome-guard.js";
import { ReseatStatus } from "./recover-reseat.js";

/** The server's code on the 409 a join earns when the agent is already a member. */
export const ALREADY_A_MEMBER_CODE = "already_a_member";

/**
 * True for the 409 `POST /groups/{id}/join` answers an agent that is already
 * seated, matched on its status and code. Structural, because the TypeScript
 * SDK raises its own error class for the same answer.
 */
export function isAlreadyAMember(err: unknown): boolean {
	const { status, code } = (err ?? {}) as { status?: unknown; code?: unknown };
	return status === 409 && code === ALREADY_A_MEMBER_CODE;
}

export const MlsMembershipOutcome = {
	/** The group has no ratchet tree; nothing was set up. */
	NotMls: "not_mls",
	/** This agent already held state for the group before the setup began. */
	Held: "held",
	/** A Welcome waiting for this agent installed the state. */
	Installed: "installed",
	/** The agent held a leaf with no state and took it back by external commit. */
	Reseated: "reseated",
	/** The agent held no leaf and joined by external commit. */
	ExternalJoined: "external_joined",
	/** A step failed for a reason that is not a refusal for this group; see `failure`. */
	Failed: "failed",
} as const;
export type MlsMembershipOutcome =
	(typeof MlsMembershipOutcome)[keyof typeof MlsMembershipOutcome];

/** The step a failed establishment stopped at. */
export const MlsEstablishStep = {
	GroupRead: "group_read",
	WelcomeInstall: "welcome_install",
	SeatRetake: "seat_retake",
	ExternalJoin: "external_join",
} as const;
export type MlsEstablishStep = (typeof MlsEstablishStep)[keyof typeof MlsEstablishStep];

export interface MlsMembershipResult {
	outcome: MlsMembershipOutcome;
	/** Why the setup stopped, for the outcome `failed`. */
	reason?: string;
	/** The failure behind `reason`, for a surface that renders failures in its own words. */
	failure?: { step: MlsEstablishStep; error: unknown };
}

/** True when the establishment left this agent holding local state for the group. */
export function mlsStateEstablished({ outcome }: MlsMembershipResult): boolean {
	return (
		outcome === MlsMembershipOutcome.Installed ||
		outcome === MlsMembershipOutcome.Reseated ||
		outcome === MlsMembershipOutcome.ExternalJoined
	);
}

/**
 * Give a joined agent the local MLS state its membership implies, trying in
 * order: a Welcome waiting for it, retaking a leaf it holds with no state, and
 * an external join when it holds none.
 *
 * Best-effort, with one exception: a refusal (a Welcome the substitution guard
 * refused, or a tree holding a member the agent cannot verify) is thrown,
 * because it is a verdict about the group and not a setup step that will come
 * good on the next read. Every other failure, local state and spool reads
 * included, comes back as outcome `failed`.
 *
 * The Welcome pass is scoped to `groupId`, the id the caller named and never one
 * the server supplied, and the retake and the external join raise with that same
 * id, so the server cannot pick which refusal is raised. A kept Welcome for the
 * group stops the setup short of the leaf steps, because both would orphan the
 * key package it holds.
 */
export async function establishMlsMembership(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<MlsMembershipResult> {
	const finish = (outcome: MlsMembershipOutcome): MlsMembershipResult => ({ outcome });
	const holdsState = () => loadMlsState(configDir, agentId, groupId) !== null;
	let step: MlsEstablishStep = MlsEstablishStep.GroupRead;
	try {
		const group = (await client.get(`/groups/${groupId}`, undefined, extraHeaders)) as GroupRead;
		if (!groupIsMls(group)) return finish(MlsMembershipOutcome.NotMls);

		step = MlsEstablishStep.WelcomeInstall;
		const heldBefore = holdsState();
		await processMlsWelcomes(configDir, agentId, client, { forGroup: groupId });
		if (holdsState()) {
			return finish(heldBefore ? MlsMembershipOutcome.Held : MlsMembershipOutcome.Installed);
		}
		if (welcomeKept(configDir, agentId, groupId)) {
			throw new Error("a Welcome for this group is kept for a later attempt");
		}

		step = MlsEstablishStep.SeatRetake;
		const reseat = await retakeOwnSeat({ configDir, agentId, client, extraHeaders }, groupId);
		if (reseat?.status === ReseatStatus.Reseated) return finish(MlsMembershipOutcome.Reseated);
		if (reseat) throw new Error(reseat.reason ?? reseat.status);

		step = MlsEstablishStep.ExternalJoin;
		await externalJoinMlsGroup(configDir, agentId, groupId, client, extraHeaders);
		return finish(MlsMembershipOutcome.ExternalJoined);
	} catch (err) {
		if (isMlsWelcomeRefusedError(err)) throw err;
		return {
			outcome: MlsMembershipOutcome.Failed,
			reason: formatError(err),
			failure: { step, error: err },
		};
	}
}

/**
 * The setup a seated agent with no state gets when its join is answered
 * `already_a_member`: `null` when the helper does not apply (any other error,
 * or state already loads, and the 409 is the caller's to report), and otherwise
 * the establishment's result, established or not. A caller re-throws the 409 on
 * `null` and on a result that left no state; it reports a `failed` result
 * through its own setup warning first. A refusal for this group propagates.
 */
export async function establishAfterAlreadyAMember(
	err: unknown,
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<MlsMembershipResult | null> {
	if (!isAlreadyAMember(err) || loadMlsState(configDir, agentId, groupId) !== null) return null;
	return establishMlsMembership(configDir, agentId, groupId, client, extraHeaders);
}
