import { ACTING_AGENT_HEADER } from "./actor.js";
import { MLS_ERR_NO_SEAT_TO_REPLACE, mlsErrorCode } from "./crypto/mls-errors.js";
import { loadMlsGroup, openMlsClient } from "./crypto/mls.js";
import type { HttpClient } from "./http.js";
import type { PeerActor } from "./mls-allowed.js";
import type { MlsRecoveryResult } from "./mls-ops-resync.js";
import { processMlsWelcomes } from "./mls-ops-join.js";
import { isPeerNotAdmitted, peerNotAdmittedRefusal } from "./mls-peer-refusal.js";
import { MlsResyncUnavailableError } from "./mls-resync-unavailable.js";
import { isMlsRotatedLeaf } from "./mls-rotated-leaf.js";
import { WelcomeSpool } from "./mls-welcome-spool.js";
import { type GroupReseat, ReseatStatus, retakeSeat } from "./recover-reseat.js";

/** Whether a Welcome for the group is still on the spool, kept for a later attempt. */
export function welcomeKept(configDir: string, agentId: string, groupId: string): boolean {
	return new WelcomeSpool(configDir, agentId)
		.pending()
		.some(({ delivery }) => delivery.group_id.toLowerCase() === groupId.toLowerCase());
}

/**
 * {@link retakeSeat} for a caller that has to tell "this agent holds no leaf
 * here" from a failure: `null` when the group's tree holds no leaf under this
 * agent's credential, and the shared refusal when the tree holds a member the
 * server no longer vouches for. Every other failure is thrown.
 */
export async function retakeOwnSeat(
	actor: PeerActor,
	groupId: string,
): Promise<GroupReseat | null> {
	try {
		return await retakeSeat(actor, groupId);
	} catch (err) {
		if (mlsErrorCode(err) === MLS_ERR_NO_SEAT_TO_REPLACE) return null;
		if (isPeerNotAdmitted(err)) throw peerNotAdmittedRefusal(groupId);
		throw err;
	}
}

/**
 * Bring back a member that is seated in a group but holds no local state for
 * it: `null` when a Welcome installed that state, the recovery result when the
 * member took its own leaf back, and a throw in every other case.
 *
 * Called only by a caller that found no loadable state. The steps, each checked
 * by something other than this function:
 *
 * * A Welcome for the group, scoped to it, goes first. One that is on the server
 *   and not yet spooled installs here instead of being orphaned by a re-seat,
 *   and a refusal for this group is raised.
 * * A Welcome for the group still on the spool is kept for a later attempt, so
 *   no leaf is replaced under it: {@link MlsResyncUnavailableError}.
 * * A leaf under this agent's own credential in the published GroupInfo, or the
 *   native core refuses with no seat to replace.
 * * A tree that verifies, or the native core refuses the peer it cannot verify
 *   with the shared `peer_not_admitted` refusal. Once a member reclaims the
 *   revoked leaf, the tree does.
 *
 * No GroupInfo, no own leaf and a leaf under a rotated-away key all answer
 * {@link MlsResyncUnavailableError}, as an agent with no state always has.
 * A network or server failure propagates.
 */
export async function reseatStrandedSeat(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
): Promise<MlsRecoveryResult | null> {
	const load = () => loadMlsGroup(openMlsClient(configDir, agentId), groupId);
	await processMlsWelcomes(configDir, agentId, client, { forGroup: groupId });
	if (load() !== null) return null;
	if (welcomeKept(configDir, agentId, groupId)) {
		throw new MlsResyncUnavailableError(groupId);
	}
	const actor = {
		configDir,
		agentId,
		client,
		extraHeaders: { [ACTING_AGENT_HEADER]: agentId },
	};
	let reseat: GroupReseat | null;
	try {
		reseat = await retakeOwnSeat(actor, groupId);
	} catch (err) {
		if (isMlsRotatedLeaf(err)) throw new MlsResyncUnavailableError(groupId);
		throw err;
	}
	if (reseat === null || reseat.status !== ReseatStatus.Reseated) {
		throw new MlsResyncUnavailableError(groupId);
	}
	// The reseat adopts local state only once the server accepted its commit.
	const group = load();
	if (group === null) throw new MlsResyncUnavailableError(groupId);
	const epoch = group.epoch();
	return {
		regime: "mls",
		rung: "resync",
		fromEpoch: epoch,
		epoch,
		behind: null,
		processed: 0,
		evicted: false,
		escrow: reseat.escrow,
	};
}
