import { MLS_ERR_PEER_NOT_ADMITTED, mlsErrorCode } from "./crypto/mls-errors.js";
import { MlsWelcomeRefusedError } from "./mls-welcome-guard.js";

/**
 * True for the native core's final refusal of a leaf it cannot verify: the
 * allowed set had no entry for an agent in the tree, and a key read of that
 * agent found nothing to verify against.
 */
export function isPeerNotAdmitted(err: unknown): boolean {
	return mlsErrorCode(err) === MLS_ERR_PEER_NOT_ADMITTED;
}

/**
 * The refusal a join earns when the group's ratchet tree holds a member this
 * agent cannot verify, so no Welcome minted at that tree can be opened and an
 * external commit meets the same leaf.
 *
 * Final for the tree it names: a later attempt succeeds once any member
 * reclaims the seat it cannot verify.
 */
export function peerNotAdmittedRefusal(groupId: string): MlsWelcomeRefusedError {
	return new MlsWelcomeRefusedError(
		groupId,
		"peer_not_admitted",
		`Cannot join the MLS group ${groupId} yet: its ratchet tree holds a member ` +
			"this agent cannot verify, because the server no longer vouches for that " +
			"agent. The group's seat for it must be reclaimed first: any other member " +
			"that holds a leaf in the group can run " +
			"`rine group resume-admission --reclaim` (an admin is not required); then " +
			"the join can be repeated.",
	);
}
