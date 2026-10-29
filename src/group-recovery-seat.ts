/**
 * The two fields a group sync adds to an MLS recovery: what the key-package
 * top-up did, and where the agent's own leaf stands after its self-update.
 */
import type { KeyPackageTopUp } from "./mls-keypackage-topup.js";
import type { PeerActor } from "./mls-allowed.js";
import type { MlsRecoveryResult } from "./mls-ops-resync.js";
import { selfUpdateGroup } from "./mls-self-update.js";
import type { SeatUpdate } from "./mls-seat-update.js";

/** An MLS recovery as a group sync reports it. */
export type MlsGroupRecovery = MlsRecoveryResult & { seat?: SeatUpdate };

/**
 * The top-up, spread rather than assigned — the `mlsNeverFoundedNote` rule. A
 * group that runs sender keys has no key packages to report on, so it reports
 * no key, not a `healthy` nobody asked about.
 */
export function topUpField(
	keyPackages: KeyPackageTopUp,
): { keyPackages?: KeyPackageTopUp } {
	return keyPackages.outcome === "healthy" ? {} : { keyPackages };
}

/**
 * A successful recovery with the agent's leaf moved to its current key.
 *
 * Only a recovery that kept the agent in the group has a leaf to move. This is
 * the one place a self-update runs on a read path's behalf, and only for the
 * explicit sync verb: the implicit catch-up behind every read and send never
 * calls it.
 */
export async function recoveredWithSeat(
	actor: PeerActor,
	groupId: string,
	recovered: MlsRecoveryResult,
	keyPackages: KeyPackageTopUp,
): Promise<MlsGroupRecovery> {
	const seat = recovered.evicted
		? undefined
		: await selfUpdateGroup(actor, groupId);
	return { ...recovered, ...topUpField(keyPackages), ...(seat ? { seat } : {}) };
}
