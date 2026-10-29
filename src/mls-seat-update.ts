/**
 * What happened to an agent's leaf in one group when its key was rotated.
 *
 * A rotation moves the agent's own leaf to its new key from a device that holds
 * the group's state. The report is snake_case, like the reseat report it sits
 * beside, and its status and reason strings are the same on every SDK.
 */

export const SeatUpdateStatus = {
	/** The leaf now carries the agent's current key. */
	Updated: "updated",
	/** The leaf already carried the agent's current key. */
	Current: "current",
	/** The leaf still carries an earlier key; a later sync finishes the move. */
	Deferred: "deferred",
	/** The leaf cannot be moved from this device. */
	Failed: "failed",
} as const;
export type SeatUpdateStatus = (typeof SeatUpdateStatus)[keyof typeof SeatUpdateStatus];

export const SeatDeferReason = {
	/** Another commit landed first. */
	EpochRace: "epoch_race",
	/** The update waits for a member to acknowledge it. */
	AwaitingAck: "awaiting_ack",
	/** The group rolled the update back before a member acknowledged it. */
	RolledBack: "rolled_back",
	/** The group could not be reached, or refused the update. */
	Unreachable: "unreachable",
} as const;
export type SeatDeferReason = (typeof SeatDeferReason)[keyof typeof SeatDeferReason];

export const SeatFailReason = {
	/** The agent has been removed from the group. */
	Evicted: "evicted",
	/** The leaf carries a key this agent cannot sign for. */
	SeatUnhealable: "seat_unhealable",
	/** This device holds an earlier key generation than the agent's current one. */
	KeyNotCurrent: "key_not_current",
	/** The core refused to build the update. */
	Refused: "refused",
} as const;
export type SeatFailReason = (typeof SeatFailReason)[keyof typeof SeatFailReason];

export interface SeatUpdate {
	/** The group, or `null` for a failure that is not about one group. */
	group_id: string | null;
	status: SeatUpdateStatus;
	reason?: SeatDeferReason | SeatFailReason;
	/** The error message, for `refused`, `seat_unhealable` and `unreachable`. */
	detail?: string;
	/** The epoch the update landed at, or awaits confirmation at. */
	epoch?: number;
	/** The drain left this epoch's escrow queued; the send gate covers it. */
	escrow_pending?: boolean;
}

export const KeyPackageRotation = {
	/** The agent's published key packages were replaced with ones minted under its current key. */
	Republished: "republished",
	/** The published key packages already carried the current key; nothing was replaced. */
	Current: "current",
	/** The replacement did not complete; the next MLS operation retries it. */
	Pending: "pending",
	/** This device holds an earlier key generation than the agent's current one, so nothing was replaced. */
	KeyNotCurrent: "key_not_current",
	/** This host holds none of the agent's MLS state, so there is nothing to replace here. */
	NotHeld: "not_held",
} as const;
export type KeyPackageRotation = (typeof KeyPackageRotation)[keyof typeof KeyPackageRotation];

/** What settling a rotation did to the agent's key packages and group seats. */
export interface RotationSettlement {
	key_packages: KeyPackageRotation;
	group_seats: SeatUpdate[];
}
