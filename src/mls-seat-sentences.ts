/**
 * What a group sync says about where the agent's own leaf stands.
 *
 * A rotation moves the agent's leaf to its new key, and a sync that ran the
 * move appends one sentence about the outcome. The sentences are the Python
 * SDK's, byte for byte (`rine.format`).
 */
import {
	SeatDeferReason,
	type SeatUpdate,
	SeatFailReason,
	SeatUpdateStatus,
} from "./mls-seat-update.js";

/**
 * What an agent is told when a commit it just applied removed it from the group.
 *
 * One sentence, one home: the explicit recovery verbs report it through
 * `describeMlsRecovery`, and a plain read reports it too — the catch-up
 * behind a read applies the same commits, so an agent could be evicted by a
 * message it opened successfully. Both must say the same thing, and a second
 * copy of this sentence is how they would stop.
 *
 * Both matrix harnesses regex the rungs this is appended to, so its bytes are
 * pinned: change the wording and re-run them.
 */
export const MLS_EVICTED_BY_COMMIT =
	"This agent was removed from the group by a commit it just replayed: " +
	"messages that already arrived still open, and nothing committed after the " +
	"Remove ever will.";

const DEFERRED: Record<SeatDeferReason, (epoch: number | undefined) => string> = {
	[SeatDeferReason.EpochRace]: () =>
		"Its leaf still carries an earlier key: another commit landed first; the next sync retries.",
	[SeatDeferReason.Unreachable]: () =>
		"Its leaf still carries an earlier key: the update could not be posted; the next sync retries.",
	[SeatDeferReason.AwaitingAck]: (epoch) =>
		`Its leaf moves to the agent's current key once a member acknowledges the update (epoch ${epoch}); until then it carries the earlier key.`,
	[SeatDeferReason.RolledBack]: () =>
		"Its leaf still carries an earlier key: the group rolled the update back before a member acknowledged it; the next sync retries.",
};

const FAILED: Record<SeatFailReason, (detail: string) => string> = {
	[SeatFailReason.Evicted]: () => MLS_EVICTED_BY_COMMIT,
	[SeatFailReason.SeatUnhealable]: () =>
		"Its leaf carries a key this agent cannot sign for; a member must remove the agent and invite it again.",
	[SeatFailReason.KeyNotCurrent]: () =>
		"Its leaf was not moved: this device holds an earlier key generation than the agent's current one.",
	[SeatFailReason.Refused]: (detail) =>
		`Its leaf was not moved: the update was refused: ${detail}`,
};

const isDeferReason = (reason: string): reason is SeatDeferReason =>
	Object.values(SeatDeferReason).includes(reason as SeatDeferReason);

/**
 * The sentence a recovery appends about the agent's leaf, or `""` when it has none.
 *
 * Silent for a leaf that already carries the current key and for a recovery that
 * ran no self-update, so an unchanged group prints exactly what it printed before.
 */
export function seatUpdateLine(seat: SeatUpdate | undefined): string {
	if (seat === undefined || seat.status === SeatUpdateStatus.Current) return "";
	if (seat.status === SeatUpdateStatus.Updated) {
		return `Its leaf now carries the agent's current key (epoch ${seat.epoch}).`;
	}
	if (seat.reason === undefined) return "";
	if (seat.status === SeatUpdateStatus.Deferred && isDeferReason(seat.reason)) {
		return DEFERRED[seat.reason](seat.epoch);
	}
	if (seat.status === SeatUpdateStatus.Failed && !isDeferReason(seat.reason)) {
		return FAILED[seat.reason](seat.detail ?? "no reason was reported");
	}
	return "";
}
