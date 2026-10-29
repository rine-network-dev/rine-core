/**
 * Moving an agent's leaf in every group it holds, and settling a key rotation.
 *
 * A rotation mints a new key generation, but two things still carry the old one:
 * the key packages published for the agent and its leaf in each group. Settling
 * replaces the first and sweeps the second. The work is host-local, so a record
 * of the last generation it completed lets a restart, a second device or the
 * next heartbeat pick up where an interrupted settlement stopped.
 */
import { loadAgentKeys } from "./crypto/keys.js";
import { isMlsKeyNotCurrent } from "./crypto/mls-key-not-current.js";
import { holdsMlsState } from "./crypto/mls-state.js";
import { holdsMlsStore } from "./crypto/mls-store-probe.js";
import { drainAndRepublishMlsKeyPackages } from "./mls-cutover.js";
import type { PeerActor } from "./mls-allowed.js";
import { diskKeyIsCurrent } from "./mls-key-current.js";
import { readRotationMarker, writeRotationMarker } from "./mls-rotation-marker.js";
import { detailOf } from "./mls-seat-failure.js";
import { seatedMlsGroups } from "./mls-seated-groups.js";
import {
	KeyPackageRotation,
	type RotationSettlement,
	SeatDeferReason,
	SeatFailReason,
	type SeatUpdate,
	SeatUpdateStatus,
} from "./mls-seat-update.js";
import {
	MlsSettleSlotUnsetError,
	isSettling,
	reseatRegisteredGroup,
	whileSettling,
} from "./mls-settle-guard.js";
import { ProcessGate, actorGateKey } from "./process-gate.js";

const NOT_HELD: RotationSettlement = {
	key_packages: KeyPackageRotation.NotHeld,
	group_seats: [],
};

/**
 * The deferred seat a failure leaves behind. An unfilled re-seat slot is a
 * packaging defect rather than a group that could not be reached, so it is
 * rethrown instead of becoming a seat a later sweep would retry forever.
 */
function deferredSeat(err: unknown): SeatUpdate {
	if (err instanceof MlsSettleSlotUnsetError) throw err;
	return {
		group_id: null,
		status: SeatUpdateStatus.Deferred,
		reason: SeatDeferReason.Unreachable,
		detail: detailOf(err),
	};
}

const BACKOFF_BASE_MS = 60_000;
const BACKOFF_MAX_MS = 60 * 60_000;

/** Per agent: how many background sweeps in a row left a seat deferred, and when the next may run. */
const stuckSweeps = new ProcessGate<{ failures: number; notBefore: number }>();

/**
 * Note how a background sweep ended. A sweep that left a seat deferred doubles
 * the wait before the next one, from one beat up to an hour; one that settled
 * everything forgets the wait. Per process and deliberately not persisted: a
 * restart gets a fresh try, which is what a stuck group needs most.
 */
function noteSweep(actor: PeerActor, deferred: boolean): void {
	const key = actorGateKey(actor);
	if (!deferred) {
		stuckSweeps.delete(key);
		return;
	}
	const failures = (stuckSweeps.get(key)?.failures ?? 0) + 1;
	const wait = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** (failures - 1));
	stuckSweeps.set(key, { failures, notBefore: Date.now() + wait });
}

/** How a settlement was started. A background one (the heartbeat) honours the backoff. */
export interface SettleOptions {
	background?: boolean;
}

/**
 * Move the agent's leaf to its current key in every group this host holds state
 * for, one group at a time.
 *
 * Nothing is attempted unless the key on disk is the agent's current one,
 * chain-verified: a host holding superseded keys would only move a leaf to its
 * own stale key. Groups are done sequentially because each one drains its own
 * escrow queue. A group the server lists but this host holds no state for is
 * skipped: the Welcome path owns it.
 */
export async function selfUpdateStaleLeaves(actor: PeerActor): Promise<SeatUpdate[]> {
	const { configDir, agentId, client } = actor;
	try {
		if (!(await diskKeyIsCurrent(actor))) {
			return [
				{
					group_id: null,
					status: SeatUpdateStatus.Failed,
					reason: SeatFailReason.KeyNotCurrent,
				},
			];
		}
		const groups = await seatedMlsGroups(client, agentId);
		const held = groups.filter((group) => holdsMlsState(configDir, agentId, group.id));
		const seats: SeatUpdate[] = [];
		for (const group of held) seats.push(await reseatRegisteredGroup(actor, group.id));
		return seats;
	} catch (err) {
		return [deferredSeat(err)];
	}
}

/**
 * Bring the agent's key packages and group seats up to its current key
 * generation, and report what was done.
 *
 * Never throws for a failure of the agent or its groups: it runs behind a
 * rotation the server has already committed and inside a heartbeat, where such a
 * failure is a report and a retry, not an error. The one throw is
 * {@link MlsSettleSlotUnsetError}, a packaging defect no retry repairs.
 * Each half is skipped once the record shows it complete for this generation, so
 * an agent that has not rotated pays a file read. A half that did not finish
 * leaves the record behind and the next call repeats it; a seat that is
 * `failed` counts as finished, because repeating it cannot change the answer.
 *
 * The settlement is guarded per agent: the sync of each group runs a heartbeat
 * that would call this again.
 */
export async function settleRotation(
	actor: PeerActor,
	options: SettleOptions = {},
): Promise<RotationSettlement> {
	if (isSettling(actor)) return NOT_HELD;
	const { configDir, agentId, client } = actor;
	return whileSettling(actor, async () => {
		try {
			if (!holdsMlsStore(configDir, agentId)) return NOT_HELD;
			const { keyGen } = loadAgentKeys(configDir, agentId);
			let marker = readRotationMarker(configDir, agentId);
			let keyPackages: KeyPackageRotation = KeyPackageRotation.Current;
			if (marker.key_packages < keyGen) {
				try {
					await drainAndRepublishMlsKeyPackages(configDir, agentId, client);
					marker = { ...marker, key_packages: keyGen };
					writeRotationMarker(configDir, agentId, marker);
					keyPackages = KeyPackageRotation.Republished;
				} catch (err) {
					keyPackages = isMlsKeyNotCurrent(err)
						? KeyPackageRotation.KeyNotCurrent
						: KeyPackageRotation.Pending;
				}
			}
			if (marker.seats >= keyGen) return { key_packages: keyPackages, group_seats: [] };
			const waitUntil = stuckSweeps.get(actorGateKey(actor))?.notBefore ?? 0;
			if (options.background && Date.now() < waitUntil) {
				return { key_packages: keyPackages, group_seats: [] };
			}
			const seats = await selfUpdateStaleLeaves(actor);
			const deferred = seats.some((seat) => seat.status === SeatUpdateStatus.Deferred);
			if (!deferred) writeRotationMarker(configDir, agentId, { ...marker, seats: keyGen });
			noteSweep(actor, deferred);
			return { key_packages: keyPackages, group_seats: seats };
		} catch (err) {
			return { key_packages: KeyPackageRotation.Pending, group_seats: [deferredSeat(err)] };
		}
	});
}
