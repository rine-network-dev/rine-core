import { fetchHandshakes, mlsFromBase64 } from "./crypto/mls-api.js";
import { type MlsHandshakeFeed, fetchHandshakeFeed } from "./crypto/mls-handshake-feed.js";
import {
	MLS_ERR_PEER_NOT_ADMITTED,
	isUnprocessableCommit,
	mlsErrorCode,
} from "./crypto/mls-errors.js";
import type { HttpClient } from "./http.js";
import { openPeerMlsGroup } from "./mls-allowed.js";
import { admitGroupPeers } from "./mls-allowed-tree.js";
import { admitRefusedPeers } from "./mls-commit-admission.js";
import { drainEscrow } from "./mls-escrow-drain.js";
import {
	type EscrowReport,
	emptyReport,
	mergeReports,
	reportDrain,
	reportOf,
} from "./mls-escrow-report.js";
import { mlsHeartbeat } from "./mls-heartbeat.js";
import { emitAck, emitNack } from "./mls-ops-sync-ack.js";
import { reconcileIfOrphaned } from "./mls-ops-sync-orphan.js";
import {
	PendingCommitOutcome,
	type PendingCommitSettlement,
	settlePendingCommit,
} from "./mls-pending-commit.js";

export interface MlsSyncOptions {
	/**
	 * Report, in the result, the epochs a background sweep lost for this group.
	 * They are reported once, so only a caller whose result reaches a reader sets
	 * it: a sync run for its side effect leaves them for a result that does.
	 */
	carryUnreported?: boolean;
}

export interface MlsSyncResult {
	epoch: number;
	processed: number;
	/** The escrow work this sync did, one drain per applied commit. */
	escrow: EscrowReport;
	/**
	 * True when a commit applied by THIS sync evicted the member. Eviction is the
	 * correct outcome of a valid commit, not an error: the group keeps decrypting
	 * the backlog it already holds secrets for, but can no longer send or commit.
	 *
	 * In-session only — the native core does not persist eviction, so a later
	 * process reloads the group as active and learns otherwise from the first
	 * operation that refuses.
	 */
	evicted: boolean;
	/** Set only when the handle held a pending self-update commit this sync settled. */
	pendingCommit?: PendingCommitSettlement;
}

/**
 * Sync local MLS group state by fetching and applying every commit posted since
 * the group's current epoch.
 *
 * Carries the acting agent's key-package heartbeat, which is what covers the
 * verbs that post no commit — the catch-up behind an ordinary read, the replay
 * rung of a recovery, and the retries behind a removal or a reclamation. It
 * beats BEFORE the group handle is opened, so only one MLS handle for this
 * store root is ever live at a time.
 */
export async function syncMlsGroup(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
	{ carryUnreported = false }: MlsSyncOptions = {},
): Promise<MlsSyncResult> {
	await mlsHeartbeat({ configDir, agentId, client }, "gated");
	const actor = { configDir, agentId, client, extraHeaders };
	const group = openPeerMlsGroup(actor, groupId);
	// A holding handle names its pending epoch, and the answer says where its own
	// commit stands. A handle with nothing pending sends the plain request.
	const pendingEpoch = group.pendingCommitEpoch();
	const feed: MlsHandshakeFeed =
		pendingEpoch === null
			? await fetchHandshakes(client, groupId, group.epoch(), extraHeaders)
			: await fetchHandshakeFeed(client, groupId, group.epoch(), extraHeaders, pendingEpoch);
	const { handshakes, pendingCommit } = feed;

	let epoch = group.epoch();
	let processed = 0;
	let escrow = emptyReport();
	const reportDrained = (outcome: Parameters<typeof reportOf>[0]): EscrowReport =>
		carryUnreported ? reportDrain(actor, groupId, outcome) : reportOf(outcome);

	// A pending self-update commit is settled before anything else: a held one
	// stops the sync, and an applied one moves the epoch the feed was read at.
	const settled = await settlePendingCommit(actor, groupId, group, pendingCommit);
	const pending = settled === null ? {} : { pendingCommit: settled };
	if (settled?.outcome === PendingCommitOutcome.Held) {
		return {
			epoch: group.epoch(),
			processed: 0,
			evicted: false,
			escrow: reportDrained({ gaps: [] }),
			...pending,
		};
	}
	if (settled?.outcome === PendingCommitOutcome.Applied) {
		epoch = settled.epoch;
		escrow = mergeReports(escrow, reportDrained(settled.drain ?? { gaps: [] }));
	}

	// Applying a peer's commit meets its leaves for the first time, so the
	// chain-verified peers must be admitted before the loop. An idle sync has no
	// handshakes and must stay free of the extra reads.
	if (handshakes.length > 0) await admitGroupPeers(actor, groupId);

	for (const handshake of handshakes) {
		// The feed was read before the pending commit was applied, so a handshake
		// at or below the epoch now held is already in this handle.
		if (handshake.epoch !== null && handshake.epoch <= epoch) continue;
		try {
			epoch = await admitRefusedPeers(actor, group, () =>
				group.applyCommit(mlsFromBase64(handshake.blob)),
			);
		} catch (err) {
			// A failure here has THREE causes that must be told apart. A local
			// failure (store I/O, a retired handle) is not the commit's fault →
			// rethrow so the next sync retries. Our OWN state may be orphaned: our
			// tentative self-join was NACK'd or timed out and the server rolled the
			// epoch back below ours, so no peer commit can ever apply to our stale
			// branch — NACK-looping that is a permanent per-member denial of
			// participation, so re-bootstrap instead. Only what is left is a
			// genuinely un-processable commit, which earns exactly one NACK. A
			// refusal naming a peer that cannot be verified is NACKed once and then
			// thrown, so the caller sees the stable code and recovery can resync
			// past it.
			if (!isUnprocessableCommit(err)) throw err;
			const reconciled = await reconcileIfOrphaned(
				configDir,
				agentId,
				groupId,
				epoch,
				client,
				extraHeaders,
			);
			if (reconciled !== null) {
				// Re-bootstrapped via external join (fresh state saved only on server
				// acceptance). Stop here; the next sync starts from the fresh epoch.
				return {
					epoch: reconciled.epoch,
					processed,
					evicted: false,
					escrow: mergeReports(escrow, reconciled.escrow),
					...pending,
				};
			}
			await emitNack(client, groupId, handshake, err, extraHeaders);
			if (mlsErrorCode(err) === MLS_ERR_PEER_NOT_ADMITTED) throw err;
			break;
		}
		processed += 1;
		// Persist the advance BEFORE ACKing so a crash mid-ACK never confirms an
		// epoch we did not save locally.
		escrow = mergeReports(
			escrow,
			reportDrained(await drainEscrow(actor, groupId, group)),
		);
		await emitAck(client, groupId, handshake, extraHeaders);
		if (!group.isActive()) {
			return { epoch, processed, evicted: true, escrow, ...pending };
		}
	}

	// An idle sync drains nothing, so it takes the news of a background loss itself.
	return {
		epoch,
		processed,
		evicted: !group.isActive(),
		escrow: mergeReports(escrow, reportDrained({ gaps: [] })),
		...pending,
	};
}
