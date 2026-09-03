import {
	fetchGroupInfo,
	fetchHandshakes,
	mlsAck,
	mlsFromBase64,
	mlsNack,
} from "./crypto/mls-api.js";
import { isUnprocessableCommit } from "./crypto/mls-errors.js";
import { openMlsGroup } from "./crypto/mls.js";
import type { HttpClient } from "./http.js";
import { mlsHeartbeat } from "./mls-heartbeat.js";
import { externalJoinMlsGroup } from "./mls-ops-join.js";

export interface MlsSyncResult {
	epoch: number;
	processed: number;
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
): Promise<MlsSyncResult> {
	await mlsHeartbeat({ configDir, agentId, client }, "gated");
	const group = openMlsGroup(configDir, agentId, groupId);
	const { handshakes } = await fetchHandshakes(
		client,
		groupId,
		group.epoch(),
		extraHeaders,
	);

	let epoch = group.epoch();
	let processed = 0;

	for (const handshake of handshakes) {
		try {
			epoch = group.applyCommit(mlsFromBase64(handshake.blob));
		} catch (err) {
			// A failure here has THREE causes that must be told apart. A local
			// failure (store I/O, a retired handle) is not the commit's fault →
			// rethrow so the next sync retries. Our OWN state may be orphaned: our
			// tentative self-join was NACK'd or timed out and the server rolled the
			// epoch back below ours, so no peer commit can ever apply to our stale
			// branch — NACK-looping that is a permanent per-member denial of
			// participation, so re-bootstrap instead. Only what is left is a
			// genuinely un-processable commit, which earns exactly one NACK.
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
				return { epoch: reconciled, processed, evicted: false };
			}
			await emitNack(client, groupId, handshake, err, extraHeaders);
			break;
		}
		processed += 1;
		// Persist the advance BEFORE ACKing so a crash mid-ACK never confirms an
		// epoch we did not save locally.
		group.save();
		await emitAck(client, groupId, handshake, extraHeaders);
		if (!group.isActive()) return { epoch, processed, evicted: true };
	}

	return { epoch, processed, evicted: !group.isActive() };
}

/**
 * Detect whether an un-processable commit is caused by our OWN local state
 * being orphaned (ahead of the server's confirmed epoch) rather than by the
 * commit itself.
 *
 * The orphan signal: the server's confirmed GroupInfo epoch is BELOW our local
 * epoch. That can only happen if our own tentative commit was rolled back — the
 * server cannot serve a confirmed token as high as the epoch we locally hold. In
 * that case we re-bootstrap via an external self-join from the confirmed epoch;
 * the re-join only overwrites the stale local state once the server accepts the
 * commit, so a mid-flight failure leaves the stale state intact for the next
 * sync to retry rather than stranding the agent stateless. Returns the
 * re-bootstrapped epoch, or null when the state is NOT orphaned (the caller
 * should NACK the commit).
 */
async function reconcileIfOrphaned(
	configDir: string,
	agentId: string,
	groupId: string,
	localEpoch: number,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<number | null> {
	let confirmedEpoch: number | null;
	try {
		const info = await fetchGroupInfo(client, groupId, extraHeaders);
		confirmedEpoch = info.epoch;
	} catch {
		// pending_confirmation / transport hiccup: cannot prove orphaned → NACK.
		return null;
	}
	// Not orphaned: the server's confirmed epoch is at or above our local epoch,
	// so our state is on the canonical branch and the failing commit is garbage.
	if (confirmedEpoch === null || confirmedEpoch >= localEpoch) return null;

	const { epoch } = await externalJoinMlsGroup(
		configDir,
		agentId,
		groupId,
		client,
		extraHeaders,
	);
	return epoch;
}

/** Fire-and-forget ACK; a failed ACK must never fail the sync. */
async function emitAck(
	client: HttpClient,
	groupId: string,
	handshake: { id: string },
	extraHeaders?: Record<string, string>,
): Promise<void> {
	try {
		await mlsAck(client, groupId, { object_id: handshake.id }, extraHeaders);
	} catch {
		// best-effort: the commit still confirms once any peer ACKs
	}
}

/** Fire-and-forget NACK; a failed NACK must never fail the sync. */
async function emitNack(
	client: HttpClient,
	groupId: string,
	handshake: { id: string; epoch: number | null },
	err: unknown,
	extraHeaders?: Record<string, string>,
): Promise<void> {
	const reason = err instanceof Error ? err.message : String(err);
	try {
		await mlsNack(
			client,
			groupId,
			{
				object_id: handshake.id,
				epoch: handshake.epoch ?? 0,
				reason: reason.slice(0, 256),
			},
			extraHeaders,
		);
	} catch {
		// best-effort: a timeout-based rollback still self-heals the group
	}
}
