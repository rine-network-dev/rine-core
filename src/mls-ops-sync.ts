import {
	processMlsCommit,
	processMlsWelcome,
	removeMemberFromMlsGroup,
} from "./crypto/mls.js";
import {
	fetchGroupInfo,
	fetchHandshakes,
	fetchWelcomes,
	mlsAck,
	mlsCommit,
	mlsFromBase64,
	mlsNack,
	mlsToBase64,
} from "./crypto/mls-api.js";
import {
	loadMlsState,
	saveMlsState,
	listPrivateKeyPackages,
	deletePrivateKeyPackage,
} from "./crypto/mls-state.js";
import { externalJoinMlsGroup } from "./mls-ops-join.js";
import type { HttpClient } from "./http.js";
import { decode, MlsError, mlsMessageDecoder, wireformats, type MlsWelcomeMessage } from "ts-mls";

/**
 * Fetch all pending MLS welcomes for an agent and process them, establishing
 * local group state for each group the agent has been added to.
 */
export async function processMlsWelcomes(
	configDir: string,
	agentId: string,
	client: HttpClient,
): Promise<{ processed: number; groupIds: string[] }> {
	const { welcomes } = await fetchWelcomes(client, agentId);
	const storedPkgs = listPrivateKeyPackages(configDir, agentId);
	const pkgByRef = new Map(storedPkgs.map((p) => [p.ref, p]));
	const groupIds: string[] = [];

	for (const welcome of welcomes) {
		// State must be keyed by the rine group UUID (carried on the welcome
		// delivery), not the MLS-internal group id — that is the identifier
		// `decryptGroupMessage`/`encryptMlsGroupMessage` and the MLS API routes
		// use. Skip welcomes the server couldn't associate with a group.
		const rineGroupId = welcome.group_id;
		if (!rineGroupId) continue;
		const welcomeBlob = mlsFromBase64(welcome.blob);
		// Decode welcome to find the matching key package ref
		const msg = decode(mlsMessageDecoder, welcomeBlob);
		if (!msg || msg.wireformat !== wireformats.mls_welcome) {
			throw new Error("Failed to decode welcome message");
		}
		const welcomeData = (msg as MlsWelcomeMessage).welcome;

		let matched: { publicBlob: Uint8Array; privateBlob: Uint8Array; refHex: string } | null = null;
		for (const secret of welcomeData.secrets) {
			const refHex = Buffer.from(secret.newMember).toString("hex");
			const pkg = pkgByRef.get(refHex);
			if (pkg) {
				matched = { publicBlob: pkg.publicBlob, privateBlob: pkg.privateBlob, refHex };
				break;
			}
		}
		if (!matched) {
			throw new Error("No matching private key package found for welcome");
		}

		const { stateBlob, epoch, cipherSuite } = await processMlsWelcome(
			welcomeBlob,
			matched.publicBlob,
			matched.privateBlob,
		);
		saveMlsState(configDir, agentId, rineGroupId, stateBlob, {
			groupId: rineGroupId,
			epoch,
			cipherSuite,
		});
		deletePrivateKeyPackage(configDir, agentId, Buffer.from(matched.refHex, "hex"));
		groupIds.push(rineGroupId);
	}

	return { processed: groupIds.length, groupIds };
}

/**
 * Remove a member from an MLS group by leaf index and post the remove commit.
 */
export async function removeMlsGroupMember(
	configDir: string,
	agentId: string,
	groupId: string,
	leafIndex: number,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number }> {
	const stored = loadMlsState(configDir, agentId, groupId);
	if (!stored) throw new Error(`No MLS state for group ${groupId}`);

	const { commitBlob, updatedState, groupInfo, epoch: commitEpoch } =
		await removeMemberFromMlsGroup(stored.stateBlob, leafIndex);

	const commitResp = await mlsCommit(
		client,
		groupId,
		{ commit: mlsToBase64(commitBlob), group_info: mlsToBase64(groupInfo), epoch: commitEpoch },
		extraHeaders,
	);

	const epoch = commitResp.epoch ?? commitEpoch;
	saveMlsState(configDir, agentId, groupId, updatedState, {
		...stored.metadata,
		epoch,
	});

	return { epoch };
}

/**
 * Sync local MLS group state by fetching and applying all commits posted
 * since the current epoch.
 */
export async function syncMlsGroup(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number; processed: number }> {
	const stored = loadMlsState(configDir, agentId, groupId);
	if (!stored) throw new Error(`No MLS state for group ${groupId}`);

	const currentEpoch = stored.metadata.epoch;
	const { handshakes } = await fetchHandshakes(
		client,
		groupId,
		currentEpoch,
		extraHeaders,
	);

	let currentState = stored.stateBlob;
	let epoch = currentEpoch;
	let processed = 0;

	for (const handshake of handshakes) {
		const commitBlob = mlsFromBase64(handshake.blob);
		let result: { updatedState: Uint8Array; epoch: number };
		try {
			result = await processMlsCommit(currentState, commitBlob);
		} catch (err) {
			if (err instanceof MlsError) {
				// H4 (MEDIUM-1): a processMlsCommit failure has TWO causes that must
				// be told apart. (1) The commit is genuinely garbage → NACK so the
				// server rolls it back. (2) Our OWN local state is orphaned: our
				// tentative self-join was NACK'd/timed-out and the server rolled the
				// epoch back below our local epoch, so a fresh peer commit can never
				// apply to our stale branch. NACK-looping case (2) is a permanent
				// per-member denial-of-participation (the quorum=1 exploit). Detect
				// the orphaned state via the server's confirmed-epoch signal and
				// re-bootstrap instead of NACKing.
				const reconciled = await reconcileIfOrphaned(
					configDir, agentId, groupId, epoch, client, extraHeaders,
				);
				if (reconciled !== null) {
					// Orphaned: re-bootstrapped via external join (fresh state saved
					// only on server acceptance). Stop this sync; the next starts from
					// the fresh epoch.
					return { epoch: reconciled, processed };
				}
				// Genuinely garbage → exactly one NACK, then abort (save nothing).
				// The server lazily rolls the tentative commit back.
				await emitNack(client, groupId, handshake, err, extraHeaders);
				break;
			}
			// Transport/other error → emit neither; rethrow so the next sync retries.
			throw err;
		}
		currentState = result.updatedState;
		epoch = result.epoch;
		processed += 1;
		// Persist the advance BEFORE ACKing so a crash mid-ACK never confirms an
		// epoch we did not save locally.
		saveMlsState(configDir, agentId, groupId, currentState, {
			...stored.metadata,
			epoch,
		});
		await emitAck(client, groupId, handshake, extraHeaders);
	}

	return { epoch, processed };
}

/**
 * H4 (MEDIUM-1) reconcile: detect whether a processMlsCommit failure is caused
 * by our OWN local state being orphaned (ahead of the server's confirmed epoch)
 * rather than by a genuinely un-processable commit.
 *
 * The orphan signal: the server's confirmed GroupInfo epoch is BELOW our local
 * epoch. That can only happen if our own tentative commit was rolled back — the
 * server cannot serve a confirmed token as high as the epoch we locally hold. In
 * that case we re-bootstrap via an external self-join from mls_confirmed_epoch
 * (no un-processing of honestly-confirmed state — the B1 win); the re-join only
 * overwrites the stale local state once the server accepts the commit, so a
 * mid-flight re-join failure leaves the stale state intact for the next sync to
 * retry rather than stranding the agent stateless. Returns the re-bootstrapped
 * epoch on reconcile, or null when the state is NOT orphaned (caller should NACK
 * the garbage commit).
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

	// Orphaned: re-bootstrap from the confirmed epoch. externalJoinMlsGroup fetches
	// the confirmed GroupInfo, re-joins, and (only on server acceptance) saveMlsState
	// recreates the state dir + overwrites the stale branch. We deliberately do NOT
	// delete the stale state first: if the re-join throws (no published GroupInfo,
	// transport failure, exhausted epoch-conflict retry) the stale state survives so
	// the next syncMlsGroup re-enters this path and retries — deleting first would
	// strand the agent permanently stateless on a mid-flight failure.
	const { epoch } = await externalJoinMlsGroup(
		configDir, agentId, groupId, client, extraHeaders,
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
	err: MlsError,
	extraHeaders?: Record<string, string>,
): Promise<void> {
	try {
		await mlsNack(
			client,
			groupId,
			{ object_id: handshake.id, epoch: handshake.epoch ?? 0, reason: err.message.slice(0, 256) },
			extraHeaders,
		);
	} catch {
		// best-effort: a timeout-based rollback still self-heals the group
	}
}
