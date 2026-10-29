import type { MlsClient } from "@rine-network/mls";
import { fetchGroupInfo, mlsFromBase64 } from "./crypto/mls-api.js";
import { noteMlsStateChanged } from "./crypto/mls-state.js";
import { RineApiError } from "./errors.js";
import type { HttpClient } from "./http.js";
import { openPeerMlsClient } from "./mls-allowed.js";
import { admitGroupPeers } from "./mls-allowed-tree.js";
import { postMlsCommit, retryOnEpochConflict } from "./mls-commit.js";
import type { EscrowReport } from "./mls-escrow-report.js";
import { isPeerNotAdmitted, peerNotAdmittedRefusal } from "./mls-peer-refusal.js";
import { settleAfterJoin } from "./mls-escrow-settle.js";
import { sleep } from "./timing.js";

/**
 * The group's only GroupInfo is still tentative (awaiting a peer ACK), so the
 * server has no confirmed join token yet. Distinct from epoch_conflict: a short
 * bounded retry resolves it once a peer ACKs, so it must NOT consume the single
 * epoch-conflict retry below.
 */
function isPendingConfirmation(err: unknown): boolean {
	return err instanceof RineApiError && err.code === "pending_confirmation";
}

const PENDING_RETRY_LIMIT = 3;
const PENDING_RETRY_DELAY_MS = 400;

/**
 * The external join, with the core's final refusal of a tree leaf it cannot
 * verify raised as the typed refusal. Every verifiable peer was admitted before
 * this call, so what is left is a member the server no longer vouches for.
 */
function joinOrRefuse(mls: MlsClient, groupId: string, groupInfo: Uint8Array) {
	try {
		return mls.joinByExternalCommit(groupInfo);
	} catch (err) {
		throw isPeerNotAdmitted(err) ? peerNotAdmittedRefusal(groupId) : err;
	}
}

/**
 * Self-join an MLS-active group via an RFC 9420 external commit.
 *
 * Used for OPEN enrollment, where the rine server adds a joiner to the group
 * with no member in the loop — so nobody mints a Welcome and the joiner is a
 * rine member but not yet an MLS member. The joiner fetches the group's latest
 * published GroupInfo, derives a fresh init_secret against its external_pub,
 * and posts a public External Commit that existing members process (via the
 * EXISTING syncMlsGroup path) to advance the epoch.
 *
 * State is keyed by the RINE group UUID — the same key encrypt/decrypt use — so
 * the joiner can immediately send and receive.
 *
 * Epoch-conflict handling (RFC 9420 §12.4.3.2 + RFC 9750): a GroupInfo is
 * single-use per epoch. If a competing external join lands first, our GroupInfo
 * is stale and our commit targets a stale epoch (members reject). We do a single
 * discard-and-rebuild retry against a freshly-fetched GroupInfo; on a second
 * failure we surface a clear, actionable terminal error rather than looping (an
 * unbounded retry against an advancing epoch is a self-DoS).
 */
export async function externalJoinMlsGroup(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number; escrow: EscrowReport }> {
	const actor = { configDir, agentId, client, extraHeaders };
	const attempt = async (): Promise<{ epoch: number; escrow: EscrowReport }> => {
		const info = await fetchGroupInfo(client, groupId, extraHeaders);
		if (!info.group_info) {
			throw new Error(
				`Cannot self-join MLS group ${groupId}: no published GroupInfo. ` +
					"An existing member must publish one (open enrollment requires a current-epoch GroupInfo).",
			);
		}

		// The external commit meets the group's leaves for the first time, so the
		// chain-verified peers must be admitted before it is built.
		await admitGroupPeers(actor, groupId);
		const mls = openPeerMlsClient(actor);
		const group = joinOrRefuse(mls, groupId, mlsFromBase64(info.group_info));
		const bundle = group.lastCommit();
		if (!bundle) {
			throw new Error(
				`External MLS self-join for group ${groupId} produced no commit`,
			);
		}

		const epoch = await postMlsCommit(
			{ configDir, agentId, client },
			groupId,
			bundle,
			[],
			extraHeaders,
		);
		// Only adopt state AFTER the server accepts the commit (never optimistically).
		const escrow = await settleAfterJoin(actor, groupId, group);
		// An accepted external commit is an establishment: invalidate at the
		// mutation rather than leaving it to whoever called the join.
		noteMlsStateChanged(configDir, agentId, groupId);
		return { epoch, escrow };
	};

	// A brand-new group whose first post-init commit is still tentative has no
	// confirmed join token yet, so the first attempt briefly polls for
	// confirmation. This never un-processes confirmed state — the joiner simply
	// has not yet seen a confirmed GroupInfo; an orphaned own-join is discarded
	// on the next sync, which re-syncs from the confirmed epoch and re-attempts
	// the external join.
	const firstAttempt = async (): Promise<{ epoch: number; escrow: EscrowReport }> => {
		for (let i = 0; ; i++) {
			try {
				return await attempt();
			} catch (err) {
				if (!isPendingConfirmation(err)) throw err;
				if (i >= PENDING_RETRY_LIMIT - 1) {
					throw new Error(
						`Cannot self-join MLS group ${groupId}: GroupInfo is still pending ` +
							"peer confirmation after a brief retry. Try again shortly.",
						{ cause: err },
					);
				}
				await sleep(PENDING_RETRY_DELAY_MS);
			}
		}
	};

	// Only an epoch conflict is recoverable by retrying: a competing join
	// advanced the epoch, so our GroupInfo is stale, and the retry rebuilds once
	// against a freshly fetched one. ANY other error (no GroupInfo, auth failure,
	// malformed blob) is surfaced as it is — retrying would be pointless and the
	// "epoch conflict" wrapper misleading.
	let firstConflict: unknown;
	try {
		return await retryOnEpochConflict(
			() => (firstConflict === undefined ? firstAttempt() : attempt()),
			async (conflict) => {
				firstConflict = conflict;
			},
		);
	} catch (err) {
		if (firstConflict === undefined) throw err;
		const detail = err instanceof Error ? err.message : String(err);
		throw new Error(
			`External MLS self-join failed for group ${groupId} after one retry ` +
				`(likely an epoch conflict — another joiner landed first): ${detail}`,
			{ cause: firstConflict },
		);
	}
}
