import { externalJoinMlsGroup as cryptoExternalJoin } from "./crypto/mls.js";
import {
	fetchGroupInfo,
	mlsCommit,
	mlsFromBase64,
	mlsToBase64,
} from "./crypto/mls-api.js";
import { saveMlsState } from "./crypto/mls-state.js";
import { loadAgentKeys } from "./crypto/keys.js";
import { RineApiError } from "./errors.js";
import type { HttpClient } from "./http.js";

/** A commit was rejected because our GroupInfo targeted a stale epoch. */
function isEpochConflict(err: unknown): boolean {
	return (
		err instanceof RineApiError &&
		err.code === "epoch_conflict"
	);
}

/**
 * The group's only GroupInfo is still tentative (awaiting a peer ACK), so the
 * server has no confirmed join token yet (H4). Distinct from epoch_conflict: a
 * short bounded retry resolves it once a peer ACKs, so it must NOT consume the
 * single epoch-conflict retry below.
 */
function isPendingConfirmation(err: unknown): boolean {
	return err instanceof RineApiError && err.code === "pending_confirmation";
}

const CIPHER_SUITE = 0x0001;
const PENDING_RETRY_LIMIT = 3;
const PENDING_RETRY_DELAY_MS = 400;

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Self-join an MLS-active group via an RFC 9420 external commit (Phase 6).
 *
 * Used for OPEN enrollment, where the rine server adds a joiner to the group
 * with no member in the loop — so nobody mints a Welcome and the joiner is a
 * rine member but not yet an MLS member. The joiner fetches the group's latest
 * published GroupInfo, derives a fresh init_secret against its external_pub,
 * and posts a public External Commit that existing members process (via the
 * EXISTING syncMlsGroup path) to advance the epoch.
 *
 * State is keyed by the RINE group UUID (groupId) — the same key
 * encrypt/decryptGroupMessage use — so the joiner can immediately send/receive.
 *
 * Epoch-conflict handling (research-guided, RFC 9420 §12.4.3.2 + RFC 9750):
 * a GroupInfo is single-use per epoch. If a competing external join lands first,
 * our GroupInfo is stale and our commit targets a stale epoch (members reject).
 * We do a single discard-and-rebuild retry against a freshly-fetched GroupInfo;
 * on a second failure we surface a clear, actionable terminal error rather than
 * looping (an unbounded retry against an advancing epoch is a self-DoS).
 */
export async function externalJoinMlsGroup(
	configDir: string,
	agentId: string,
	groupId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number }> {
	const keys = loadAgentKeys(configDir, agentId);

	const attempt = async (): Promise<{ epoch: number }> => {
		const info = await fetchGroupInfo(client, groupId, extraHeaders);
		if (!info.group_info) {
			throw new Error(
				`Cannot self-join MLS group ${groupId}: no published GroupInfo. ` +
					"An existing member must publish one (open enrollment requires a current-epoch GroupInfo).",
			);
		}
		const groupInfoBlob = mlsFromBase64(info.group_info);

		const joined = await cryptoExternalJoin(keys.signing.privateKey, groupInfoBlob);

		const commitResp = await mlsCommit(
			client,
			groupId,
			{
				commit: mlsToBase64(joined.commitBlob),
				group_info: mlsToBase64(joined.groupInfo),
				epoch: joined.epoch,
			},
			extraHeaders,
		);

		const epoch = commitResp.epoch ?? joined.epoch;
		// Only adopt state AFTER the server accepts the commit (never optimistically).
		saveMlsState(configDir, agentId, groupId, joined.stateBlob, {
			groupId,
			epoch,
			cipherSuite: CIPHER_SUITE,
		});
		return { epoch };
	};

	// H4 (Q6): a brand-new group whose first post-init commit is still tentative
	// has no confirmed join token yet. Briefly poll for confirmation, capturing
	// the FIRST non-pending error so it flows into the epoch-conflict handler
	// below WITHOUT a duplicate attempt. This never un-processes confirmed state
	// — the joiner simply has not yet seen a confirmed GroupInfo (the B1 win: no
	// client-state rollback of honest members; an orphaned own-join is discarded
	// on the next sync, which re-syncs from mls_confirmed_epoch and re-attempts
	// the external join).
	let firstErr: unknown = undefined;
	for (let i = 0; ; i++) {
		try {
			return await attempt();
		} catch (err) {
			if (!isPendingConfirmation(err)) {
				firstErr = err;
				break;
			}
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

	{
		// Only an epoch conflict is recoverable by retrying: a competing join
		// advanced the epoch, so our GroupInfo is stale. ANY other error (no
		// GroupInfo, auth failure, malformed blob) is surfaced immediately —
		// retrying would be pointless and the "epoch conflict" wrapper misleading.
		if (!isEpochConflict(firstErr)) throw firstErr;

		// Single discard-and-rebuild retry against a fresh GroupInfo (the
		// competing join already advanced the epoch, so a current GroupInfo
		// should be available immediately).
		try {
			return await attempt();
		} catch (retryErr) {
			const detail = retryErr instanceof Error ? retryErr.message : String(retryErr);
			throw new Error(
				`External MLS self-join failed for group ${groupId} after one retry ` +
					`(likely an epoch conflict — another joiner landed first): ${detail}`,
				{ cause: firstErr },
			);
		}
	}
}
