import {
	fetchGroupInfo,
	fetchWelcomes,
	mlsFromBase64,
} from "./crypto/mls-api.js";
import { openMlsClient } from "./crypto/mls.js";
import { bytesToUuid } from "./crypto/sender-keys-helpers.js";
import { RineApiError } from "./errors.js";
import type { HttpClient } from "./http.js";
import { postMlsCommit } from "./mls-commit.js";
import { replenishMlsKeyPackages } from "./mls-keypackages.js";

/**
 * Fetch all pending MLS welcomes for an agent and process them, establishing
 * local group state for each group the agent has been added to.
 *
 * The native core matches the Welcome to the private half of the KeyPackage it
 * was sealed to and consumes that half on `save()`, so nothing here has to
 * bookkeep key packages.
 */
export async function processMlsWelcomes(
	configDir: string,
	agentId: string,
	client: HttpClient,
): Promise<{ processed: number; groupIds: string[] }> {
	const { welcomes } = await fetchWelcomes(client, agentId);
	const mls = openMlsClient(configDir, agentId);
	const groupIds: string[] = [];

	for (const welcome of welcomes) {
		// State is keyed by the rine group UUID (carried on the welcome delivery),
		// which is also what the founder put in the MLS group id. Skip welcomes the
		// server could not associate with a group.
		const rineGroupId = welcome.group_id;
		if (!rineGroupId) continue;

		const group = mls.joinFromWelcome(mlsFromBase64(welcome.blob));
		const joinedId = bytesToUuid(group.groupId());
		if (joinedId !== rineGroupId.toLowerCase()) {
			throw new Error(
				`MLS welcome for group ${rineGroupId} carries group id ${joinedId}`,
			);
		}
		group.save();
		groupIds.push(rineGroupId);
	}

	// Each processed welcome consumed one key package. This is the only path on
	// which an agent's OWN inventory shrinks, so it is where replenishment
	// matters most: without it the agent silently becomes un-addable once the
	// onboarding batch runs out.
	if (groupIds.length > 0) {
		await replenishMlsKeyPackages(configDir, agentId, client);
	}

	return { processed: groupIds.length, groupIds };
}

/** A commit was rejected because our GroupInfo targeted a stale epoch. */
function isEpochConflict(err: unknown): boolean {
	return err instanceof RineApiError && err.code === "epoch_conflict";
}

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

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
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
): Promise<{ epoch: number }> {
	const attempt = async (): Promise<{ epoch: number }> => {
		const info = await fetchGroupInfo(client, groupId, extraHeaders);
		if (!info.group_info) {
			throw new Error(
				`Cannot self-join MLS group ${groupId}: no published GroupInfo. ` +
					"An existing member must publish one (open enrollment requires a current-epoch GroupInfo).",
			);
		}

		const mls = openMlsClient(configDir, agentId);
		const group = mls.joinByExternalCommit(mlsFromBase64(info.group_info));
		const bundle = group.lastCommit();
		if (!bundle) {
			throw new Error(
				`External MLS self-join for group ${groupId} produced no commit`,
			);
		}

		const epoch = await postMlsCommit(
			client,
			groupId,
			group,
			bundle,
			[],
			extraHeaders,
		);
		// Only adopt state AFTER the server accepts the commit (never optimistically).
		group.save();
		return { epoch };
	};

	// A brand-new group whose first post-init commit is still tentative has no
	// confirmed join token yet. Briefly poll for confirmation, capturing the
	// FIRST non-pending error so it flows into the epoch-conflict handler below
	// WITHOUT a duplicate attempt. This never un-processes confirmed state — the
	// joiner simply has not yet seen a confirmed GroupInfo; an orphaned own-join
	// is discarded on the next sync, which re-syncs from the confirmed epoch and
	// re-attempts the external join.
	let firstErr: unknown;
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

	// Only an epoch conflict is recoverable by retrying: a competing join
	// advanced the epoch, so our GroupInfo is stale. ANY other error (no
	// GroupInfo, auth failure, malformed blob) is surfaced immediately —
	// retrying would be pointless and the "epoch conflict" wrapper misleading.
	if (!isEpochConflict(firstErr)) throw firstErr;

	// Single discard-and-rebuild retry against a fresh GroupInfo (the competing
	// join already advanced the epoch, so a current GroupInfo should be
	// available immediately).
	try {
		return await attempt();
	} catch (retryErr) {
		const detail =
			retryErr instanceof Error ? retryErr.message : String(retryErr);
		throw new Error(
			`External MLS self-join failed for group ${groupId} after one retry ` +
				`(likely an epoch conflict — another joiner landed first): ${detail}`,
			{ cause: firstErr },
		);
	}
}
