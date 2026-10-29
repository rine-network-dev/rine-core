import { fetchGroupInfo } from "./crypto/mls-api.js";
import type { HttpClient } from "./http.js";
import type { EscrowReport } from "./mls-escrow-report.js";
import { externalJoinMlsGroup } from "./mls-external-join.js";

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
 * re-bootstrapped epoch and the escrow the external join reported, or null when
 * the state is NOT orphaned (the caller should NACK the commit).
 */
export async function reconcileIfOrphaned(
	configDir: string,
	agentId: string,
	groupId: string,
	localEpoch: number,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number; escrow: EscrowReport } | null> {
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

	const { epoch, escrow } = await externalJoinMlsGroup(
		configDir,
		agentId,
		groupId,
		client,
		extraHeaders,
	);
	return { epoch, escrow };
}
