/**
 * The INBOUND half of sender keys: taking delivery of other agents' keys, and
 * the one-shot recovery a group read performs when the key it needs has not
 * arrived yet.
 *
 * Its outbound twin is `sender-key-ops.ts` — minting this agent's own key,
 * distributing it, rotating it, retiring it. The two halves share nothing but
 * the on-disk state file, and this one performs no distribution at all.
 */
import { ACTING_AGENT_HEADER } from "./actor.js";
import type { MessageRead, PaginatedResponse } from "./api-types.js";
import { SENDER_KEY_DISTRIBUTION_TYPE } from "./control-frames.js";
import { ingestSenderKeyDistribution } from "./crypto/ingest.js";
import { type DecryptResult, decryptMessage } from "./crypto/message.js";
import {
	liftRetirementIfMember,
	senderKeysRetired,
} from "./crypto/sender-keys-helpers.js";
import { fetchGroupMembers } from "./group-members.js";
import type { HttpClient } from "./http.js";
import { decryptGroupMessage } from "./message-group.js";
import { withPeekHeader } from "./message-words.js";
import { ackAfterRead, isSettledRow } from "./read-ack.js";
import type { SenderKeyScan } from "./sender-key-scan.js";
import {
	isCached,
	recordMissing,
	settleRowFailures,
} from "./sender-key-negative-cache.js";
import {
	SenderKeyUnavailableError,
	unknownSenderKeyId,
} from "./sender-key-words.js";

/**
 * Whether a retired group's keys may be taken again, lifting the marker when
 * the server still names this agent a member.
 *
 * 🔴 This is the READ path's half of the lift, and without it the marker
 * is spent only by SENDING: `getOrCreateSenderKey` is reachable from a group
 * send and from nothing else, so a re-admitted agent that reads before it sends
 * — a monitor, or any connector that only replies to what it could decrypt —
 * refused every distribution its new peers made it, permanently, and could open
 * nothing they posted.
 *
 * A membership read that fails is not a lift: a departed agent is refused
 * `GET /groups/{id}/members` outright, and a transport failure proves nothing,
 * so both keep the refusal.
 *
 * Exported because the recovery verb has to tell "nothing was waiting" from
 * "this agent's own material was retired here and nothing lifted that
 * retirement" — two facts the scan below collapses into the same `0`, and only
 * one of which has a remedy the operator can act on. 🔴 The second is NOT "the
 * server said this agent is not a member": the gate above fails closed, so a
 * membership read that never got an answer produces it too, and a caller
 * rendering it must leave a retry open. Asking it first costs no extra
 * round trip: the scan re-checks, and by then the marker has either been lifted
 * or was never there, so the second check reads local disk alone.
 */
export async function retirementBlocksRead(
	client: HttpClient,
	configDir: string,
	agentId: string,
	groupId: string,
): Promise<boolean> {
	if (!senderKeysRetired(configDir, agentId, groupId)) return false;
	let members: string[];
	try {
		// Read rather than inferred: membership is the server's to state, and a
		// client that decided it locally could un-retire material it left with.
		members = (await fetchGroupMembers(client, groupId)).map(
			(m) => m.agent_id,
		);
	} catch {
		return true;
	}
	return !liftRetirementIfMember(configDir, agentId, groupId, members);
}

/**
 * Fetch pending sender key distributions from the inbox and ingest them.
 * Used by `read` and `stream` to auto-recover when a sender key is missing.
 *
 * Optionally short-circuits once `targetSenderKeyId` is ingested.
 * Returns the number of newly ingested keys.
 *
 * With the group, the key id and its `senderAgentId` all named, a COMPLETE scan
 * that installed nothing is remembered for 15 minutes ({@link isCached}), and
 * the next ask for the same key throws {@link SenderKeyUnavailableError}
 * without listing the inbox again. A distribution from that sender clears it.
 * Complete means nothing was left unopened and no row threw that may still
 * heal ({@link ROW_FAILURE_LIMIT} bounds how long one row may keep saying so).
 *
 * 🔴 Complete also means the whole listing fits the one page read, and the
 * listing is every distribution ever sent to this agent, read ones included,
 * newest first. An agent past 100 of them never caches: nothing on the page
 * says the rows behind it hold no key still waiting, so it rescans per read
 * rather than state a miss it did not prove.
 *
 * 🔴 That number is what was INSTALLED, and it is not an inventory of the
 * inbox: this returns `0` with distribution DMs still listed (one already
 * installed, one with no server-authenticated sender, one whose envelope
 * refused, one past the un-paginated `limit: 100` the scan reads). A caller
 * that renders the zero may say nothing was installed and may not say nothing
 * was waiting.
 *
 * 🔴 Its return type is `number` and stays `number`: every read path calls this,
 * so widening it is a breaking change on the hottest path there is. The one
 * caller that needs more, the sync verb, calls {@link scanPendingSKDistributions}
 * instead, which is never cached, so an explicit sync always scans.
 */
export async function fetchAndIngestPendingSKDistributions(
	client: HttpClient,
	configDir: string,
	agentId: string,
	targetSenderKeyId?: string,
	groupId?: string,
	senderAgentId?: string,
): Promise<number> {
	const missing =
		targetSenderKeyId && groupId && senderAgentId
			? { agentId, groupId, senderAgentId, keyId: targetSenderKeyId }
			: null;
	if (missing) {
		const { groupId: g, senderAgentId: s, keyId: k } = missing;
		if (isCached(agentId, g, s, k)) throw new SenderKeyUnavailableError(k, g);
	}
	const scan = await scanPendingSKDistributions(
		client,
		configDir,
		agentId,
		targetSenderKeyId,
		groupId,
	);
	const complete = scan.unscanned === 0 && scan.failed === 0;
	if (missing && scan.ingested === 0 && complete) recordMissing(missing);
	return scan.ingested;
}

/**
 * The same pass, reporting what it did not reach as well as what it installed.
 *
 * The whole of the scan lives here, so the cached wrapper above and the sync
 * verb (`recoverGroup`, which reads the second number and always scans) cannot
 * disagree about what a pass does.
 *
 * 🔴 A leave-time wipe alone would be point-in-time: the DMs that carried every
 * peer key are still listed here. This does NOT route around the retirement
 * marker. The group a distribution belongs to is only known after the DM is
 * decrypted, so the refusal lives in {@link ingestSenderKeyDistribution}, and
 * a retired group's keys are counted as not ingested.
 *
 * `groupId` names the group whose read missed, and every caller that has one
 * must pass it: it is the only thing that can spend a retirement on the read
 * path, and the CLI's `read`/`stream` and the TypeScript SDK call this
 * directly. Omitting it keeps the group's material refused, which fails closed.
 */
export async function scanPendingSKDistributions(
	client: HttpClient,
	configDir: string,
	agentId: string,
	targetSenderKeyId?: string,
	groupId?: string,
): Promise<SenderKeyScan> {
	// A retired group refuses everything the scan below would ingest, so the
	// inbox fetch — one list call plus one GET and one decrypt per pending DM —
	// buys nothing unless the server still names this agent a member.
	if (
		groupId &&
		(await retirementBlocksRead(client, configDir, agentId, groupId))
	)
		return { ingested: 0, unscanned: 0, failed: 0 };
	const inbox = (await client.get(`/agents/${agentId}/messages`, {
		type: SENDER_KEY_DISTRIBUTION_TYPE,
		limit: 100,
	})) as PaginatedResponse<MessageRead>;
	// `total` counts every row the server matched, the page holds at most the
	// hundred asked for, and the difference is the part of the inbox that was
	// never listed. The list route computes the total by default
	// (`include_total`, `src/rine/api/messages_inbox.py`) but a server that omitted it
	// leaves nothing to subtract — and a shortfall invented out of a missing
	// field is worse than none, so an absent total is no shortfall.
	const beyondPage =
		typeof inbox.total === "number"
			? Math.max(0, inbox.total - inbox.items.length)
			: 0;

	let ingested = 0;
	const openedIds: string[] = [];
	const failedIds: string[] = [];
	// Counted rather than derived from the page length, because the targeted
	// arm below `break`s: the rows it never reached were listed and not opened,
	// which is the same state as the rows past the end of the page.
	let opened = 0;
	// Marked in ONE request after the scan: one POST per row would be up to a
	// hundred extra requests, where the fetch used to mark for free.
	const settledIds: string[] = [];
	for (const msg of inbox.items) {
		opened++;
		openedIds.push(msg.id);
		try {
			// Say which agent is reading, and read as a peek: the server would mark
			// the row at fetch, before this scan knows whether it opens. The mark
			// is made below, once the row is settled (`read-ack.ts`).
			const full = (await client.get(
				`/messages/${msg.id}`,
				{},
				withPeekHeader({ [ACTING_AGENT_HEADER]: agentId }, true),
			)) as MessageRead;
			// With no server-authenticated sender the envelope's claim cannot be bound
			// to anything, so skip rather than ingest key material on the strength of
			// the envelope alone.
			if (!full.from_agent_id) continue;
			const result = await decryptMessage(
				configDir,
				agentId,
				full.encrypted_payload,
				client,
				full.from_agent_id,
				undefined,
				full.created_at,
			);
			// A refused envelope carries no text, so it holds no key material to
			// read; an authenticity refusal is still settled, and marked.
			const readable = result.plaintext !== undefined;
			const row = { ...full, verification_status: result.verificationStatus };
			if (isSettledRow(row, readable)) settledIds.push(full.id);
			if (!readable) continue;
			if (ingestSenderKeyDistribution(configDir, agentId, full.type, result)) {
				ingested++;
				if (targetSenderKeyId) {
					const dist = JSON.parse(result.plaintext) as {
						sender_key_id: string;
					};
					if (dist.sender_key_id === targetSenderKeyId) break;
				}
			}
		} catch {
			// An undecryptable row is skipped; it is counted so the miss is not cached
			failedIds.push(msg.id);
		}
	}
	const failure = await ackAfterRead(client, agentId, settledIds, {
		settled: true,
	});
	if (failure) {
		console.warn(
			`rine: could not mark ${settledIds.length} scanned message(s) delivered: ${failure.message}`,
		);
	}
	const failed = settleRowFailures(agentId, openedIds, failedIds);
	return { ingested, unscanned: beyondPage + (inbox.items.length - opened), failed };
}

/**
 * Decrypt a sender-key/MLS group message with one-shot key-material recovery.
 *
 * `decryptGroupMessage` throws the clause {@link unknownSenderKeyId} reads when
 * the sender's key distribution has not yet been ingested locally. On that
 * specific failure we fetch + ingest pending distributions (targeting the
 * missing id) and retry once. Any other error propagates untouched so the
 * caller can degrade the row; a scan that ingests nothing is the end of the
 * road, and comes back as a {@link SenderKeyUnavailableError}.
 *
 * 🔴 A retry that ingested keys and still missed THIS one is the same verdict,
 * never the raw control string; a caller reads the cause with
 * {@link asSenderKeyUnavailable}.
 *
 * This is the single home for the sender-key recovery dance: `rine_read`
 * (rine-mcp), `classifyThreadRow` (core), and the CLI's `message read` and
 * `stream` all reach the failure through here.
 *
 * `fromAgentId` is the row's server-authenticated sender, threaded into both
 * attempts so the retry is bound exactly as strictly as the first try.
 * `createdAt` is the row's server `created_at`, threaded into both attempts for the
 * superseded-key window.
 */
export async function decryptGroupMessageWithRecovery(
	client: HttpClient,
	configDir: string,
	agentId: string,
	groupId: string,
	ciphertext: string,
	fromAgentId: string,
	createdAt?: string,
): Promise<DecryptResult> {
	try {
		return await decryptGroupMessage(
			configDir,
			agentId,
			groupId,
			ciphertext,
			client,
			fromAgentId,
			createdAt,
		);
	} catch (err) {
		const missingKeyId = unknownSenderKeyId(err);
		if (missingKeyId === null) throw err;
		// The retirement gate rides inside the scan: a retired group ingests
		// nothing and the read is refused.
		const ingested = await fetchAndIngestPendingSKDistributions(
			client,
			configDir,
			agentId,
			missingKeyId,
			groupId,
			fromAgentId,
		);
		// The recovery found nothing: a verdict, not a retry hint.
		if (ingested === 0)
			throw new SenderKeyUnavailableError(missingKeyId, groupId, {
				cause: err,
			});
		try {
			return await decryptGroupMessage(
				configDir,
				agentId,
				groupId,
				ciphertext,
				client,
				fromAgentId,
				createdAt,
			);
		} catch (retryErr) {
			// The scan brought key material but not this key: the same final
			// answer the empty scan reaches, in the same words.
			const stillMissing = unknownSenderKeyId(retryErr);
			if (stillMissing === null) throw retryErr;
			throw new SenderKeyUnavailableError(stillMissing, groupId, {
				cause: retryErr,
			});
		}
	}
}
