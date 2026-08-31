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
import type { DecryptResult } from "./crypto/index.js";
import {
	decryptGroupMessage,
	decryptMessage,
	ingestSenderKeyDistribution,
	liftRetirementIfMember,
	senderKeysRetired,
} from "./crypto/index.js";
import type { HttpClient } from "./http.js";
import {
	SenderKeyUnavailableError,
	unknownSenderKeyId,
} from "./sender-key-words.js";

/**
 * The agent ids the server currently names as members of a group.
 *
 * Read here rather than inferred, because it is the only fact that may lift a
 * retirement: membership is the server's to state, and a client that decided it
 * locally could un-retire material it left with.
 */
async function fetchGroupMemberIds(
	client: HttpClient,
	groupId: string,
): Promise<string[]> {
	const resp = (await client.get(`/groups/${groupId}/members`)) as {
		items?: { agent_id: string }[];
	};
	return (resp.items ?? []).map((item) => item.agent_id);
}

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
		members = await fetchGroupMemberIds(client, groupId);
	} catch {
		return true;
	}
	return !liftRetirementIfMember(configDir, agentId, groupId, members);
}

/**
 * One pass over the distribution inbox: what it installed, and what it never
 * looked at.
 *
 * The second number is the whole reason this shape exists. The scan reads ONE
 * page of `limit: 100` and follows no cursor, so on an agent whose distribution
 * inbox is longer than that page the pass is a partial one — and the count of
 * what it installed cannot say so. Carrying the two together is what lets the
 * sync answer state the shortfall instead of reporting a partial pass as a
 * whole one.
 */
export interface SenderKeyScan {
	/**
	 * Sender keys newly installed by this pass. What every read path reads, and
	 * the number {@link fetchAndIngestPendingSKDistributions} hands back.
	 */
	ingested: number;
	/**
	 * How many distribution DMs this pass did not open: the rows the server
	 * counts BEYOND the page it read, plus any of that page a targeted scan
	 * stopped short of. `0` when the pass opened everything, and `0` again when
	 * the server sent no total to compare against.
	 *
	 * 🔴 The two halves are one number because they are one fact. A scan given a
	 * `targetSenderKeyId` breaks the moment it installs that key, so the rest of
	 * its own page is as unopened as the rows past the end of it — counting only
	 * the second half would report a partial pass as a whole one on exactly the
	 * path that stops early.
	 *
	 * 🔴 It is a count of what this pass did not LOOK at, and says nothing about
	 * what those DMs hold: the inbox listing is every distribution this agent has
	 * ever been sent, so most of the ones behind that page are keys it installed
	 * long ago. A renderer may state the number and may not conclude a missing
	 * key from it.
	 */
	unscanned: number;
}

/**
 * Fetch pending sender key distributions from the inbox and ingest them.
 * Used by `read` and `stream` to auto-recover when a sender key is missing.
 *
 * Optionally short-circuits once `targetSenderKeyId` is ingested.
 * Returns the number of newly ingested keys.
 *
 * 🔴 That number is what was INSTALLED, and it is not an inventory of the
 * inbox: this returns `0` with distribution DMs still listed — one already
 * installed, one with no server-authenticated sender, one whose envelope
 * refused, one past the un-paginated `limit: 100` the scan reads. A caller that
 * renders the zero may say nothing was installed and may not say nothing was
 * waiting;
 * `describeMlsRecovery`'s empty-scan arm (`mls-recovery-format.ts`) was
 * reworded twice for saying the second.
 *
 * 🔴 Its return type is `number` and stays `number`. Every read path in the
 * product calls this — the CLI's `read`/`stream`, the TypeScript SDK's decrypt,
 * `rine_read`, {@link decryptGroupMessageWithRecovery}'s own retry — so
 * widening it is a breaking change on the hottest path there is. The one caller
 * that needs more than the count, the sync verb, calls
 * {@link scanPendingSKDistributions} instead; this is that function with the
 * second number dropped, never a second implementation of it.
 */
export async function fetchAndIngestPendingSKDistributions(
	client: HttpClient,
	configDir: string,
	agentId: string,
	targetSenderKeyId?: string,
	groupId?: string,
): Promise<number> {
	return (
		await scanPendingSKDistributions(
			client,
			configDir,
			agentId,
			targetSenderKeyId,
			groupId,
		)
	).ingested;
}

/**
 * The same pass, reporting what it did not reach as well as what it installed.
 *
 * The whole of the scan lives here and
 * {@link fetchAndIngestPendingSKDistributions} is one line over it, so the two
 * cannot come to disagree about what a pass does. Only the sync verb
 * (`recoverGroup`) reads the second number; every read path takes the count
 * alone.
 *
 * 🔴 This function is why the leave-time wipe used to be point-in-time: a leave
 * removes the state file and takes nothing out of the inbox, so the DMs that
 * carried every peer key are still listed here. It does NOT route around the
 * retirement marker — the group a distribution belongs to is only known after
 * the DM is decrypted, so the refusal lives in
 * {@link ingestSenderKeyDistribution}, which every branch below goes through,
 * and a retired group's keys are counted as not ingested.
 *
 * `groupId` names the group whose read missed, and every caller that has one
 * must pass it: it is the only thing that can spend a retirement on the read
 * path. This scan — not {@link decryptGroupMessageWithRecovery} — is what the
 * CLI's `read`/`stream` and the TypeScript SDK's decrypt call directly, so a
 * lift that lived one level up left a re-admitted member on those surfaces
 * refusing every distribution its new peers sent it, for ever, and unable to
 * open a word of the group. Omitting it keeps the group's material refused,
 * which fails closed.
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
		return { ingested: 0, unscanned: 0 };
	const inbox = (await client.get(`/agents/${agentId}/messages`, {
		type: "rine.v1.sender_key_distribution",
		limit: 100,
	})) as PaginatedResponse<MessageRead>;
	// `total` counts every row the server matched, the page holds at most the
	// hundred asked for, and the difference is the part of the inbox that was
	// never listed. The list route computes the total by default
	// (`include_total`, `src/rine/api/messages.py`) but a server that omitted it
	// leaves nothing to subtract — and a shortfall invented out of a missing
	// field is worse than none, so an absent total is no shortfall.
	const beyondPage =
		typeof inbox.total === "number"
			? Math.max(0, inbox.total - inbox.items.length)
			: 0;

	let ingested = 0;
	// Counted rather than derived from the page length, because the targeted
	// arm below `break`s: the rows it never reached were listed and not opened,
	// which is the same state as the rows past the end of the page.
	let opened = 0;
	for (const msg of inbox.items) {
		opened++;
		try {
			// Say which agent is reading. The server marks the delivery row of the
			// acting agent alone, and this scan reads on behalf of `agentId` — a
			// bare GET would either mark nothing (multi-agent org) or, worse,
			// leave the recovery invisible to the queue that tracks it.
			const full = (await client.get(
				`/messages/${msg.id}`,
				{},
				{ [ACTING_AGENT_HEADER]: agentId },
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
			);
			// A refused envelope carries no text, so it holds no key material to read.
			if (result.plaintext === undefined) continue;
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
			// Skip undecryptable or already-ingested distributions
		}
	}
	return { ingested, unscanned: beyondPage + (inbox.items.length - opened) };
}

/**
 * Decrypt a sender-key/MLS group message with one-shot key-material recovery.
 *
 * `decryptGroupMessage` throws the clause {@link unknownSenderKeyId} reads when
 * the sender's key distribution has not yet been ingested locally. On that
 * specific failure we fetch + ingest pending distributions (targeting the
 * missing id) and retry once. Any other error propagates untouched so the
 * caller can degrade the row; a scan that ingests nothing is the end of the
 * road, and comes back as a {@link SenderKeyUnavailableError} whose sentence
 * says what happened and what to do instead — the library's control string is
 * never what an agent reads.
 *
 * 🔴 A retry that ingested keys and still missed THIS one is the same verdict,
 * and comes back the same way. It used to propagate as it threw, which is the
 * raw control string — so every caller had to translate that arm itself, and
 * the three that did disagreed about what it meant. Both ends of the recovery
 * now speak the one sentence, and a caller reads the cause with
 * {@link asSenderKeyUnavailable} and nothing hand-rolled.
 *
 * This is the single home for the sender-key recovery dance: `rine_read`
 * (rine-mcp), `classifyThreadRow` (core), and the CLI's `message read` and
 * `stream` all reach the failure through here.
 *
 * `fromAgentId` is the row's server-authenticated sender, threaded into both
 * attempts so the retry is bound exactly as strictly as the first try.
 */
export async function decryptGroupMessageWithRecovery(
	client: HttpClient,
	configDir: string,
	agentId: string,
	groupId: string,
	ciphertext: string,
	fromAgentId: string,
): Promise<DecryptResult> {
	try {
		return await decryptGroupMessage(
			configDir,
			agentId,
			groupId,
			ciphertext,
			client,
			fromAgentId,
		);
	} catch (err) {
		const missingKeyId = unknownSenderKeyId(err);
		if (missingKeyId === null) throw err;
		// The retirement gate rides inside the scan, so this path and the surfaces
		// that call the scan directly spend a retirement on exactly the same terms
		// A retired group ingests nothing and the read is refused.
		const ingested = await fetchAndIngestPendingSKDistributions(
			client,
			configDir,
			agentId,
			missingKeyId,
			groupId,
		);
		// The recovery has run and found nothing, so this is a verdict and not a
		// retry hint: hand back the sentence that says so, keeping the library's
		// own throw as its `cause`.
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
			);
		} catch (retryErr) {
			// The scan brought key material but not this key. The recovery has
			// still had its turn, so this is the same final answer the empty scan
			// reaches — said in the same words, here, rather than left as the
			// control string for each surface to recognise and reword.
			const stillMissing = unknownSenderKeyId(retryErr);
			if (stillMissing === null) throw retryErr;
			throw new SenderKeyUnavailableError(stillMissing, groupId, {
				cause: retryErr,
			});
		}
	}
}
