import * as fs from "node:fs";
import { join } from "node:path";
import type {
	AgentRead,
	BatchKeysResponse,
	GroupMemberRead,
} from "./api-types.js";
import {
	encryptMessage,
	fromBase64Url,
	jwkToPqPublicKey,
	toBase64Url,
	validatePathId,
} from "./crypto/index.js";
import type { PqJWK } from "./crypto/keys.js";
import type { SenderKeyState } from "./crypto/sender-keys.js";
import { generateSenderKey, needsRotation } from "./crypto/sender-keys.js";
import {
	liftRetirementIfMember,
	loadSenderKeyStates,
	markSenderKeysRetired,
	saveSenderKeyState,
} from "./crypto/sender-keys-helpers.js";
import { unseatedGroupSendRefusal } from "./group-words.js";
import type { HttpClient } from "./http.js";
import { fetchAgents } from "./resolve-agent.js";
import { resolveGroupByHandle } from "./resolve-group.js";

export interface DistributeResult {
	succeeded: string[];
	failed: string[];
}

/**
 * Ids one `GET /agents/keys` accepts. The server refuses 201 in a single call
 * ("Maximum 200 IDs per request"), so anything past 200 members has to be
 * fetched in chunks — asking for all of them at once made a group send fail
 * outright at 201 members, before a single distribution was attempted.
 */
const BATCH_KEYS_MAX_IDS = 200;

/**
 * Distribution DMs in flight at once. Each recipient costs one seal and one
 * POST, so an unbounded fan-out over a group at the 500-member ceiling would
 * open 500 sockets and queue 500 seals ahead of everything else this process is
 * doing. Sequentially the same fan-out is ~10 s of round trips on the critical
 * path of a send; a small bound takes that to ~1 s without turning one send
 * into a burst against the server.
 */
const DISTRIBUTION_CONCURRENCY = 8;

/**
 * Published keys for every recipient, fetched in server-sized chunks.
 *
 * A chunk that fails is left OUT of the map rather than thrown: its recipients
 * then take the same path as a recipient who published no keys and are reported
 * as failed. One bad chunk therefore costs those recipients their copy of the
 * key, never the whole distribution.
 *
 * A TOTAL failure is still raised. Absorbing that too would let a send proceed
 * under a key NOBODY holds: the caller distributes nothing, seals the message
 * anyway, and the chain key ratchets forward, so the message is undecryptable
 * for the whole group and no later distribution can recover it. One unreachable
 * chunk degrades the send; an unreachable endpoint stops it, which is what a
 * single unchunked fetch used to do for every failure.
 */
async function fetchPublishedKeys(
	client: HttpClient,
	recipientIds: string[],
): Promise<BatchKeysResponse["keys"]> {
	const keys: BatchKeysResponse["keys"] = {};
	let fetched = 0;
	let lastError: unknown;
	for (let i = 0; i < recipientIds.length; i += BATCH_KEYS_MAX_IDS) {
		const chunk = recipientIds.slice(i, i + BATCH_KEYS_MAX_IDS);
		try {
			const batch = (await client.get("/agents/keys", {
				ids: chunk.join(","),
			})) as BatchKeysResponse;
			Object.assign(keys, batch.keys);
			fetched++;
		} catch (err) {
			lastError = err;
		}
	}
	if (fetched === 0) throw lastError;
	return keys;
}

/**
 * Run `fn` over `items` with at most `limit` of them in flight.
 *
 * Workers pull the next index as they free up, so one slow recipient delays
 * only itself. Nothing about completion order is preserved; the caller reads
 * results back by index.
 */
async function forEachBounded<T>(
	items: T[],
	limit: number,
	fn: (item: T, index: number) => Promise<void>,
): Promise<void> {
	let next = 0;
	const worker = async (): Promise<void> => {
		while (next < items.length) {
			const index = next++;
			await fn(items[index]!, index);
		}
	};
	await Promise.all(
		Array.from({ length: Math.min(limit, items.length) }, worker),
	);
}

/**
 * Distribute a sender key to group members via encrypted DMs.
 * Returns which recipients succeeded/failed, in the order they were given.
 *
 * Every failure is per-recipient: a recipient with no published keys, a seal
 * that throws, a POST that is refused, or a whole key-fetch chunk that failed.
 * The caller records only the recipients that were actually reached, so the
 * next send retries the rest.
 */
export async function distributeSenderKey(
	client: HttpClient,
	configDir: string,
	senderAgentId: string,
	state: SenderKeyState,
	groupId: string,
	recipientIds: string[],
	extraHeaders?: Record<string, string>,
): Promise<DistributeResult> {
	if (recipientIds.length === 0) return { succeeded: [], failed: [] };

	const publishedKeys = await fetchPublishedKeys(client, recipientIds);

	const distPayload = {
		group_id: groupId,
		sender_key_id: state.senderKeyId,
		chain_key: toBase64Url(state.chainKey),
		message_index: state.messageIndex,
		sender_agent_id: senderAgentId,
	};

	const delivered = new Array<boolean>(recipientIds.length).fill(false);

	await forEachBounded(
		recipientIds,
		DISTRIBUTION_CONCURRENCY,
		async (recipientId, index) => {
			const recipientKeyData = publishedKeys[recipientId];
			if (!recipientKeyData) return;
			try {
				const recipientPk = fromBase64Url(
					recipientKeyData.encryption_public_key.x,
				);
				const recipientPqPk = recipientKeyData.pq_encryption_public_key
					? jwkToPqPublicKey(recipientKeyData.pq_encryption_public_key as PqJWK)
					: undefined;
				const encrypted = await encryptMessage(
					configDir,
					senderAgentId,
					recipientPk,
					distPayload,
					recipientPqPk,
				);
				await client.post(
					"/messages",
					{
						to_agent_id: recipientId,
						type: "rine.v1.sender_key_distribution",
						...encrypted,
					},
					extraHeaders,
				);
				delivered[index] = true;
			} catch {
				// Reported as failed below.
			}
		},
	);

	const succeeded: string[] = [];
	const failed: string[] = [];
	recipientIds.forEach((id, index) => {
		(delivered[index] ? succeeded : failed).push(id);
	});

	return { succeeded, failed };
}

/**
 * The caller's own agents that hold a seat in this group, spelled as
 * `X-Rine-Agent` accepts them — or `null` when this client could not find out.
 *
 * Both halves are read off fields the DEPLOYED server sends: the roster's
 * `agent_handle`, and `GET /agents`' own `id`. The intersection of the two IS
 * the own-org answer, so nothing here reads `GroupMemberRead.is_own_org` or
 * `GroupRead.member_agent_ids` — those are young fields, absent from a server
 * that predates them, and a refusal built on one of them renders an empty
 * clause against production while reading perfectly in a fixture.
 *
 * 🔴 `null` is not the empty list. "No agent of your org is seated" and "this
 * client could not read your agent list" have different remedies, and
 * {@link unseatedGroupSendRefusal} renders a different arm for each. The fetch
 * failing must never replace the refusal it is decorating, which is why its
 * error is swallowed rather than raised: the caller asked to send, not to list
 * agents, and the seat refusal is still the true answer.
 *
 * The order is the server's, not this function's. `GET /agents` decides it, and
 * sorting here would fight the `ORDER BY` that route is getting rather than add
 * determinism to anything.
 */
async function seatedOwnAgents(
	client: HttpClient,
	members: GroupMemberRead[],
): Promise<string[] | null> {
	let agents: AgentRead[] | undefined;
	try {
		agents = await fetchAgents(client);
	} catch {
		return null;
	}
	// 🔴 A 200 that carries no `items` is not an empty org, and it is not caught
	// above: {@link fetchAgents} returns `data.items` unvalidated, so a proxy or
	// gateway answering a JSON body of another shape hands back `undefined`
	// without throwing, past the catch. Reading `.filter` on it would raise a
	// TypeError OUT of this function and replace the seat refusal with a stack
	// trace — the one thing the paragraph above says must never happen. It is
	// the same answer as a failed fetch: this client could not find out.
	if (!Array.isArray(agents)) return null;
	const seats = new Map(
		members.map((m) => [m.agent_id.toLowerCase(), m.agent_handle]),
	);
	return agents
		.filter((a) => seats.has(a.id.toLowerCase()))
		.map((a) => seats.get(a.id.toLowerCase()) ?? a.id);
}

/**
 * Get or create a sender key for a group, distributing it to members as needed.
 * Handles rotation on member removal, periodic rotation, and new key generation.
 *
 * This agent keeps at most TWO sending keys per group — the current one and the
 * one it just superseded — so the stored array is bounded by the group's
 * membership instead of growing once per rotation for the life of the group.
 * The cost of that is stated where it lands: a message this agent sent two or
 * more rotations ago can no longer be read back by its sender, because the
 * self-read key was cached on a state that has since been dropped. Keeping one
 * superseded key is what makes rotation cheap without making the agent's own
 * recent history unreadable to it.
 */
export async function getOrCreateSenderKey(
	client: HttpClient,
	configDir: string,
	senderAgentId: string,
	groupHandle: string,
	extraHeaders?: Record<string, string>,
): Promise<{ state: SenderKeyState; groupId: string }> {
	// One resolver for the whole stack (`resolve-group.ts`): this lookup and its
	// refusal had three copies, and the transcript read was about to be a fourth.
	const groupId = (await resolveGroupByHandle(client, groupHandle)).id;

	const membersResp = (await client.get(`/groups/${groupId}/members`)) as {
		items: GroupMemberRead[];
	};
	const memberIds = membersResp.items.map((m) => m.agent_id);
	const senderIdLower = senderAgentId.toLowerCase();
	// Before the first write, and it stays there: `distributeSenderKey` fans this
	// agent's key out as real DMs to every member the server lists, so a refusal
	// raised after it would have written into other orgs' inboxes and only then
	// said no. What the sentence adds is the rest of the answer — the group, the
	// agents of the caller's own org that ARE seated, and the move — for the one
	// `GET /agents` it costs, spent on this path and no other.
	if (!memberIds.some((id) => id.toLowerCase() === senderIdLower)) {
		throw new Error(
			unseatedGroupSendRefusal({
				group: groupHandle,
				agent: senderAgentId,
				seated: await seatedOwnAgents(client, membersResp.items),
			}),
		);
	}
	const recipientIds = memberIds.filter(
		(id) => id.toLowerCase() !== senderIdLower,
	);

	// The server has just confirmed this agent is a member, so a retirement it
	// left behind on a previous departure is spent. The read path lifts
	// it on the same fact — see `liftRetirementIfMember` — because a re-admitted
	// agent that reads before it sends, or never sends at all, would otherwise
	// refuse every distribution its new peers make it, forever.
	liftRetirementIfMember(configDir, senderAgentId, groupId, memberIds);

	const states = loadSenderKeyStates(configDir, senderAgentId, groupId);
	// The last own state is the current one: a rotation appends and drops the key
	// it superseded. Reading the FIRST match is what turned a single departure
	// into a rekey on every send — the superseded state's `distributedTo` still
	// named the departed member, so the removal check below fired forever.
	// Taking the last also heals an array an older client left stacked.
	//
	// Own-vs-peer is decided case-insensitively, like every other id comparison in
	// this function: `validatePathId` accepts a UUID in either case, and an id
	// that differs from the stored one only by case would reopen BOTH of the bugs
	// this comparison closes at once — `own` would be undefined (rotate on every
	// send) and this agent's own past states would be classified as peers and
	// retained for the life of the group (the unbounded state leak).
	const ownStates = states.filter(
		(s) => s.senderAgentId.toLowerCase() === senderIdLower,
	);
	const own = ownStates[ownStates.length - 1];

	// Detect member removal: if we distributed to agents no longer in the group,
	// we must rotate to prevent removed members from decrypting future messages.
	const currentMemberSet = new Set(memberIds.map((id) => id.toLowerCase()));
	const memberRemoved =
		own?.distributedTo?.some((id) => !currentMemberSet.has(id.toLowerCase())) ??
		false;

	if (own && !needsRotation(own) && !memberRemoved) {
		const alreadyDistributed = new Set(
			(own.distributedTo ?? []).map((id) => id.toLowerCase()),
		);
		const undistributed = recipientIds.filter(
			(id) => !alreadyDistributed.has(id.toLowerCase()),
		);

		if (undistributed.length > 0) {
			const { succeeded } = await distributeSenderKey(
				client,
				configDir,
				senderAgentId,
				own,
				groupId,
				undistributed,
				extraHeaders,
			);
			if (succeeded.length > 0) {
				own.distributedTo = [...(own.distributedTo ?? []), ...succeeded];
				saveSenderKeyState(configDir, senderAgentId, groupId, states);
			}
		}

		return { state: own, groupId };
	}

	// Generate new sender key (rotation on member removal, periodic rotation, or first key)
	const newState = generateSenderKey(groupId, senderAgentId);
	const { succeeded } = await distributeSenderKey(
		client,
		configDir,
		senderAgentId,
		newState,
		groupId,
		recipientIds,
		extraHeaders,
	);
	newState.distributedTo = succeeded;
	// Retain the peers' keys — they open traffic those peers already sent — and
	// exactly ONE of this agent's own superseded states, the key it was sending
	// under until now. Nothing can be SENT under it again, but its cached
	// `skippedKeys` are what let this agent re-read its own past messages
	// (`crypto/message.ts` caches the self-read key there on every send), so
	// dropping every superseded state would make an agent's own recent history
	// unreadable to it on each rotation. Keeping one is still bounded — the defect
	// it replaced was an array that grew once per rotation for the group's life.
	// Older own states, including a stack an older client left behind, are
	// dropped here. On a member removal also drop the states of agents no longer
	// in the group.
	const peerStates = states.filter(
		(s) =>
			s.senderAgentId.toLowerCase() !== senderIdLower &&
			(!memberRemoved || currentMemberSet.has(s.senderAgentId.toLowerCase())),
	);
	saveSenderKeyState(configDir, senderAgentId, groupId, [
		...peerStates,
		...(own ? [own] : []),
		newState,
	]);
	return { state: newState, groupId };
}

/**
 * Retire this agent's local sender-key material for one group: the key it sends
 * under, the one state it superseded, every peer key it ingested for that group,
 * and the cached message keys all of them left behind — including the self-read
 * cache `crypto/message.ts` writes on every send. All of it lives in the group's
 * single state file, so retiring the group is removing that file.
 *
 * Retiring a group this agent holds no material for is not an error, so a leave
 * path may call this AND `deleteMlsState` unconditionally rather than branching
 * on which crypto the group runs: whichever of the two holds nothing costs one
 * unlink that finds no file.
 *
 * The wipe alone was point-in-time, so it no longer travels alone. Every peer
 * key removed here arrived as a `rine.v1.sender_key_distribution` DM which is
 * still in this agent's inbox — leaving a group takes nothing out of an inbox —
 * and {@link fetchAndIngestPendingSKDistributions}, re-exported from this very
 * module, used to put all of them back on the next group read that missed its
 * key. So this also writes a RETIREMENT MARKER
 * ({@link markSenderKeysRetired}), and every ingest of a sender key for this
 * group is refused from here on. The marker is written whether or not there was
 * anything to delete: a distribution DM this agent never opened is material the
 * wipe never saw, and it is in the same inbox.
 *
 * 🔴 What that buys is LOCAL and it is not an eviction. Membership in an open
 * group is enforced by the server's delivery filter; the marker binds this
 * client's own future behaviour and nothing else, and no surface may describe
 * it as putting the material beyond a departed member's reach — a client that
 * never had the marker, or an operator who deletes it, is unaffected. What
 * bounds a departed member's reach into later traffic is each remaining member
 * ROTATING on their next send (see {@link getOrCreateSenderKey}). Deleting
 * one's own state on the way out is neither a rekey nor a cryptographic
 * removal.

 */
export function deleteSenderKey(
	configDir: string,
	agentId: string,
	groupId: string,
): void {
	validatePathId(agentId, "agent ID");
	validatePathId(groupId, "group ID");
	const dir = join(configDir, "keys", agentId, "sender_keys");
	// The group id is a FILENAME here, and `validatePathId` accepts a UUID in
	// either case while every writer takes the id from the server, which spells
	// it lower-case. A caller that upper-cases the same group — a CLI `group
	// leave` hands its positional argument straight through — would otherwise
	// unlink a path that does not exist, and `force: true` makes that SILENT:
	// the operator is told their material is gone while all of it is still
	// there. Remove both spellings; the one that is not on disk costs nothing.
	for (const id of new Set([groupId, groupId.toLowerCase()])) {
		fs.rmSync(join(dir, `${id}.json`), { force: true });
	}
	markSenderKeysRetired(configDir, agentId, groupId);
}

/**
 * The inbound half moved to its own module; the public surface is unchanged, so
 * every caller that reaches these through `@rine-network/core` — or directly
 * through this module — is unaffected.
 */
export {
	decryptGroupMessageWithRecovery,
	fetchAndIngestPendingSKDistributions,
} from "./sender-key-recovery.js";
