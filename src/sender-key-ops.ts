import type { BatchKeysResponse, GroupMemberRead, MessageRead, PaginatedResponse } from "./api-types.js";
import { decryptMessage, encryptMessage, fromBase64Url, ingestSenderKeyDistribution, toBase64Url } from "./crypto/index.js";
import type { SenderKeyState } from "./crypto/sender-keys.js";
import {
	generateSenderKey,
	needsRotation,
} from "./crypto/sender-keys.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
} from "./crypto/sender-keys-helpers.js";
import type { HttpClient } from "./http.js";

export interface DistributeResult {
	succeeded: string[];
	failed: string[];
}

/**
 * Distribute a sender key to group members via encrypted DMs.
 * Returns which recipients succeeded/failed.
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

	const batchKeys = (await client.get("/agents/keys", {
		ids: recipientIds.join(","),
	})) as BatchKeysResponse;

	const distPayload = {
		group_id: groupId,
		sender_key_id: state.senderKeyId,
		chain_key: toBase64Url(state.chainKey),
		message_index: state.messageIndex,
		sender_agent_id: senderAgentId,
	};

	const succeeded: string[] = [];
	const failed: string[] = [];

	for (const recipientId of recipientIds) {
		const recipientKeyData = batchKeys.keys[recipientId];
		if (!recipientKeyData) {
			failed.push(recipientId);
			continue;
		}
		try {
			const recipientPk = fromBase64Url(
				recipientKeyData.encryption_public_key.x,
			);
			const encrypted = await encryptMessage(
				configDir,
				senderAgentId,
				recipientPk,
				distPayload,
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
			succeeded.push(recipientId);
		} catch {
			failed.push(recipientId);
		}
	}

	return { succeeded, failed };
}

/**
 * Get or create a sender key for a group, distributing it to members as needed.
 * Handles rotation on member removal, periodic rotation, and new key generation.
 */
export async function getOrCreateSenderKey(
	client: HttpClient,
	configDir: string,
	senderAgentId: string,
	groupHandle: string,
	extraHeaders?: Record<string, string>,
): Promise<{ state: SenderKeyState; groupId: string }> {
	const groups = (await client.get("/groups", {
		handle: groupHandle,
	})) as { items: { id: string }[] };
	const firstGroup = groups.items?.[0];
	if (!firstGroup) throw new Error(`Group not found: ${groupHandle}`);
	const groupId = firstGroup.id;

	const membersResp = (await client.get(
		`/groups/${groupId}/members`,
	)) as { items: GroupMemberRead[] };
	const memberIds = membersResp.items.map((m) => m.agent_id);
	const senderIdLower = senderAgentId.toLowerCase();
	if (!memberIds.some((id) => id.toLowerCase() === senderIdLower)) {
		throw new Error("You are not a member of this group");
	}
	const recipientIds = memberIds.filter(
		(id) => id.toLowerCase() !== senderIdLower,
	);

	const states = loadSenderKeyStates(configDir, senderAgentId, groupId);
	const own = states.find((s) => s.senderAgentId === senderAgentId);

	// Detect member removal: if we distributed to agents no longer in the group,
	// we must rotate to prevent removed members from decrypting future messages.
	const currentMemberSet = new Set(memberIds.map((id) => id.toLowerCase()));
	const memberRemoved =
		own?.distributedTo?.some(
			(id) => !currentMemberSet.has(id.toLowerCase()),
		) ?? false;

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
	// On member removal, prune states from agents no longer in the group
	const activeStates = memberRemoved
		? states.filter((s) =>
				currentMemberSet.has(s.senderAgentId.toLowerCase()),
			)
		: states;
	saveSenderKeyState(configDir, senderAgentId, groupId, [
		...activeStates,
		newState,
	]);
	return { state: newState, groupId };
}

/**
 * Fetch pending sender key distributions from the inbox and ingest them.
 * Used by `read` and `stream` to auto-recover when a sender key is missing.
 *
 * Optionally short-circuits once `targetSenderKeyId` is ingested.
 * Returns the number of newly ingested keys.
 */
export async function fetchAndIngestPendingSKDistributions(
	client: HttpClient,
	configDir: string,
	agentId: string,
	targetSenderKeyId?: string,
): Promise<number> {
	const inbox = (await client.get(`/agents/${agentId}/messages`, {
		type: "rine.v1.sender_key_distribution",
		limit: 100,
	})) as PaginatedResponse<MessageRead>;

	let ingested = 0;
	for (const msg of inbox.items) {
		try {
			const full = (await client.get(
				`/messages/${msg.id}`,
			)) as MessageRead;
			const result = await decryptMessage(
				configDir,
				agentId,
				full.encrypted_payload,
				client,
			);
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
	return ingested;
}
