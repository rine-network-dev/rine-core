import { ACTING_AGENT_HEADER } from "./actor.js";
import type { JoinRequestRead, ListResponse } from "./api-types.js";
import { encryptMessage, fetchRecipientKeys } from "./crypto/message.js";
import type { HttpClient } from "./http.js";

/**
 * Message type for the best-effort group-invite notification DM.
 *
 * Underscore-namespaced like `rine.v1.sender_key_distribution`. Sealed by the
 * inviter and delivered to the invitee's normal inbox; it is a convenience
 * nudge — `GET /groups/invites` is the authoritative source of truth.
 */
export const GROUP_INVITE_TYPE = "rine.v1.group_invite";

/** Cleartext fields the inviter supplies for the sealed invite payload. */
export interface GroupInvitePayload {
	group_id: string;
	group_handle: string;
	message: string | null;
}

/**
 * Seal a `rine.v1.group_invite` notification to the invitee and POST it.
 *
 * Reuses the 1:1 DM crypto path (`fetchRecipientKeys` + `encryptMessage`), so
 * hybrid PQ is auto-negotiated when the invitee publishes an ML-KEM key. The
 * sealed payload carries `invited_by = inviterAgentId` (also cryptographically
 * bound via the sender signature). `X-Rine-Agent` selects the inviter as sender.
 *
 * Best-effort by contract: callers wrap this so a failure (e.g. groups_only
 * 403, missing keys) warns but never fails the invite.
 */
export async function sendGroupInviteNotification(
	client: HttpClient,
	configDir: string,
	inviterAgentId: string,
	inviteeAgentId: string,
	invite: GroupInvitePayload,
): Promise<void> {
	const recipientKeys = await fetchRecipientKeys(client, inviteeAgentId);
	const payload = {
		group_id: invite.group_id,
		group_handle: invite.group_handle,
		invited_by: inviterAgentId,
		message: invite.message,
	};
	const encrypted = await encryptMessage(
		configDir,
		inviterAgentId,
		recipientKeys.encryption,
		payload,
		recipientKeys.pqEncryption,
	);
	await client.post(
		"/messages",
		{ to_agent_id: inviteeAgentId, type: GROUP_INVITE_TYPE, ...encrypted },
		{ [ACTING_AGENT_HEADER]: inviterAgentId },
	);
}

/**
 * List the calling agent's open group invites via the authoritative pull
 * endpoint `GET /groups/invites`. `extraHeaders` lets multi-agent orgs pass
 * `X-Rine-Agent` to disambiguate which agent's invites to list.
 */
export async function listMyInvites(
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<JoinRequestRead[]> {
	const data = (await client.get(
		"/groups/invites",
		undefined,
		extraHeaders,
	)) as ListResponse<JoinRequestRead>;
	return data.items;
}
