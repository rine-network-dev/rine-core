import { ACTING_AGENT_HEADER } from "./actor.js";
import type { JoinRequestRead, ListResponse } from "./api-types.js";
import { GROUP_INVITE_TYPE } from "./control-frames.js";
import { sealForAgent } from "./crypto/message.js";
import type { HttpClient } from "./http.js";

/** Cleartext fields the inviter supplies for the sealed invite payload. */
export interface GroupInvitePayload {
	group_id: string;
	group_handle: string;
	message: string | null;
}

/**
 * Seal a `rine.v1.group_invite` notification to the invitee and POST it.
 *
 * Reuses the 1:1 DM seal ({@link sealForAgent}), so the invite is sealed to the
 * invitee's chain-verified hybrid keys. The sealed payload carries
 * `invited_by = inviterAgentId` (also cryptographically bound via the sender
 * signature). `X-Rine-Agent` selects the inviter as sender.
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
	const payload = {
		group_id: invite.group_id,
		group_handle: invite.group_handle,
		invited_by: inviterAgentId,
		message: invite.message,
	};
	const encrypted = await sealForAgent(
		client,
		configDir,
		{ senderAgentId: inviterAgentId, recipientAgentId: inviteeAgentId },
		payload,
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
