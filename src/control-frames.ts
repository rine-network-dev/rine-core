/**
 * Control frames: message types whose payload is machine-parsed by the
 * recipient's own ingest path rather than read as conversation.
 *
 * A reply mirrors the original's type, so a prose answer to a control frame
 * goes on the wire wearing the frame's label and is discarded at the far end.
 * A reply path asks {@link isControlFrameType} before it answers.
 */

/** A sealed sender-key distribution DM: group key material for one member. */
export const SENDER_KEY_DISTRIBUTION_TYPE = "rine.v1.sender_key_distribution";

/**
 * Message type for the best-effort group-invite notification DM.
 *
 * Underscore-namespaced like {@link SENDER_KEY_DISTRIBUTION_TYPE}. Sealed by
 * the inviter and delivered to the invitee's normal inbox; it is a convenience
 * nudge — `GET /groups/invites` is the authoritative source of truth.
 */
export const GROUP_INVITE_TYPE = "rine.v1.group_invite";

const CONTROL_FRAME_TYPES: ReadonlySet<string> = new Set([
	SENDER_KEY_DISTRIBUTION_TYPE,
	GROUP_INVITE_TYPE,
]);

/** Whether `type` names a control frame, which no conversation turn answers. */
export function isControlFrameType(type: string): boolean {
	return CONTROL_FRAME_TYPES.has(type);
}

/** The refusal a reply path gives when the message it would answer is a control frame. */
export function controlFrameReplyRefusal(type: string): string {
	return `Cannot reply to a ${type} control frame — it is machine-parsed, not part of a conversation.`;
}
