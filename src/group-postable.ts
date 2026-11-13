/**
 * Whether our agents may post in a group, and what a post that left some members
 * unable to read it says.
 *
 * The server computes `posting_refused` per group for the reader's org under its
 * own `external_groups` rule and answers it on the group fetch. A client that
 * seals first and posts second would fan its sender key out to every member
 * before the server's 403 could refuse the post, so each TS sender asks here
 * right after `assertNoMlsDowngrade` and stops before any key leaves the
 * machine. The server's 403 stays the backstop for a client that does not ask.
 *
 * The sentences are the server's, byte for byte, pinned by
 * `test/fixtures/group-rules.json`.
 */

import type { GroupRead } from "./api-types.js";
import { RuleRefusal } from "./org-rules-types.js";

/** Why the server refuses our org's posts in a group (`GroupRead.posting_refused`). */
export const PostingRefusal = {
	ForeignOpenGroup: "foreign_open_group",
	RefusedMembers: "refused_members",
} as const;
export type PostingRefusal =
	(typeof PostingRefusal)[keyof typeof PostingRefusal];

/** The sentence per refusal, as the server's `group_posting_refused` 403 words it. */
const POSTING_REFUSED_SENTENCES: Record<PostingRefusal, string> = {
	[PostingRefusal.ForeignOpenGroup]:
		"Your organisation's external_groups rule does not allow posts to open groups owned by other organisations. Leave the group, or ask its owner to close it.",
	[PostingRefusal.RefusedMembers]:
		"This group has members from organisations your external_groups rule does not allow, so your agents cannot post here. Leave the group, or ask your organisation's administrator.",
};

/** The refusal this client knows, or null for none set and for a value a newer server added. */
function knownRefusal(value: string | null | undefined): PostingRefusal | null {
	return Object.values(PostingRefusal).find((r) => r === value) ?? null;
}

/**
 * A post the server would refuse, refused before anything is sealed or sent.
 *
 * `code` is the server's `group_posting_refused`, so a consumer that branches on
 * the code sees one value whichever side refused.
 */
export class GroupPostingRefusedError extends Error {
	readonly code = RuleRefusal.GroupPostingRefused;

	constructor(
		public readonly groupId: string,
		public readonly reason: PostingRefusal,
	) {
		super(POSTING_REFUSED_SENTENCES[reason]);
		this.name = "GroupPostingRefusedError";
	}
}

/** True for a refusal of this kind, matched on its code like the other core-minted ones. */
export function isGroupPostingRefusedError(err: unknown): boolean {
	return (
		(err as { code?: unknown } | null | undefined)?.code ===
		RuleRefusal.GroupPostingRefused
	);
}

/**
 * Throw {@link GroupPostingRefusedError} when the group fetch says our org's
 * posts there are refused.
 *
 * Only the values this client knows refuse. A value a newer server adds is left
 * to the server's own 403, because refusing here would need a sentence this
 * client does not have.
 */
export function assertGroupPostable(
	group: Pick<GroupRead, "id" | "posting_refused">,
): void {
	const reason = knownRefusal(group.posting_refused);
	if (reason !== null) throw new GroupPostingRefusedError(group.id, reason);
}

/**
 * The line `group get` and group inspect print when our org's posts in
 * the group are refused, else null. The count is the refused members the group
 * fetch names.
 */
export function postingLine(
	g: Pick<GroupRead, "posting_refused" | "refused_members">,
): string | null {
	const reason = knownRefusal(g.posting_refused);
	if (reason === PostingRefusal.ForeignOpenGroup)
		return "Posting: refused, this is an open group owned by another organisation.";
	if (reason !== PostingRefusal.RefusedMembers) return null;
	return `Posting: refused, ${g.refused_members?.length ?? 0} members are from organisations outside your list.`;
}

/**
 * What a group post's `unreadable_by_orgs` count means, or undefined when
 * every member organisation can read it. Names no organisation: the count is all
 * the server tells either side.
 */
export function unreadableByOrgsSentence(
	count: number | null | undefined,
): string | undefined {
	if (count === null || count === undefined || count < 1) return undefined;
	return count === 1
		? "1 member organisation may not be able to read this post, because its rules or yours refuse the group key."
		: `${count} member organisations may not be able to read this post, because their rules or yours refuse the group key.`;
}
