/**
 * What a group's enrollment policy makes of an invitation.
 *
 * On `closed` an invite mints a spendable voucher; on `open` it mints nothing,
 * because an open group needs none. On `majority` and `unanimity` it files a
 * NOMINATION instead — a pending join request the electorate decides — because
 * the vote is the sole seating decision there and an invite that seated past it
 * made `unanimity`, the policy every surface renders as the strictest, the one
 * a single member could walk a stranger through.
 *
 * Every client has to know which of the two it just did, and for a sharper
 * reason than wording: it decides whether a ratchet-tree leaf is minted with
 * the row. A nomination mints none — the vote seats the member, and seating is
 * what grants the key. The predicate lives in `rine-core` because
 * five TypeScript surfaces ask it, and a copy per surface is how one policy
 * comes to mean two things.
 */

/**
 * The policies whose admissions an electorate decides.
 *
 * Deliberately not the full policy vocabulary: `enrollment_policy` is a loose
 * string on the wire so a policy this client predates degrades rather than
 * throwing a group read away, and naming only the two this question is about
 * keeps that true.
 */
export const VOTING_ENROLLMENT_POLICIES = ["majority", "unanimity"] as const;

/**
 * Whether an invite to a group under this policy nominates rather than seats.
 *
 * A caller branches on it twice: to decide whether to post the MLS Add commit
 * that would otherwise Welcome a nominee the electorate may still deny, and to
 * tell the operator what actually happened to the agent they named.
 *
 * A policy this client does not recognise answers `false`, which is what every
 * client did before nominations existed. The alternative — treating an unknown
 * policy as a voting one — withholds a leaf from an invitee who is entitled to
 * one, and that is the failure this cannot self-correct from: an unminted
 * Welcome is recovered by the next `resumeMlsGroupAdmission`, an unwanted one
 * costs an O(N) reclamation commit billed to every member.
 *
 * 🔴 The GROUP's policy, never the founding path's. A roster on `POST /groups`
 * mints real invitations under every policy — at founding the creator
 * is the entire electorate, so a vote would auto-approve every row — so the
 * founding path does not ask this question at all.
 */
export function inviteNominates(
	enrollmentPolicy: string | null | undefined,
): boolean {
	return (VOTING_ENROLLMENT_POLICIES as readonly string[]).includes(
		enrollmentPolicy ?? "",
	);
}
