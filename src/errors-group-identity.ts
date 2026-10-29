/**
 * The stable code the SDK's `instanceof` widening branches on. A caller matching
 * {@link GroupIdentityMismatchError} by its message text is a defect — the text
 * is for an operator reading a log.
 */
export const GROUP_IDENTITY_MISMATCH_CODE = "RINE_GROUP_IDENTITY_MISMATCH";

/**
 * A group read answered about a group other than the one it asked for.
 *
 * 🔴 **A server fault, surfaced as a server fault.** No status said this — the
 * response may well have been a well-formed 200 — so it is not a
 * {@link RineApiError}, and it must never fall through into "no group of that
 * id": a caller told its reference was wrong goes and re-spells a reference
 * that was correct, while the substituted group is the one every downstream
 * verb then acts on.
 *
 * It fails closed because of what reads the result. `resolveGroup`'s UUID rung
 * is where a reference becomes an id every group verb afterwards trusts, and on
 * the SDK stack the identical read scopes an MLS Welcome pass: an id the caller
 * never named matches no refusal, so a Welcome that client REFUSED is withheld
 * rather than raised and the join reports success holding no MLS state
 * (MEASURED).
 *
 * 🔴 **This is the only TypeScript declaration of it.** `rine-ts-sdk`
 * re-exports this class rather than declaring one of the same name, so
 * `GroupsResource.get`'s throw and the UUID rung's throw are the same class and
 * one `instanceof` catches both. The Python twin,
 * `rine.errors.GroupIdentityMismatchError` (raised by `rine._mls.api.read_group`
 * and by the Python recipient ladder's own UUID rung), is byte-for-byte on the
 * message; that sentence is the contract, and it is what a stack that cannot
 * share a class has instead.
 *
 * 🔴 `answeredGroupId` is `null` for a body that named no group at all, and the
 * sentence SAYS so rather than printing an empty slot — the two stacks are
 * byte-symmetric on this sentence, and a blank before a full stop reads as a
 * rendering bug in a log, not as a server fault. A group id is a JSON string or
 * it is absent: the coercion that decides which is stated once per stack, at
 * `readableGroupById` here and at `rine._recipient_reads.answered_group_id`
 * there, because `String(x)` and `str(x)` disagree on every non-string value.
 */
export class GroupIdentityMismatchError extends Error {
	readonly code = GROUP_IDENTITY_MISMATCH_CODE;

	constructor(
		readonly requestedGroupId: string,
		readonly answeredGroupId: string | null,
	) {
		super(
			`Refusing the group read for ${requestedGroupId}: ${
				answeredGroupId === null
					? "the server's answer carried no group id"
					: `the server answered with group ${answeredGroupId}`
			}. A read that is not about the group it named cannot be used to ` +
				"establish that group's MLS state.",
		);
		this.name = "GroupIdentityMismatchError";
	}
}

/**
 * True for a substitution refusal this package minted, matched on its code.
 *
 * 🔴 **What it is for.** This class extends `Error` and not `RineError`, because
 * `rine-core` must not depend on the SDK — so without a predicate the SDK can
 * widen on, a consumer's `catch (e) { if (e instanceof RineError) … }` would be
 * false for the refusal its own `groups.resolveRef` just threw and the
 * substitution would escape unhandled. `rine-ts-sdk`'s `errors-core-refusals.ts`
 * lists this beside `isMlsInitInFlightError` and `isMlsDowngradeError` for
 * exactly that reason. The SDK re-exports the class itself rather than
 * declaring one of the same name, so a consumer may equally narrow with
 * `instanceof`; the predicate stays the one answer that survives a bundler
 * loading two copies of this package.
 */
export function isGroupIdentityMismatchError(err: unknown): boolean {
	return (
		(err as { code?: unknown } | null | undefined)?.code ===
		GROUP_IDENTITY_MISMATCH_CODE
	);
}
