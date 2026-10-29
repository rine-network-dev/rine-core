/**
 * The native MLS core's error vocabulary, as TypeScript sees it.
 *
 * Every binding failure arrives as an `Error` whose `code` is one of the core's
 * stable `RINE_MLS_*` strings — a value to branch on, never a message to parse.
 * The predicates here are the only places rine decides what a given failure
 * means, so no surface has to know the vocabulary itself.
 */
/** Absent or unreadable local group state, and a KeyPackage this core cannot parse. */
export const MLS_ERR_PROTOCOL = "RINE_MLS_PROTOCOL";
/**
 * The identity provider refused a leaf: its agent is not in the allowed set under
 * the key it carries. The handle is unchanged, so the same input can be retried
 * once that agent is verified.
 */
export const MLS_ERR_PEER_NOT_ADMITTED = "RINE_MLS_PEER_NOT_ADMITTED";
/** This member was evicted by a Remove commit; the handle is retired. */
export const MLS_ERR_GROUP_INACTIVE = "RINE_MLS_GROUP_INACTIVE";
/** A message this member sent, whose plaintext has aged out of the self-read cache. */
export const MLS_ERR_SELF_MESSAGE_NOT_CACHED =
	"RINE_MLS_SELF_MESSAGE_NOT_CACHED";
/** A claimed KeyPackage minted by the pre-cutover stack. */
export const MLS_ERR_UNREADABLE_KEY_PACKAGE = "RINE_MLS_UNREADABLE_KEY_PACKAGE";
/**
 * An agent's leaf in a group still carries a key it has since rotated away from,
 * and this device holds no group state that can move it, so the group cannot be
 * resynced from that leaf. Rine's own code, not the core's: deliberately outside
 * the `RINE_MLS_` namespace, which is the core's vocabulary and which the retry
 * paths classify as a recoverable MLS read. Shared byte-for-byte with the Python
 * SDK.
 */
export const MLS_ERR_ROTATED_LEAF = "mls_rotated_leaf";
/** An external commit that would replace a leaf's signing key; a resync keeps the key it replaces. */
export const MLS_ERR_RESYNC_CHANGES_KEY = "RINE_MLS_RESYNC_CHANGES_KEY";
/** The native core found no leaf under this agent's credential in the GroupInfo tree. */
export const MLS_ERR_NO_SEAT_TO_REPLACE = "RINE_MLS_NO_SEAT_TO_REPLACE";
/** A commit is already pending on this handle, so no other commit can be built until it settles. */
export const MLS_ERR_COMMIT_PENDING = "RINE_MLS_COMMIT_PENDING";
/** The handle signs with a key other than the one on its own leaf, so it cannot move that leaf. */
export const MLS_ERR_SIGNER_LEAF_MISMATCH = "RINE_MLS_SIGNER_LEAF_MISMATCH";
/** An allowed-set insert gave a generation a leaf key another generation of the agent already holds. */
export const MLS_ERR_ALLOWED_GENERATION_CONFLICT = "RINE_MLS_ALLOWED_GENERATION_CONFLICT";
/** The local store could not be read or written. */
export const MLS_ERR_STORE = "RINE_MLS_STORE";
/** A panic was contained at the binding boundary; the handle is retired. */
export const MLS_ERR_PANIC = "RINE_MLS_PANIC";
/** A later call on a handle a panic already retired. */
export const MLS_ERR_POISONED = "RINE_MLS_POISONED";

/** Failures of THIS process, never of the artifact it was handed. */
const LOCAL_FAILURE_CODES: ReadonlySet<string> = new Set([
	MLS_ERR_STORE,
	MLS_ERR_PANIC,
	MLS_ERR_POISONED,
]);

/**
 * The native core's stable error code, or null for anything that did not come
 * from it. Every binding failure arrives as an `Error` whose `code` is one of
 * the core's `RINE_MLS_*` strings — a value to branch on, never a message to
 * parse.
 */
export function mlsErrorCode(err: unknown): string | null {
	const code = (err as { code?: unknown } | null | undefined)?.code;
	return typeof code === "string" && code.startsWith("RINE_MLS_") ? code : null;
}

/** True for any failure raised by the native MLS core. */
export function isMlsError(err: unknown): boolean {
	return mlsErrorCode(err) !== null;
}

/**
 * True when a failure means "this commit cannot be applied", as opposed to
 * "this process failed". Only the former earns a NACK: NACKing a commit because
 * our own disk was unwritable would roll back a commit every other member
 * applied cleanly.
 */
export function isUnprocessableCommit(err: unknown): boolean {
	const code = mlsErrorCode(err);
	return code !== null && !LOCAL_FAILURE_CODES.has(code);
}
