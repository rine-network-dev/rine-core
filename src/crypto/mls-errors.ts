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
/** This member was evicted by a Remove commit; the handle is retired. */
export const MLS_ERR_GROUP_INACTIVE = "RINE_MLS_GROUP_INACTIVE";
/** A message this member sent, whose plaintext has aged out of the self-read cache. */
export const MLS_ERR_SELF_MESSAGE_NOT_CACHED =
  "RINE_MLS_SELF_MESSAGE_NOT_CACHED";
/** A claimed KeyPackage minted by the pre-cutover stack. */
export const MLS_ERR_UNREADABLE_KEY_PACKAGE = "RINE_MLS_UNREADABLE_KEY_PACKAGE";
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
