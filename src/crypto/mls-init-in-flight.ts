/**
 * The refusal a client mints for a group whose MLS init is still in flight.
 *
 * `mls_pending` freezes the group: the server accepts only `mls-v1` there
 * (`is_mls_frozen`, `src/rine/api/group_helpers.py`), and no member holds
 * usable MLS state until the founding commit lands. Both sends are therefore
 * impossible, and saying so client-side beats a server 409 with no explanation
 * of when to retry.
 *
 * It lives here, once, because the CLI, the MCP server and the TS SDK all reach
 * this state on the same send path and all three previously restated it — as a
 * bare `Error` carrying a message string, which left a caller no way to
 * recognise it except by matching that text.
 */

/**
 * How long the server lets an unfinished MLS init hold a group frozen before it
 * self-clears.
 *
 * The server enforces it as a literal at `src/rine/api/mls_confirmation.py:56`,
 * and `src/rine/api/mls_constants.py:32` documents the same window as the one
 * `MLS_ACK_DEADLINE_SECONDS` reuses. This is the TypeScript side's single
 * source of truth for it: the operator-facing minutes below are derived, never
 * spelled out a second time.
 */
export const MLS_PENDING_SELF_CLEAR_SECONDS = 900;

/**
 * The stable code every surface branches on. A caller matching this error by
 * its message text is a defect — the text is for the operator reading it.
 */
export const MLS_INIT_IN_FLIGHT_CODE = "RINE_GROUP_MLS_INIT_IN_FLIGHT";

/**
 * A group send refused because the group's MLS init has not landed yet.
 *
 * The code is deliberately outside the `RINE_MLS_` namespace: `mlsErrorCode`
 * classifies by that prefix, so a code inside it would make this a recoverable
 * MLS read, NACKed and swallowed by the one-shot recovery in
 * `decryptGroupMessage`. This is a wait-and-retry condition of the group, not a
 * failure of the native core, and it must survive as one.
 */
export class MlsInitInFlightError extends Error {
  readonly code = MLS_INIT_IN_FLIGHT_CODE;

  constructor(public readonly groupHandle: string) {
    super(inFlightMessage(groupHandle));
    this.name = "MlsInitInFlightError";
  }
}

function inFlightMessage(groupHandle: string): string {
  const minutes = Math.round(MLS_PENDING_SELF_CLEAR_SECONDS / 60);
  return [
    `Group ${groupHandle} is initialising MLS. The server accepts only MLS`,
    "messages here, and the group has no MLS state to encrypt with yet.",
    `Retry once the init completes; a stuck init self-clears server-side after`,
    `${minutes} minutes.`,
  ].join(" ");
}

/** True for a refusal minted by the in-flight init guard, matched on its code. */
export function isMlsInitInFlightError(err: unknown): boolean {
  return (
    (err as { code?: unknown } | null | undefined)?.code ===
    MLS_INIT_IN_FLIGHT_CODE
  );
}
