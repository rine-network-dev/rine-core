/**
 * The group predicates every TypeScript surface shares.
 *
 * The first two answer different questions and must never be swapped:
 *
 * - {@link groupIsMls} — the **render/state** question: does this group have
 *   MLS state a client can hold? Only a latched `mls_group_id` answers yes.
 * - {@link groupAcceptsMlsSendOnly} — the **send** question: will the server
 *   accept anything but an MLS message here?
 *
 * The third, {@link groupMlsInitInFlight}, is the gap between them, and is
 * written as that gap rather than as a third reading of the fields.
 *
 * They live in `rine-core` because all four TypeScript surfaces — the CLI, the
 * MCP server, the TS SDK and every integration built on it — depend on this
 * package and on nothing else in common. Restating them per surface is what
 * produced five different answers to the same question; a predicate that
 * decides which key a message is sealed under cannot be allowed to drift.
 * They sit beside the downgrade guard because
 * {@link assertNoMlsDowngrade}'s `serverSaysMls` argument **is**
 * {@link groupAcceptsMlsSendOnly} — the same expression, not a similar one.
 */

/**
 * The fields a group predicate reads, and nothing else.
 *
 * Structural rather than the concrete `GroupRead` so the TS SDK's zod-inferred
 * shape, this package's interface and any future group projection all satisfy
 * it. Both fields are optional because `rine-core`'s own `GroupRead` marks them
 * so; a group the server minted before MLS existed carries neither.
 */
export interface MlsGroupFields {
  mls_group_id?: string | null;
  mls_pending?: boolean;
}

/**
 * The fields that say which encryption a group was MEANT to run.
 *
 * {@link MlsGroupFields} answers what a group HAS. This answers what it was
 * created for, and the two come apart: a closed group whose founding never
 * landed has no MLS state at all, and is indistinguishable from an open group
 * by the latch alone. `enrollment_policy` is the durable record, set at create
 * and never cleared — the server binds the regime to it, refusing `/mls/init`
 * and `/mls/commit` on an open group (`src/rine/api/mls_validation.py`), so a
 * non-open policy is the server's own statement that this group's encryption is
 * MLS.
 *
 * Declared as its own interface rather than folded into {@link MlsGroupFields}
 * because the latch predicates read neither field, and a predicate that reads
 * more than it needs is one that can be given less than it needs by a caller
 * that projects a row.
 */
export interface GroupRegimeFields extends MlsGroupFields {
  enrollment_policy: string;
  mls_enabled?: boolean;
}

/**
 * Does this group run on MLS?
 *
 * `mls_group_id` is the server's MLS latch: non-null means the group's MLS
 * state has been founded and every member holds (or can install) local MLS
 * state. It is the only field that says so.
 *
 * `mls_enabled` is an *intent* flag — a closed group carries it from birth,
 * before any MLS state exists, and an open-enrollment group carries it while
 * running on sender keys, because the server refuses MLS there. `mls_pending`
 * marks an init in flight, which is not state either. Neither belongs in this
 * answer; a surface that reads them labels a sender-key group "MLS".
 */
export function groupIsMls(g: MlsGroupFields): boolean {
  return g.mls_group_id != null;
}

/**
 * Will this group accept only MLS messages?
 *
 * The client-side mirror of the server's `is_mls_frozen`
 * (`src/rine/api/group_helpers.py`): once a group is MLS-latched **or** an init
 * is in flight, the server refuses a sender-key send with a 409. A send path
 * that asks {@link groupIsMls} instead walks into that 409 during the init
 * window, which the server self-clears after
 * `MLS_PENDING_SELF_CLEAR_SECONDS`.
 */
export function groupAcceptsMlsSendOnly(g: MlsGroupFields): boolean {
  return groupIsMls(g) || g.mls_pending === true;
}

/**
 * Is this group's MLS initialisation still in flight?
 *
 * The window between the server accepting a group's MLS init and its
 * `mls_group_id` latching. It is written as the gap between the other two
 * answers — no MLS state to render yet ({@link groupIsMls} is false) while the
 * server already refuses everything but MLS ({@link groupAcceptsMlsSendOnly} is
 * true) — and never as a third reading of the fields, so it cannot drift away
 * from the pair it sits between.
 *
 * This is a normal transient state of a healthy group, not a failure: a send
 * made during the window already takes the MLS branch, because the send
 * question is the one {@link groupAcceptsMlsSendOnly} answers. A surface that
 * renders a group therefore has three cases, not two, and rendering this one
 * "sender-key" says the opposite of what the group is doing.
 */
export function groupMlsInitInFlight(g: MlsGroupFields): boolean {
  return !groupIsMls(g) && groupAcceptsMlsSendOnly(g);
}

/**
 * Was this group created to run MLS, and does it still have no ratchet tree?
 *
 * The fourth case, and the one the other three collapse into "sender key". A
 * closed group whose founding never landed carries a null latch and — once the
 * server has cleared the init window it self-heals after
 * `MLS_PENDING_SELF_CLEAR_SECONDS` — a false `mls_pending`, which is field for
 * field what an open group looks like. Nothing in the group's MLS columns
 * survives to say a founding was ever attempted, so the only durable record is
 * the intent pair set at create time, and this reads it.
 *
 * 🔴 It says **never founded**, not "founding failed". A group whose init died
 * and one whose client never ran an init are the same four values on the wire,
 * so no client can tell them apart and no sentence built on this may claim to.
 *
 * The group is not broken: the server does not freeze it
 * (`is_mls_frozen` is false), so sends take the sender-key branch and are
 * accepted. That is the point — a group created to run MLS is carrying
 * sender-key traffic, and nothing said so.
 *
 * `mls_enabled` is read here, and only here, because it is the one field that
 * can say a closed group was deliberately NOT given MLS — legal on the wire and
 * settable while the group is unlatched. It is sensed as `=== true`: the server
 * always sends it, so absence means a projection or a hand-built row rather
 * than a real answer, and an absent field must never be what manufactures a
 * refusal.
 */
export function groupMlsNeverFounded(g: GroupRegimeFields): boolean {
  // `!groupAcceptsMlsSendOnly` is exactly "no latch and no init in flight" —
  // the server would accept a sender-key send into this group right now.
  return (
    g.enrollment_policy !== "open" &&
    g.mls_enabled === true &&
    !groupAcceptsMlsSendOnly(g)
  );
}
