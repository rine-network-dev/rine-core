/**
 * The group predicates, and the lines between them.
 *
 * `groupIsMls` answers "does this group have MLS state?" and `mls_group_id` is
 * the only field that says so; `groupAcceptsMlsSendOnly` answers "will the
 * server refuse a sender-key send here?" and adds the in-flight init window.
 * Reading either flag for the other's question is the defect these tests pin.
 * `groupMlsInitInFlight` names the window the two disagree over, and the three
 * together partition every group into exactly one of three renderable states.
 *
 * They are asserted here, in the package that owns them, because every
 * TypeScript surface now imports these two functions rather than restating
 * them.
 */

import { describe, expect, it } from "vitest";
import type { GroupRead } from "../../src/api-types.js";
import {
  groupAcceptsMlsSendOnly,
  groupIsMls,
  groupMlsInitInFlight,
  groupMlsNeverFounded,
} from "../../src/crypto/group-predicates.js";

function group(over: Partial<GroupRead> = {}): GroupRead {
  return {
    id: "33333333-3333-4333-8333-333333333333",
    name: "dev",
    handle: "#dev@acme.rine.network",
    description: null,
    enrollment_policy: "closed",
    visibility: "private",
    isolated: false,
    vote_duration_hours: 72,
    member_count: 1,
    created_at: "2026-04-11T12:00:00Z",
    mls_enabled: false,
    mls_group_id: null,
    mls_pending: false,
    mls_cipher_suite: null,
    conversation_id: null,
    member_agent_ids: [],
    ...over,
  };
}

describe("groupIsMls", () => {
  it("group_is_mls_when_group_has_an_mls_latch_returns_true", () => {
    expect(groupIsMls(group({ mls_group_id: "mls-latch-abc" }))).toBe(true);
  });

  it("group_is_mls_when_open_group_with_mls_enabled_returns_false", () => {
    // Open enrollment runs on sender keys by design — the server refuses MLS
    // there — yet the group still carries the `mls_enabled` intent flag.
    expect(
      groupIsMls(
        group({
          enrollment_policy: "open",
          mls_enabled: true,
          mls_group_id: null,
        }),
      ),
    ).toBe(false);
  });

  it("group_is_mls_when_init_is_still_pending_returns_false", () => {
    // An init in flight is not state: nothing can be decrypted with it yet.
    expect(groupIsMls(group({ mls_enabled: true, mls_pending: true }))).toBe(
      false,
    );
  });

  it("group_is_mls_when_group_is_sender_key_returns_false", () => {
    expect(groupIsMls(group())).toBe(false);
  });

  it("group_is_mls_when_the_mls_fields_are_absent_returns_false", () => {
    // A group projection minted before MLS existed carries neither field.
    expect(groupIsMls({})).toBe(false);
  });
});

describe("groupAcceptsMlsSendOnly", () => {
  it("group_accepts_mls_send_only_when_init_is_pending_returns_true", () => {
    // The server's `is_mls_frozen` mirror: a sender-key send into a group
    // whose init is in flight is refused with a 409, so the client must not
    // take the sender-key branch here.
    const pending = group({ mls_enabled: true, mls_pending: true });
    expect(groupAcceptsMlsSendOnly(pending)).toBe(true);
    expect(groupIsMls(pending)).toBe(false);
  });

  it("group_accepts_mls_send_only_when_group_has_an_mls_latch_returns_true", () => {
    expect(groupAcceptsMlsSendOnly(group({ mls_group_id: "mls-abc" }))).toBe(
      true,
    );
  });

  it("group_accepts_mls_send_only_when_open_group_with_mls_enabled_returns_false", () => {
    expect(
      groupAcceptsMlsSendOnly(
        group({ enrollment_policy: "open", mls_enabled: true }),
      ),
    ).toBe(false);
  });

  it("group_accepts_mls_send_only_when_the_mls_fields_are_absent_returns_false", () => {
    expect(groupAcceptsMlsSendOnly({})).toBe(false);
  });
});

describe("groupMlsInitInFlight", () => {
  it("group_mls_init_in_flight_when_init_is_pending_returns_true", () => {
    expect(
      groupMlsInitInFlight(group({ mls_enabled: true, mls_pending: true })),
    ).toBe(true);
  });

  it("group_mls_init_in_flight_when_group_has_an_mls_latch_returns_false", () => {
    // The latch ends the window, even if the server has not cleared the flag
    // yet: there is MLS state to render, so the group is simply MLS.
    expect(
      groupMlsInitInFlight(
        group({ mls_group_id: "mls-abc", mls_pending: true }),
      ),
    ).toBe(false);
  });

  it("group_mls_init_in_flight_when_open_group_with_mls_enabled_returns_false", () => {
    // The case the window must never swallow: open enrollment runs on sender
    // keys by design and no init is or will be in flight for it.
    expect(
      groupMlsInitInFlight(
        group({ enrollment_policy: "open", mls_enabled: true }),
      ),
    ).toBe(false);
  });

  it("group_mls_init_in_flight_when_group_is_sender_key_returns_false", () => {
    expect(groupMlsInitInFlight(group())).toBe(false);
    expect(groupMlsInitInFlight({})).toBe(false);
  });

  it("group_predicates_when_asked_together_place_a_group_in_exactly_one_state", () => {
    // The three renderable states are mutually exclusive and total, which is
    // what lets a renderer branch on them without a fourth fallback.
    const groups = [
      group({ mls_group_id: "mls-abc" }),
      group({ mls_enabled: true, mls_pending: true }),
      group({ enrollment_policy: "open", mls_enabled: true }),
      group(),
      {},
    ];
    for (const g of groups) {
      const states = [
        groupIsMls(g),
        groupMlsInitInFlight(g),
        !groupIsMls(g) && !groupMlsInitInFlight(g),
      ];
      expect(states.filter(Boolean)).toHaveLength(1);
    }
  });
});

describe("groupMlsNeverFounded", () => {
  it("group_mls_never_founded_when_closed_group_has_no_latch_returns_true", () => {
    // The founding never landed, and the server's 15-minute self-heal put
    // `mls_pending` back to false — so the four MLS columns are field for field
    // an open group's, and only what the group was created FOR tells them apart.
    expect(
      groupMlsNeverFounded(group({ enrollment_policy: "closed", mls_enabled: true })),
    ).toBe(true);
  });

  it("group_mls_never_founded_when_group_is_open_returns_false", () => {
    // The regression this predicate most plausibly causes: an open group has
    // the same null latch and carries `mls_enabled` from birth, and it is a
    // sender-key group by design — the server refuses MLS on it.
    expect(
      groupMlsNeverFounded(group({ enrollment_policy: "open", mls_enabled: true })),
    ).toBe(false);
  });

  it("group_mls_never_founded_when_closed_group_opted_out_of_mls_returns_false", () => {
    // Legal on the wire: `mls_enabled` may be set false while a group is
    // unlatched, and such a group really does run sender keys.
    expect(
      groupMlsNeverFounded(group({ enrollment_policy: "closed", mls_enabled: false })),
    ).toBe(false);
  });

  it("group_mls_never_founded_when_mls_enabled_is_absent_returns_false", () => {
    // The server always sends the field, so absence means a projection or a
    // hand-built row — never an answer, and never grounds for a refusal.
    expect(groupMlsNeverFounded({ enrollment_policy: "closed" })).toBe(false);
  });

  it("group_mls_never_founded_when_group_is_latched_returns_false", () => {
    expect(
      groupMlsNeverFounded(
        group({ enrollment_policy: "closed", mls_enabled: true, mls_group_id: "mls-abc" }),
      ),
    ).toBe(false);
  });

  it("group_mls_never_founded_when_init_is_in_flight_returns_false", () => {
    // Its own refusal already, with its own remedy: that one clears itself.
    expect(
      groupMlsNeverFounded(
        group({ enrollment_policy: "closed", mls_enabled: true, mls_pending: true }),
      ),
    ).toBe(false);
  });

  it("group_mls_never_founded_when_asked_beside_the_three_states_splits_only_the_third", () => {
    // It refines the sender-key fallthrough rather than adding a fourth
    // renderable state: nothing it answers true for is MLS or in flight.
    const rows = [
      group({ enrollment_policy: "closed", mls_enabled: true }),
      group({ enrollment_policy: "open", mls_enabled: true }),
      group({ enrollment_policy: "closed", mls_enabled: true, mls_group_id: "mls-abc" }),
      group({ enrollment_policy: "closed", mls_enabled: true, mls_pending: true }),
    ];
    for (const g of rows) {
      if (!groupMlsNeverFounded(g)) continue;
      expect(groupIsMls(g)).toBe(false);
      expect(groupMlsInitInFlight(g)).toBe(false);
    }
  });
});
