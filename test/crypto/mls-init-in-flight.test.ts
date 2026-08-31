/**
 * The in-flight-init refusal: one definition, one code, and — the part that
 * matters — outside the MLS recoverable taxonomy.
 *
 * `mlsErrorCode` classifies by the `RINE_MLS_` string prefix, so a code inside
 * that namespace would make this refusal an "unprocessable commit", therefore a
 * recoverable MLS read, therefore NACKed and swallowed by the one-shot recovery
 * in `decryptGroupMessage`. A refusal that heals itself is not a refusal, so the
 * namespace is asserted here rather than left to a reviewer's eye.
 */

import { describe, expect, it } from "vitest";
import { isRecoverableMlsRead } from "../../src/crypto/mls.js";
import {
  isUnprocessableCommit,
  mlsErrorCode,
} from "../../src/crypto/mls-errors.js";
import {
  MLS_INIT_IN_FLIGHT_CODE,
  MLS_PENDING_SELF_CLEAR_SECONDS,
  MlsInitInFlightError,
  isMlsInitInFlightError,
} from "../../src/crypto/mls-init-in-flight.js";

const HANDLE = "#dev@acme.rine.network";

describe("MlsInitInFlightError", () => {
  it("mls_init_in_flight_error_when_thrown_carries_the_stable_code", () => {
    const err = new MlsInitInFlightError(HANDLE);
    expect(err.code).toBe(MLS_INIT_IN_FLIGHT_CODE);
    expect(isMlsInitInFlightError(err)).toBe(true);
    expect(err.groupHandle).toBe(HANDLE);
  });

  it("mls_init_in_flight_error_when_matched_ignores_unrelated_errors", () => {
    expect(isMlsInitInFlightError(new Error("boom"))).toBe(false);
    expect(isMlsInitInFlightError(null)).toBe(false);
    expect(isMlsInitInFlightError(undefined)).toBe(false);
  });

  it("mls_init_in_flight_error_when_classified_is_not_a_recoverable_mls_read", () => {
    // The namespace trap. If this ever returns true the refusal is swallowed
    // by the read-recovery path and the send silently degrades.
    const err = new MlsInitInFlightError(HANDLE);
    expect(MLS_INIT_IN_FLIGHT_CODE.startsWith("RINE_MLS_")).toBe(false);
    expect(mlsErrorCode(err)).toBeNull();
    expect(isUnprocessableCommit(err)).toBe(false);
    expect(isRecoverableMlsRead(err)).toBe(false);
  });

  it("mls_init_in_flight_error_when_read_by_an_operator_names_the_self_clear_window", () => {
    // Derived from the one constant, never spelled a second time.
    const minutes = Math.round(MLS_PENDING_SELF_CLEAR_SECONDS / 60);
    expect(new MlsInitInFlightError(HANDLE).message).toContain(
      `${minutes} minutes`,
    );
  });
});
