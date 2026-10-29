/**
 * How the server's refusal of one pending escrow upload is sorted. A terminal
 * `error` code parks the file for ever, so it is honoured only on the 4xx the
 * escrow routes answer it with; the same code on a 5xx or a throttle is an
 * intermediary's, not the server's refusal of this file.
 */
import { describe, expect, it } from "vitest";
import {
	EscrowAnswer,
	EscrowTerminalCode,
	classifyRefusal,
} from "../src/mls-escrow-answer.js";
import { PrincipalRevokedError, RineApiError, RevokedScope } from "../src/errors.js";

function refusal(status: number, code?: string): RineApiError {
	return new RineApiError(status, "x", undefined, code);
}

describe("classifyRefusal", () => {
	it.each(Object.values(EscrowTerminalCode))(
		"test_classify_refusal_when_the_4xx_names_terminal_code_%s_then_it_is_refused",
		(code) => {
			expect(classifyRefusal(refusal(403, code))).toBe(EscrowAnswer.Refused);
		},
	);

	it("test_classify_refusal_when_the_slot_is_taken_then_it_counts_as_stored", () => {
		expect(classifyRefusal(refusal(409, "escrow_slot_taken"))).toBe(EscrowAnswer.Stored);
	});

	it("test_classify_refusal_when_a_server_error_carries_a_terminal_code_then_it_backs_off_and_parks_nothing", () => {
		expect(classifyRefusal(refusal(500, EscrowTerminalCode.NoSeat))).toBe(EscrowAnswer.Backoff);
		expect(classifyRefusal(refusal(503, EscrowTerminalCode.ForkLimit))).toBe(EscrowAnswer.Backoff);
	});

	it("test_classify_refusal_when_a_throttle_carries_a_terminal_or_slot_code_then_it_backs_off", () => {
		expect(classifyRefusal(refusal(429, EscrowTerminalCode.BranchRevoked))).toBe(EscrowAnswer.Backoff);
		expect(classifyRefusal(refusal(429, "escrow_slot_taken"))).toBe(EscrowAnswer.Backoff);
	});

	it("test_classify_refusal_when_a_bare_403_or_404_has_no_code_then_it_is_retried", () => {
		expect(classifyRefusal(refusal(403))).toBe(EscrowAnswer.Retry);
		expect(classifyRefusal(refusal(404))).toBe(EscrowAnswer.Retry);
	});

	it("test_classify_refusal_when_a_4xx_names_an_unknown_code_then_it_is_retried", () => {
		expect(classifyRefusal(refusal(422, "something_else"))).toBe(EscrowAnswer.Retry);
	});

	it.each([RevokedScope.Agent, RevokedScope.Branch])(
		"test_classify_refusal_when_a_principal_revoked_error_then_refused",
		(scope) => {
			expect(classifyRefusal(new PrincipalRevokedError(scope, "revoked"))).toBe(
				EscrowAnswer.Refused,
			);
		},
	);

	it("test_classify_refusal_when_a_plain_401_has_no_code_then_it_is_retried", () => {
		expect(classifyRefusal(refusal(401))).toBe(EscrowAnswer.Retry);
	});
});
