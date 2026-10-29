/**
 * The loss a revoked principal means: three refusals from three places, one
 * mapping. Anything that does not name a revocation stays an ordinary failure.
 */
import { describe, expect, it } from "vitest";
import { PrincipalRevokedError, RineApiError, RevokedScope } from "../src/errors.js";
import { EscrowLoss } from "../src/mls-escrow-gap.js";
import { BranchRevokedError } from "../src/mls-escrow-key.js";
import { revokedLoss } from "../src/mls-escrow-revoked.js";

describe("revokedLoss", () => {
	it("test_revoked_loss_when_the_branch_key_read_was_refused_then_it_is_a_branch_revocation", () => {
		expect(revokedLoss(new BranchRevokedError())).toBe(EscrowLoss.BranchRevoked);
	});

	it("test_revoked_loss_when_the_principal_is_the_agent_then_it_is_an_agent_revocation", () => {
		const error = new PrincipalRevokedError(RevokedScope.Agent, "agent revoked");

		expect(revokedLoss(error)).toBe(EscrowLoss.AgentRevoked);
	});

	it("test_revoked_loss_when_the_principal_is_the_branch_then_it_is_a_branch_revocation", () => {
		const error = new PrincipalRevokedError(RevokedScope.Branch, "branch revoked");

		expect(revokedLoss(error)).toBe(EscrowLoss.BranchRevoked);
	});

	it("test_revoked_loss_when_an_upload_answers_branch_revoked_then_it_is_a_branch_revocation", () => {
		const error = new RineApiError(422, "branch revoked", undefined, "branch_revoked");

		expect(revokedLoss(error)).toBe(EscrowLoss.BranchRevoked);
	});

	it("test_revoked_loss_when_an_upload_answers_agent_revoked_then_it_is_an_agent_revocation", () => {
		const error = new RineApiError(422, "agent revoked", undefined, "agent_revoked");

		expect(revokedLoss(error)).toBe(EscrowLoss.AgentRevoked);
	});

	it.each([403, 500, 502])(
		"test_revoked_loss_when_a_%i_carries_a_revoked_code_then_it_is_no_revocation",
		(status) => {
			for (const code of ["agent_revoked", "branch_revoked"]) {
				expect(revokedLoss(new RineApiError(status, "echo", undefined, code))).toBeUndefined();
			}
		},
	);

	it("test_revoked_loss_when_a_plain_401_names_no_scope_then_it_is_no_revocation", () => {
		expect(revokedLoss(new RineApiError(401, "unauthorized"))).toBeUndefined();
	});

	it("test_revoked_loss_when_the_value_is_not_an_error_then_it_is_no_revocation", () => {
		expect(revokedLoss("branch_revoked")).toBeUndefined();
	});
});
