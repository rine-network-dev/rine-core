import { EscrowGapReason } from "@rine-network/mls";
import { describe, expect, it } from "vitest";
import {
	AGENT_ID_MISMATCH_CODE,
	AgentIdMismatchError,
	ESCROW_GAP_CODE,
	EscrowGapError,
	ORG_MISMATCH_CODE,
	OrgMismatchError,
	isAgentIdMismatchError,
	isEscrowGapError,
	isOrgMismatchError,
} from "../src/errors.js";

const gap = new EscrowGapError("g", 3, EscrowGapReason.Malformed);
const org = new OrgMismatchError("a", "b");
const agent = new AgentIdMismatchError("a", "b");

describe("the refusals rine-core mints", () => {
	it("test_refusals_when_minted_then_each_carries_its_stable_code", () => {
		expect(gap.code).toBe(ESCROW_GAP_CODE);
		expect(org.code).toBe(ORG_MISMATCH_CODE);
		expect(agent.code).toBe(AGENT_ID_MISMATCH_CODE);
	});

	it("test_predicates_when_asked_then_each_matches_only_its_own_refusal", () => {
		expect([gap, org, agent].map(isEscrowGapError)).toEqual([true, false, false]);
		expect([gap, org, agent].map(isOrgMismatchError)).toEqual([false, true, false]);
		expect([gap, org, agent].map(isAgentIdMismatchError)).toEqual([false, false, true]);
		expect(isEscrowGapError(undefined)).toBe(false);
	});
});
