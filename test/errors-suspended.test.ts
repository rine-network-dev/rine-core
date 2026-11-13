// A held principal (suspended agent, suspended branch, frozen org) is refused with a hold code:
// a 403 carries it in `error` on a bearer route, the token mint's 400 `unauthorized_client`
// carries it in `reason`. `holdOf` is the one reader of both shapes, and the funnel relay's
// `TunnelBindError` is what tells a held agent (pause) from a revoked one (exit).
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import { GovernanceRefusal, HoldCode, holdOf } from "../src/errors-suspended.js";
import { DelegateScope } from "../src/org-governance-types.js";
import {
	BindNakReason,
	CLOSE_SUSPENDED,
	TunnelBindError,
} from "../src/funnel/tunnel.js";

describe("holdOf", () => {
	it.each(Object.values(HoldCode))("reads %s from a 403 `error`", (code) => {
		expect(holdOf(403, { error: code, detail: "held" })).toBe(code);
	});

	it.each(Object.values(HoldCode))(
		"reads %s from a mint 400 `reason`",
		(code) => {
			expect(holdOf(400, { error: "unauthorized_client", reason: code })).toBe(
				code,
			);
		},
	);

	it("names no hold for any other shape", () => {
		expect(holdOf(403, { error: "AuthorizationError" })).toBeUndefined();
		expect(holdOf(401, { error: HoldCode.AgentSuspended })).toBeUndefined();
		expect(
			holdOf(400, { error: "invalid_client", reason: HoldCode.AgentSuspended }),
		).toBeUndefined();
		expect(holdOf(400, { error: HoldCode.AgentSuspended })).toBeUndefined();
		expect(holdOf(403, { error: "constructor" })).toBeUndefined();
		expect(holdOf(403, undefined)).toBeUndefined();
	});
});

describe("TunnelBindError", () => {
	it("carries the NAK reason and is revoked for every reason but suspended", () => {
		for (const reason of Object.values(BindNakReason)) {
			const err = new TunnelBindError(reason);
			expect(err.reason).toBe(reason);
			expect(err.revoked).toBe(reason !== BindNakReason.Suspended);
		}
		expect(new TunnelBindError("a-reason-from-a-newer-broker").revoked).toBe(
			true,
		);
	});

	it("names the suspended close code the broker sends", () => {
		expect(CLOSE_SUSPENDED).toBe(4423);
	});
});

describe("governance code fixture", () => {
	const fixture = JSON.parse(
		fs.readFileSync(new URL("./fixtures/governance-codes.json", import.meta.url), "utf-8"),
	) as Record<string, string[]>;

	it("names exactly the codes the client enumerates, as the server does", () => {
		expect(fixture.holds).toEqual(Object.values(HoldCode));
		expect(fixture.refusals).toEqual(Object.values(GovernanceRefusal));
		expect(fixture.delegate_scopes).toEqual(Object.values(DelegateScope));
	});
});
