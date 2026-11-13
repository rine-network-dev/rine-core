import * as fs from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	fromBase64Url,
	looksLikeSeat,
	type OperatorPin,
	pinMatchesKey,
	pinMatchesSender,
} from "../src/index.js";

/**
 * The TypeScript half of the operator pin parity gate: the id and full-key
 * comparison that decides operator authority, replayed from one hand-written
 * fixture shared with the Python twin
 * (`rine-sdk/tests/contract/test_operator_pin_golden.py`). Neither stack
 * regenerates it, so a stack cannot move its own goalposts.
 */
const FIXTURE = fileURLToPath(
	new URL("./fixtures/operator-pin.json", import.meta.url),
);

interface PinCase {
	name: string;
	pin_agent_id: string;
	pin_signing_key: string;
	pin_handle?: string;
	from_agent_id: string;
	verifying_key: string | null;
	matches_sender: boolean;
	matches_key: boolean;
}

interface LookalikeCase {
	name: string;
	pin: { handle?: string } | null;
	handle: string;
	looks_like_seat: boolean;
}

const fixture = JSON.parse(fs.readFileSync(FIXTURE, "utf8")) as {
	cases: PinCase[];
	seat_lookalike: LookalikeCase[];
};
const cases = fixture.cases;

function pinOf(c: PinCase): OperatorPin {
	return {
		agentId: c.pin_agent_id,
		signingKey: c.pin_signing_key,
		...(c.pin_handle === undefined ? {} : { handle: c.pin_handle }),
	};
}

describe("operator pin golden", () => {
	it("test_pin_when_cases_are_loaded_then_both_outcomes_are_covered", () => {
		expect(cases.length).toBeGreaterThan(10);
		expect(cases.some((c) => c.matches_sender && c.matches_key)).toBe(true);
		expect(cases.some((c) => !c.matches_sender)).toBe(true);
		expect(cases.some((c) => !c.matches_key)).toBe(true);
	});

	it.each(cases)("test_pin_matches_sender_matches_golden_when_$name", (c) => {
		const pin = pinOf(c);
		expect(pinMatchesSender(pin, c.from_agent_id)).toBe(c.matches_sender);
	});

	it.each(cases)("test_pin_matches_key_matches_golden_when_$name", (c) => {
		const pin = pinOf(c);
		const key =
			c.verifying_key === null ? null : fromBase64Url(c.verifying_key);
		expect(pinMatchesKey(pin, key)).toBe(c.matches_key);
	});

	it("test_pin_when_cases_carry_a_handle_then_authority_never_reads_it", () => {
		const withHandle = cases.filter((c) => c.pin_handle !== undefined);
		expect(withHandle.some((c) => !c.matches_sender)).toBe(true);
		expect(withHandle.some((c) => c.matches_sender && c.matches_key)).toBe(true);
	});
});

describe("seat look-alike golden", () => {
	it("test_lookalike_when_cases_are_loaded_then_both_outcomes_are_covered", () => {
		expect(fixture.seat_lookalike.some((c) => c.looks_like_seat)).toBe(true);
		expect(fixture.seat_lookalike.some((c) => !c.looks_like_seat)).toBe(true);
	});

	it.each(fixture.seat_lookalike)(
		"test_looks_like_seat_matches_golden_when_$name",
		(c) => {
			const pin: OperatorPin | null =
				c.pin === null
					? null
					: {
							...pinOf(cases[0] as PinCase),
							...(c.pin.handle === undefined ? {} : { handle: c.pin.handle }),
						};
			expect(looksLikeSeat(pin, c.handle)).toBe(c.looks_like_seat);
		},
	);
});
