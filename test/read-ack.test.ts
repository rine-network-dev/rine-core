import { describe, expect, it, vi } from "vitest";
import { ACTING_AGENT_HEADER } from "../src/actor.js";
import type { MessageRead } from "../src/api-types.js";
import type { HttpClient } from "../src/http.js";
import { ackAfterRead, isSettledRow } from "../src/read-ack.js";

const AGENT = "11111111-1111-1111-1111-111111111111";
const MESSAGE = "22222222-2222-2222-2222-222222222222";

function row(
	encryption_version: string,
	verification_status?: "invalid" | "sender-mismatch" | "unverifiable",
) {
	return {
		id: MESSAGE,
		encryption_version,
		...(verification_status ? { verification_status } : {}),
	} as MessageRead & { verification_status?: "invalid" };
}

describe("isSettledRow", () => {
	it("test_isSettledRow_when_the_row_opened_then_it_is_settled", () => {
		expect(isSettledRow(row("hpke-hybrid-v2"), true)).toBe(true);
	});

	it("test_isSettledRow_when_the_row_was_never_ciphertext_then_it_is_settled", () => {
		expect(isSettledRow(row("none"), false)).toBe(true);
	});

	it("test_isSettledRow_when_the_encryption_version_is_unknown_then_it_is_not", () => {
		expect(isSettledRow(row("hpke-v9"), false)).toBe(false);
	});

	it.each(["invalid", "sender-mismatch"] as const)(
		"test_isSettledRow_when_the_author_is_refused_as_%s_then_it_is_settled",
		(status) => {
			expect(isSettledRow(row("hpke-hybrid-v2", status), false)).toBe(true);
		},
	);

	it("test_isSettledRow_when_no_key_material_opened_a_direct_row_then_it_is_not", () => {
		expect(isSettledRow(row("hpke-hybrid-v2"), false)).toBe(false);
	});

	it("test_isSettledRow_when_a_group_sender_key_has_not_arrived_then_it_is_not", () => {
		expect(isSettledRow(row("sender-key-v1"), false)).toBe(false);
	});

	it("test_isSettledRow_when_the_verdict_is_only_unverifiable_then_it_is_not", () => {
		expect(isSettledRow(row("hpke-hybrid-v2", "unverifiable"), false)).toBe(
			false,
		);
	});
});

describe("ackAfterRead", () => {
	const client = (markDelivered: () => Promise<unknown>) =>
		({ markDelivered: vi.fn(markDelivered) }) as unknown as HttpClient & {
			markDelivered: ReturnType<typeof vi.fn>;
		};

	it("test_ackAfterRead_when_settled_and_not_peeking_then_it_marks_for_the_acting_agent", async () => {
		const c = client(async () => ({ marked: 1 }));

		expect(await ackAfterRead(c, AGENT, [MESSAGE], { settled: true })).toBeNull();
		expect(c.markDelivered).toHaveBeenCalledWith(AGENT, [MESSAGE], {
			[ACTING_AGENT_HEADER]: AGENT,
		});
	});

	it("test_ackAfterRead_when_peeking_then_it_never_marks", async () => {
		const c = client(async () => ({ marked: 1 }));

		await ackAfterRead(c, AGENT, [MESSAGE], { settled: true, peek: true });

		expect(c.markDelivered).not.toHaveBeenCalled();
	});

	it("test_ackAfterRead_when_unsettled_then_it_never_marks", async () => {
		const c = client(async () => ({ marked: 1 }));

		await ackAfterRead(c, AGENT, [MESSAGE], { settled: false });

		expect(c.markDelivered).not.toHaveBeenCalled();
	});

	it("test_ackAfterRead_when_no_id_is_given_then_it_makes_no_request", async () => {
		const c = client(async () => ({ marked: 0 }));

		expect(await ackAfterRead(c, AGENT, [], { settled: true })).toBeNull();
		expect(c.markDelivered).not.toHaveBeenCalled();
	});

	it("test_ackAfterRead_when_the_mark_fails_then_it_returns_the_failure_without_throwing", async () => {
		const c = client(async () => {
			throw new Error("503");
		});

		const failure = await ackAfterRead(c, AGENT, [MESSAGE], { settled: true });

		expect(failure?.message).toBe("503");
	});
});
