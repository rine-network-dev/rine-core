import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SENDER_KEY_DISTRIBUTION_TYPE } from "../src/control-frames.js";
import {
	chainKeyAt,
	deriveMessageKey,
	generateSenderKey,
	sealGroup,
} from "../src/crypto/sender-keys.js";
import type { SenderKeyState } from "../src/crypto/sender-keys.js";
import { toBase64Url } from "../src/crypto/keys.js";
import { parseSenderKeyWire } from "../src/crypto/sender-key-wire.js";
import {
	ORG_READ_MAX_CHAIN_STEPS,
	SenderKeyReader,
	type SenderVerifier,
} from "../src/org-reader/sender-key.js";
import { distributionState } from "../src/org-reader/distribution.js";
import { ReadGapReason } from "../src/org-reader/gaps.js";
import { type ReadMessage, readMessage } from "../src/org-reader/page.js";
import { type Row, isParseFailure, parseRow } from "../src/org-reader/rows.js";

const GROUP = "11111111-1111-4111-8111-111111111111";
const SENDER = "aaaaaaaa-0000-4000-8000-000000000001";
const SIGNING_KEY = new Uint8Array(32).fill(7);

const verifier: SenderVerifier = {
	async verify(decoded) {
		return {
			text: new TextDecoder().decode(decoded.payload),
			verification: null,
		};
	},
};

function makeRow(
	over: Record<string, unknown> = {},
	ciphertext: Uint8Array = new Uint8Array(40),
): Row {
	const result = parseRow({
		id: "m-1",
		created_at: "2026-10-24T12:00:10.000000Z",
		type: "rine.v1.group_message",
		direction: "received",
		from: { agent_id: SENDER, handle: null, org_id: "org-a", own: false },
		to: null,
		group: { id: GROUP, handle: "g@x" },
		conversation_id: "conv-a",
		encryption_version: "sender-key-v1",
		payload: { encrypted_payload: toBase64Url(Uint8Array.from(ciphertext)) },
		...over,
	});
	if (isParseFailure(result)) throw new Error("expected a row");
	return result;
}

/** A state the sender holds `steps` messages into its chain. */
function advancedBy(state: SenderKeyState, steps: number): SenderKeyState {
	let chainKey = state.chainKey;
	for (let i = 0; i < steps; i++)
		chainKey = deriveMessageKey(chainKey).nextChainKey;
	return { ...state, chainKey, messageIndex: state.messageIndex + steps };
}

async function sealedRow(
	state: SenderKeyState,
	text: string,
	over: Record<string, unknown> = {},
): Promise<Row> {
	const { encryptedPayload } = await sealGroup(
		SIGNING_KEY,
		"kid",
		state,
		new TextEncoder().encode(text),
	);
	return makeRow(over, encryptedPayload);
}

function distribution(state: SenderKeyState): ReadMessage {
	const text = JSON.stringify({
		group_id: state.groupId,
		sender_key_id: state.senderKeyId,
		chain_key: toBase64Url(state.chainKey),
		message_index: state.messageIndex,
	});
	return readMessage(makeRow({ type: SENDER_KEY_DISTRIBUTION_TYPE }), { text });
}

describe("distributionState", () => {
	const state = generateSenderKey(GROUP, SENDER);

	it("returns_the_state_a_verified_distribution_carries", () => {
		const parsed = distributionState(distribution(state));
		expect(parsed?.senderKeyId).toBe(state.senderKeyId);
		expect(parsed?.senderAgentId).toBe(SENDER);
		expect(parsed?.messageIndex).toBe(0);
	});

	it("is_null_when_the_row_type_is_not_a_distribution", () => {
		const message = distribution(state);
		expect(
			distributionState({ ...message, row: makeRow({ type: "rine.v1.dm" }) }),
		).toBeNull();
	});

	it("is_null_when_the_text_is_withheld_or_not_a_distribution_object", () => {
		const message = distribution(state);
		expect(distributionState({ ...message, text: null })).toBeNull();
		expect(distributionState({ ...message, text: "not json" })).toBeNull();
		expect(distributionState({ ...message, text: "[1]" })).toBeNull();
		expect(distributionState({ ...message, text: "{}" })).toBeNull();
	});
});

describe("SenderKeyReader.open", () => {
	it("opens_a_message_from_a_distribution_at_index_zero", async () => {
		const state = generateSenderKey(GROUP, SENDER);
		const reader = new SenderKeyReader(verifier);
		reader.ingest([distribution(state)]);
		const opened = await reader.open(await sealedRow(state, "hello"));
		expect(opened.text).toBe("hello");
		expect(opened.verification).toBeNull();
		expect(opened.gap).toBeNull();
		expect(opened.slot).toBe(JSON.stringify([GROUP, state.senderKeyId, 0]));
		expect(opened.envelope).not.toBeNull();
	});

	it("carries_the_verifier_verdict_and_withholds_text_when_unverified", async () => {
		const state = generateSenderKey(GROUP, SENDER);
		const reader = new SenderKeyReader({
			verify: async () => ({ text: null, verification: "invalid" }),
		});
		reader.ingest([distribution(state)]);
		const opened = await reader.open(await sealedRow(state, "hello"));
		expect(opened.text).toBeNull();
		expect(opened.verification).toBe("invalid");
	});

	it("reports_no_distribution_when_no_state_is_held", async () => {
		const state = generateSenderKey(GROUP, SENDER);
		const opened = await new SenderKeyReader(verifier).open(
			await sealedRow(state, "x"),
		);
		expect(opened.gap).toEqual({
			reason: ReadGapReason.NoDistribution,
			sender: SENDER,
		});
	});

	it("reports_no_distribution_when_every_held_state_is_above_the_index", async () => {
		const state = generateSenderKey(GROUP, SENDER);
		const reader = new SenderKeyReader(verifier);
		reader.ingest([distribution(advancedBy(state, 5))]);
		const opened = await reader.open(await sealedRow(state, "x"));
		expect(opened.gap?.reason).toBe(ReadGapReason.NoDistribution);
	});

	it("reports_unreadable_for_a_malformed_wire_or_a_row_without_a_group", async () => {
		const reader = new SenderKeyReader(verifier);
		expect(
			(await reader.open(makeRow({}, new Uint8Array(5)))).gap?.reason,
		).toBe(ReadGapReason.Unreadable);
		const wrongVersion = new Uint8Array(40);
		wrongVersion[0] = 1;
		expect((await reader.open(makeRow({}, wrongVersion))).gap?.reason).toBe(
			ReadGapReason.Unreadable,
		);
		const state = generateSenderKey(GROUP, SENDER);
		const grouplessRow = await sealedRow(state, "x", { group: null });
		expect((await reader.open(grouplessRow)).gap?.reason).toBe(
			ReadGapReason.Unreadable,
		);
	});

	it("reports_unreadable_when_the_ciphertext_does_not_open", async () => {
		const state = generateSenderKey(GROUP, SENDER);
		const reader = new SenderKeyReader(verifier);
		reader.ingest([
			distribution({ ...state, chainKey: new Uint8Array(32).fill(9) }),
		]);
		const opened = await reader.open(await sealedRow(state, "x"));
		expect(opened.gap).toEqual({ reason: ReadGapReason.Unreadable });
	});

	it("rethrows_a_programming_error_instead_of_reporting_unreadable", async () => {
		class Defective extends Uint8Array {
			override slice(): never {
				throw new TypeError("defect");
			}
		}
		const state = generateSenderKey(GROUP, SENDER);
		const reader = new SenderKeyReader(verifier);
		reader.ingest([distribution(state)]);
		const sealed = await sealedRow(state, "x");
		const row = { ...sealed, ciphertext: Defective.from(sealed.ciphertext) };
		await expect(reader.open(row)).rejects.toThrow(TypeError);
	});

	it("steps_exactly_the_chain_step_bound_and_refuses_one_more", async () => {
		expect(ORG_READ_MAX_CHAIN_STEPS).toBe(10_000);
		const state = generateSenderKey(GROUP, SENDER);
		const reader = new SenderKeyReader(verifier);
		reader.ingest([distribution(state)]);
		const atBound = await reader.open(
			await sealedRow(advancedBy(state, 10_000), "far"),
		);
		expect(atBound.text).toBe("far");
		const pastBound = new SenderKeyReader(verifier);
		pastBound.ingest([distribution(state)]);
		const refused = await pastBound.open(
			await sealedRow(advancedBy(state, 10_001), "forged"),
		);
		expect(refused.gap).toEqual({
			reason: ReadGapReason.RatchetGap,
			sender: SENDER,
			index: 10_001,
		});
	});

	it("starts_from_the_advanced_state_after_an_earlier_open", async () => {
		const state = generateSenderKey(GROUP, SENDER);
		const reader = new SenderKeyReader(verifier);
		reader.ingest([distribution(state)]);
		const far = await sealedRow(advancedBy(state, 15_000), "later");
		expect((await reader.open(far)).gap?.reason).toBe(ReadGapReason.RatchetGap);
		const middle = await sealedRow(advancedBy(state, 8_000), "middle");
		expect((await reader.open(middle)).text).toBe("middle");
		expect((await reader.open(far)).text).toBe("later");
	});

	it("matches_the_sender_slot_case_insensitively", async () => {
		const state = generateSenderKey(GROUP, SENDER.toLowerCase());
		const reader = new SenderKeyReader(verifier);
		reader.ingest([distribution(state)]);
		const opened = await reader.open(await sealedRow(state, "hi"));
		expect(opened.text).toBe("hi");
	});
});

describe("SenderKeyReader.want, satisfied and ingest", () => {
	it("is_satisfied_when_nothing_is_wanted", () => {
		expect(new SenderKeyReader(verifier).satisfied()).toBe(true);
	});

	it("wants_the_lowest_index_per_slot_and_is_satisfied_by_a_state_at_or_below_it", async () => {
		const state = generateSenderKey(GROUP, SENDER);
		const reader = new SenderKeyReader(verifier);
		reader.want([
			await sealedRow(advancedBy(state, 7), "a"),
			await sealedRow(advancedBy(state, 3), "b"),
		]);
		expect(reader.satisfied()).toBe(false);
		reader.ingest([distribution(advancedBy(state, 4))]);
		expect(reader.satisfied()).toBe(false);
		reader.ingest([distribution(advancedBy(state, 3))]);
		expect(reader.satisfied()).toBe(true);
	});

	it("ignores_rows_that_name_no_group_or_carry_a_malformed_wire", async () => {
		const state = generateSenderKey(GROUP, SENDER);
		const reader = new SenderKeyReader(verifier);
		reader.want([
			makeRow({}, new Uint8Array(3)),
			await sealedRow(state, "x", { group: null }),
		]);
		expect(reader.satisfied()).toBe(true);
	});

	it("keeps_the_first_state_seen_for_a_message_index", async () => {
		const state = generateSenderKey(GROUP, SENDER);
		const reader = new SenderKeyReader(verifier);
		reader.ingest([
			distribution(state),
			distribution({ ...state, chainKey: new Uint8Array(32).fill(5) }),
		]);
		expect((await reader.open(await sealedRow(state, "first"))).text).toBe(
			"first",
		);
	});

	it("ignores_messages_that_are_not_verified_distributions", async () => {
		const state = generateSenderKey(GROUP, SENDER);
		const reader = new SenderKeyReader(verifier);
		reader.ingest([{ ...distribution(state), text: null }]);
		expect((await reader.open(await sealedRow(state, "x"))).gap?.reason).toBe(
			ReadGapReason.NoDistribution,
		);
	});
});

describe("open-group chain-step bound parity", () => {
	it("pins_the_bound_to_the_python_reader_constant", () => {
		const source = readFileSync(
			join(
				__dirname,
				"..",
				"..",
				"fleet",
				"src",
				"fleet",
				"core",
				"org_reader",
				"sender_key.py",
			),
			"utf8",
		);
		const match = /^MAX_CHAIN_STEPS: Final = ([\d_]+)/m.exec(source);
		expect(Number((match?.[1] ?? "").replaceAll("_", ""))).toBe(
			ORG_READ_MAX_CHAIN_STEPS,
		);
	});
});

describe("the reader and the live decrypt path share one wire parser", () => {
	it("names_the_key_id_and_index_the_live_sealer_wrote", async () => {
		const state = advancedBy(generateSenderKey(GROUP, SENDER), 3);
		const row = await sealedRow(state, "hi");
		expect(parseSenderKeyWire(row.ciphertext)).toEqual({
			keyId: state.senderKeyId,
			index: 3,
		});
	});

	it("refuses_a_wire_version_the_live_path_refuses", async () => {
		const state = generateSenderKey(GROUP, SENDER);
		const bumped = Uint8Array.from((await sealedRow(state, "hi")).ciphertext);
		bumped[0] = 0x03;
		expect(() => parseSenderKeyWire(bumped)).toThrow("unsupported version");
		const reader = new SenderKeyReader(verifier);
		reader.ingest([distribution(state)]);
		const opened = await reader.open(makeRow({}, bumped));
		expect(opened.gap?.reason).toBe(ReadGapReason.Unreadable);
	});

	it("derives_the_chain_key_the_ratchet_reaches", () => {
		const state = generateSenderKey(GROUP, SENDER);
		expect(chainKeyAt(state, 5)).toEqual(advancedBy(state, 5).chainKey);
	});
});
