import { describe, expect, it } from "vitest";
import { toBase64Url } from "../src/crypto/keys.js";
import {
	distributionGroupId,
	parseSenderKeyDistribution,
} from "../src/crypto/sk-distribution.js";

const GROUP = "11111111-1111-4111-8111-111111111111";
const KEY_ID = "22222222-2222-4222-8222-222222222222";
const SIGNER = "33333333-3333-4333-8333-333333333333";
const chainKey = new Uint8Array(32).fill(7);

const payload = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
	group_id: GROUP,
	sender_key_id: KEY_ID,
	chain_key: toBase64Url(chainKey),
	...over,
});

describe("parseSenderKeyDistribution", () => {
	it("builds the state from a valid payload, index absent meaning zero", () => {
		expect(parseSenderKeyDistribution(payload(), GROUP, SIGNER)).toEqual({
			senderKeyId: KEY_ID,
			groupId: GROUP,
			senderAgentId: SIGNER,
			chainKey,
			messageIndex: 0,
		});
	});

	it("takes the signer and group from its arguments, not the payload", () => {
		const state = parseSenderKeyDistribution(
			payload({ sender_agent_id: "evil", message_index: 5 }),
			GROUP,
			SIGNER,
		);
		expect(state?.senderAgentId).toBe(SIGNER);
		expect(state?.messageIndex).toBe(5);
	});

	it("lower-cases the sender key id", () => {
		const state = parseSenderKeyDistribution(
			payload({ sender_key_id: KEY_ID.toUpperCase() }),
			GROUP,
			SIGNER,
		);
		expect(state?.senderKeyId).toBe(KEY_ID);
	});

	it.each([
		["a non-string chain key", { chain_key: 5 }],
		["a missing chain key", { chain_key: undefined }],
		["a 31-byte chain key", { chain_key: toBase64Url(new Uint8Array(31)) }],
		["a 33-byte chain key", { chain_key: toBase64Url(new Uint8Array(33)) }],
		["a null index", { message_index: null }],
		["a negative index", { message_index: -1 }],
		["a fractional index", { message_index: 1.5 }],
		["an index above uint32", { message_index: 0x100000000 }],
		["a string index", { message_index: "1" }],
		["a non-UUID key id", { sender_key_id: "../x" }],
		["a missing key id", { sender_key_id: undefined }],
	])("returns null for %s", (_label, over) => {
		expect(parseSenderKeyDistribution(payload(over), GROUP, SIGNER)).toBeNull();
	});

	it("accepts the uint32 maximum", () => {
		const state = parseSenderKeyDistribution(
			payload({ message_index: 0xffffffff }),
			GROUP,
			SIGNER,
		);
		expect(state?.messageIndex).toBe(0xffffffff);
	});
});

describe("parseSenderKeyDistribution known divergence", () => {
	it("accepts a float-literal index that Python refuses (JSON.parse erases the spelling)", () => {
		const parsed = JSON.parse(
			`{"sender_key_id":"${KEY_ID}","chain_key":"${toBase64Url(chainKey)}","message_index":5.0}`,
		) as Record<string, unknown>;
		expect(parseSenderKeyDistribution(parsed, GROUP, SIGNER)?.messageIndex).toBe(5);
	});
});

describe("distributionGroupId", () => {
	it("lower-cases the group id", () => {
		expect(distributionGroupId(payload({ group_id: GROUP.toUpperCase() }))).toBe(GROUP);
	});

	it.each([[undefined], [7], ["../etc"]])("throws on %s", (value) => {
		expect(() => distributionGroupId(payload({ group_id: value }))).toThrow();
	});
});
