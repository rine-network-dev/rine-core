import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { decodeEnvelope } from "../../src/crypto/envelope.js";
import {
	fromBase64Url,
	generateAgentKeys,
	generateSigningKeyPair,
	saveAgentKeys,
	toBase64Url,
} from "../../src/crypto/keys.js";
import { encryptGroupMessage } from "../../src/crypto/message.js";
import {
	advanceChain,
	deriveMessageKey,
	generateSenderKey,
	openGroup,
	sealGroup,
	type SenderKeyState,
} from "../../src/crypto/sender-keys.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
} from "../../src/crypto/sender-keys-helpers.js";

// ── helpers ──────────────────────────────────────────────────────────────────

function makeState(): SenderKeyState {
	return generateSenderKey("group-1", "agent-1");
}

function stateMap(state: SenderKeyState): Map<string, SenderKeyState> {
	return new Map([[state.senderKeyId, state]]);
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe("generateSenderKey", () => {
	it("produces state with expected shape", () => {
		const state = generateSenderKey("gid", "aid");
		expect(state.groupId).toBe("gid");
		expect(state.senderAgentId).toBe("aid");
		expect(state.messageIndex).toBe(0);
		expect(state.chainKey).toHaveLength(32);
		expect(state.senderKeyId).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
		);
	});

	it("produces different chain keys each call", () => {
		const a = generateSenderKey("g", "a");
		const b = generateSenderKey("g", "a");
		expect(Buffer.from(a.chainKey).equals(Buffer.from(b.chainKey))).toBe(false);
	});
});

describe("deriveMessageKey", () => {
	it("is deterministic for the same chain key", () => {
		const ck = new Uint8Array(32).fill(0xab);
		const r1 = deriveMessageKey(ck);
		const r2 = deriveMessageKey(ck);
		expect(Buffer.from(r1.messageKey).equals(Buffer.from(r2.messageKey))).toBe(true);
		expect(Buffer.from(r1.nextChainKey).equals(Buffer.from(r2.nextChainKey))).toBe(true);
	});

	it("message key and next chain key are different", () => {
		const { messageKey, nextChainKey } = deriveMessageKey(new Uint8Array(32).fill(1));
		expect(Buffer.from(messageKey).equals(Buffer.from(nextChainKey))).toBe(false);
	});

	it("returns 32-byte keys", () => {
		const { messageKey, nextChainKey } = deriveMessageKey(new Uint8Array(32).fill(2));
		expect(messageKey).toHaveLength(32);
		expect(nextChainKey).toHaveLength(32);
	});
});

describe("sealGroup + openGroup roundtrip", () => {
	it("recovers plaintext and advances state", async () => {
		const signing = generateSigningKeyPair();
		const state = makeState();
		const plaintext = new TextEncoder().encode("hello group");

		const { encryptedPayload, updatedState } = await sealGroup(
			signing.privateKey,
			"kid-1",
			state,
			plaintext,
		);

		expect(updatedState.messageIndex).toBe(1);

		const { innerEnvelope, senderKeyId, messageIndex, updatedState: recvState } = await openGroup(
			stateMap(state),
			encryptedPayload,
		);

		const decoded = decodeEnvelope(innerEnvelope);
		expect(new TextDecoder().decode(decoded.payload)).toBe("hello group");
		expect(senderKeyId).toBe(state.senderKeyId);
		expect(messageIndex).toBe(0);
		expect(recvState.messageIndex).toBe(1);
	});

	it("version byte in wire output is 0x02", async () => {
		const signing = generateSigningKeyPair();
		const state = makeState();
		const { encryptedPayload } = await sealGroup(
			signing.privateKey,
			"kid",
			state,
			new Uint8Array([1]),
		);
		expect(encryptedPayload[0]).toBe(0x02);
	});

	it("produces different ciphertext each time (random nonce)", async () => {
		const signing = generateSigningKeyPair();
		const state = makeState();
		const msg = new TextEncoder().encode("same");

		const { encryptedPayload: ct1 } = await sealGroup(signing.privateKey, "k", state, msg);
		const { encryptedPayload: ct2 } = await sealGroup(signing.privateKey, "k", state, msg);

		expect(Buffer.from(ct1).equals(Buffer.from(ct2))).toBe(false);
	});

	it("rejects unknown sender key id", async () => {
		const signing = generateSigningKeyPair();
		const state = makeState();
		const { encryptedPayload } = await sealGroup(
			signing.privateKey,
			"kid",
			state,
			new Uint8Array([1]),
		);

		await expect(openGroup(new Map(), encryptedPayload)).rejects.toThrow(
			"unknown sender key id",
		);
	});

	it("rejects wrong version byte", async () => {
		const signing = generateSigningKeyPair();
		const state = makeState();
		const { encryptedPayload } = await sealGroup(
			signing.privateKey,
			"kid",
			state,
			new Uint8Array([1]),
		);
		encryptedPayload[0] = 0x99;
		await expect(openGroup(stateMap(state), encryptedPayload)).rejects.toThrow(
			"unsupported version",
		);
	});
});

describe("out-of-order messages (skip + cache)", () => {
	it("can decrypt message at index 2 then go back and read index 1", async () => {
		const signing = generateSigningKeyPair();
		const sharedState = makeState();

		const sealed0 = await sealGroup(signing.privateKey, "k", sharedState, new TextEncoder().encode("msg-0"));
		const sealed1 = await sealGroup(signing.privateKey, "k", sealed0.updatedState, new TextEncoder().encode("msg-1"));
		const sealed2 = await sealGroup(signing.privateKey, "k", sealed1.updatedState, new TextEncoder().encode("msg-2"));

		const receiverStates = stateMap(sharedState);
		const result2 = await openGroup(receiverStates, sealed2.encryptedPayload);
		expect(decodeEnvelope(result2.innerEnvelope).payload).toEqual(new TextEncoder().encode("msg-2"));
		expect(result2.messageIndex).toBe(2);

		receiverStates.set(result2.updatedState.senderKeyId, result2.updatedState);
		expect(result2.updatedState.skippedKeys).toBeDefined();
		expect(result2.updatedState.skippedKeys![0]).toBeDefined();
		expect(result2.updatedState.skippedKeys![1]).toBeDefined();

		const result1 = await openGroup(receiverStates, sealed1.encryptedPayload);
		expect(new TextDecoder().decode(decodeEnvelope(result1.innerEnvelope).payload)).toBe("msg-1");

		receiverStates.set(result1.updatedState.senderKeyId, result1.updatedState);
		const result0 = await openGroup(receiverStates, sealed0.encryptedPayload);
		expect(new TextDecoder().decode(decodeEnvelope(result0.innerEnvelope).payload)).toBe("msg-0");
	});

	it("reading already-consumed key throws", async () => {
		const signing = generateSigningKeyPair();
		const sharedState = makeState();

		const sealed0 = await sealGroup(signing.privateKey, "k", sharedState, new TextEncoder().encode("msg-0"));
		const sealed1 = await sealGroup(signing.privateKey, "k", sealed0.updatedState, new TextEncoder().encode("msg-1"));

		const receiverStates = stateMap(sharedState);
		const result1 = await openGroup(receiverStates, sealed1.encryptedPayload);
		receiverStates.set(result1.updatedState.senderKeyId, result1.updatedState);

		const result0 = await openGroup(receiverStates, sealed0.encryptedPayload);
		receiverStates.set(result0.updatedState.senderKeyId, result0.updatedState);

		await expect(openGroup(receiverStates, sealed0.encryptedPayload)).rejects.toThrow(
			"message key expired or already consumed",
		);
	});
});

describe("sender key distribution ingestion roundtrip", () => {
	it("ingested distribution payload can decrypt a message from that sender", async () => {
		const signing = generateSigningKeyPair();

		const senderState = generateSenderKey("group-dist", "sender-agent");
		const plaintext = new TextEncoder().encode("group message");
		const { encryptedPayload } = await sealGroup(
			signing.privateKey,
			"kid-dist",
			senderState,
			plaintext,
		);

		const distPayload = {
			group_id: senderState.groupId,
			sender_key_id: senderState.senderKeyId,
			chain_key: toBase64Url(senderState.chainKey),
			message_index: senderState.messageIndex,
			sender_agent_id: senderState.senderAgentId,
		};

		const reconstructed: SenderKeyState = {
			senderKeyId: distPayload.sender_key_id,
			groupId: distPayload.group_id,
			senderAgentId: distPayload.sender_agent_id,
			chainKey: fromBase64Url(distPayload.chain_key),
			messageIndex: distPayload.message_index,
		};

		const { innerEnvelope } = await openGroup(
			stateMap(reconstructed),
			encryptedPayload,
		);
		const decoded = decodeEnvelope(innerEnvelope);
		expect(new TextDecoder().decode(decoded.payload)).toBe("group message");
	});
});

describe("encryptGroupMessage preserves foreign sender key states", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rine-sk-fix4-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("foreign sender key state survives encryptGroupMessage", async () => {
		const agentId = "00000000-0000-4000-a000-f00000000004";
		const groupId = "00000000-0000-4000-b000-f00000000004";

		const agentKeys = generateAgentKeys();
		saveAgentKeys(tmpDir, agentId, agentKeys);

		const ownState = generateSenderKey(groupId, agentId);
		const foreignState = generateSenderKey(groupId, "00000000-0000-4000-a000-f00000000099");

		saveSenderKeyState(tmpDir, agentId, groupId, [ownState, foreignState]);

		await encryptGroupMessage(tmpDir, agentId, groupId, ownState, { hello: "world" });

		const loaded = loadSenderKeyStates(tmpDir, agentId, groupId);
		expect(loaded).toHaveLength(2);
		const foreignLoaded = loaded.find(s => s.senderAgentId === "00000000-0000-4000-a000-f00000000099");
		expect(foreignLoaded).toBeDefined();
		expect(foreignLoaded!.senderKeyId).toBe(foreignState.senderKeyId);
	});
});

describe("advanceChain", () => {
	it("returns skipped keys for each index", () => {
		const state = makeState();
		const { skippedKeys, updatedState } = advanceChain(state, 3);
		expect(skippedKeys.size).toBe(3);
		expect(skippedKeys.has(0)).toBe(true);
		expect(skippedKeys.has(1)).toBe(true);
		expect(skippedKeys.has(2)).toBe(true);
		expect(updatedState.messageIndex).toBe(3);
	});

	it("throws when skip exceeds max", () => {
		const state = makeState();
		expect(() => advanceChain(state, 1001)).toThrow("too many skipped messages");
	});

	it("exactly 1000 skips is allowed", () => {
		const state = makeState();
		expect(() => advanceChain(state, 1000)).not.toThrow();
	});
});

describe("saveSenderKeyState / loadSenderKeyStates", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rine-sk-test-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("roundtrips sender key states including chain key", () => {
		const state = makeState();
		const agX = "00000000-0000-4000-a000-aaaaaaaaaaaa";
		const grY = "00000000-0000-4000-b000-bbbbbbbbbbbb";
		saveSenderKeyState(tmpDir, agX, grY, [state]);
		const loaded = loadSenderKeyStates(tmpDir, agX, grY);

		expect(loaded).toHaveLength(1);
		const s = loaded[0]!;
		expect(s.senderKeyId).toBe(state.senderKeyId);
		expect(s.groupId).toBe(state.groupId);
		expect(s.senderAgentId).toBe(state.senderAgentId);
		expect(s.messageIndex).toBe(state.messageIndex);
		expect(Buffer.from(s.chainKey).equals(Buffer.from(state.chainKey))).toBe(true);
	});

	it("roundtrips skipped keys through save/load", () => {
		const state = makeState();
		state.skippedKeys = { 0: "AAAA", 1: "BBBB", 5: "CCCC" };
		const agS = "00000000-0000-4000-a000-cccccccccccc";
		const grS = "00000000-0000-4000-b000-dddddddddddd";
		saveSenderKeyState(tmpDir, agS, grS, [state]);
		const loaded = loadSenderKeyStates(tmpDir, agS, grS);

		expect(loaded).toHaveLength(1);
		const s = loaded[0]!;
		expect(s.skippedKeys).toBeDefined();
		expect(s.skippedKeys![0]).toBe("AAAA");
		expect(s.skippedKeys![1]).toBe("BBBB");
		expect(s.skippedKeys![5]).toBe("CCCC");
	});

	it("returns empty array when file does not exist", () => {
		const result = loadSenderKeyStates(tmpDir, "00000000-0000-4000-a000-eeeeeeeeeeee", "00000000-0000-4000-b000-ffffffffffff");
		expect(result).toEqual([]);
	});

	it("sets restrictive file permissions", () => {
		const state = makeState();
		const permAg = "00000000-0000-4000-a000-111111111111";
		const permGr = "00000000-0000-4000-b000-222222222222";
		saveSenderKeyState(tmpDir, permAg, permGr, [state]);
		const filePath = path.join(tmpDir, "keys", permAg, "sender_keys", `${permGr}.json`);
		const stat = fs.statSync(filePath);
		expect(stat.mode & 0o777).toBe(0o600);
	});
});
