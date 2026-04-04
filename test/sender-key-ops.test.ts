import * as fs from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { distributeSenderKey, getOrCreateSenderKey } from "../src/sender-key-ops.js";
import { generateAgentKeys, saveAgentKeys, toBase64Url } from "../src/crypto/keys.js";
import { generateSenderKey } from "../src/crypto/sender-keys.js";
import { loadSenderKeyStates, saveSenderKeyState } from "../src/crypto/sender-keys-helpers.js";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-skops-test-"));
}

const SENDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const RECIPIENT_A = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const RECIPIENT_B = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const GROUP_ID = "d4e5f6a7-b8c9-0123-defa-234567890123";

function setupAgent(dir: string, agentId: string) {
	const keys = generateAgentKeys();
	saveAgentKeys(dir, agentId, keys);
	return keys;
}

function makeBatchKeysResponse(agentIds: string[]) {
	const keys: Record<string, { signing_public_key: object; encryption_public_key: object }> = {};
	for (const id of agentIds) {
		const k = generateAgentKeys();
		keys[id] = {
			signing_public_key: { kty: "OKP", crv: "Ed25519", x: toBase64Url(k.signing.publicKey) },
			encryption_public_key: { kty: "OKP", crv: "X25519", x: toBase64Url(k.encryption.publicKey) },
		};
	}
	return { keys };
}

describe("distributeSenderKey", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, SENDER_ID);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("distributes to all recipients", async () => {
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		const client = {
			get: vi.fn().mockResolvedValue(makeBatchKeysResponse([RECIPIENT_A, RECIPIENT_B])),
			post: vi.fn().mockResolvedValue({ id: "msg-1" }),
		};

		const result = await distributeSenderKey(
			client as never, dir, SENDER_ID, state, GROUP_ID, [RECIPIENT_A, RECIPIENT_B],
		);

		expect(result.succeeded).toEqual([RECIPIENT_A, RECIPIENT_B]);
		expect(result.failed).toEqual([]);
		expect(client.post).toHaveBeenCalledTimes(2);

		// Verify DM posts are sender_key_distribution type
		for (const call of client.post.mock.calls) {
			expect(call[0]).toBe("/messages");
			expect(call[1].type).toBe("rine.v1.sender_key_distribution");
			expect(call[1].encryption_version).toBe("hpke-v1");
		}
	});

	it("reports missing keys as failures", async () => {
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		// Only return keys for RECIPIENT_A
		const client = {
			get: vi.fn().mockResolvedValue(makeBatchKeysResponse([RECIPIENT_A])),
			post: vi.fn().mockResolvedValue({ id: "msg-1" }),
		};

		const result = await distributeSenderKey(
			client as never, dir, SENDER_ID, state, GROUP_ID, [RECIPIENT_A, RECIPIENT_B],
		);

		expect(result.succeeded).toEqual([RECIPIENT_A]);
		expect(result.failed).toEqual([RECIPIENT_B]);
		expect(client.post).toHaveBeenCalledTimes(1);
	});

	it("returns empty arrays for empty recipients", async () => {
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		const client = { get: vi.fn(), post: vi.fn() };

		const result = await distributeSenderKey(
			client as never, dir, SENDER_ID, state, GROUP_ID, [],
		);

		expect(result.succeeded).toEqual([]);
		expect(result.failed).toEqual([]);
		expect(client.get).not.toHaveBeenCalled();
	});
});

describe("getOrCreateSenderKey", () => {
	let dir: string;

	function makeClient(memberIds: string[]) {
		return {
			get: vi.fn().mockImplementation((path: string) => {
				if (path === "/groups") {
					return Promise.resolve({ items: [{ id: GROUP_ID }] });
				}
				if (path.includes("/members")) {
					return Promise.resolve({
						items: memberIds.map(id => ({ agent_id: id, role: "member" })),
					});
				}
				if (path === "/agents/keys") {
					const recipientIds = memberIds.filter(id => id !== SENDER_ID);
					return Promise.resolve(makeBatchKeysResponse(recipientIds));
				}
				return Promise.reject(new Error(`Unexpected GET: ${path}`));
			}),
			post: vi.fn().mockResolvedValue({ id: "msg-1" }),
		};
	}

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, SENDER_ID);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("generates new key on first send", async () => {
		const client = makeClient([SENDER_ID, RECIPIENT_A]);

		const { state, groupId } = await getOrCreateSenderKey(
			client as never, dir, SENDER_ID, "group@org.rine.network",
		);

		expect(groupId).toBe(GROUP_ID);
		expect(state.senderAgentId).toBe(SENDER_ID);
		expect(state.groupId).toBe(GROUP_ID);
		expect(state.messageIndex).toBe(0);

		// Key was distributed to the other member
		expect(client.post).toHaveBeenCalledTimes(1);

		// State was persisted
		const saved = loadSenderKeyStates(dir, SENDER_ID, GROUP_ID);
		expect(saved).toHaveLength(1);
		expect(saved[0]!.distributedTo).toContain(RECIPIENT_A);
	});

	it("reuses existing key when not rotated", async () => {
		const client = makeClient([SENDER_ID, RECIPIENT_A]);

		// First call creates key
		const { state: first } = await getOrCreateSenderKey(
			client as never, dir, SENDER_ID, "group@org.rine.network",
		);

		client.post.mockClear();

		// Second call reuses — no new distribution needed
		const { state: second } = await getOrCreateSenderKey(
			client as never, dir, SENDER_ID, "group@org.rine.network",
		);

		expect(second.senderKeyId).toBe(first.senderKeyId);
		expect(client.post).not.toHaveBeenCalled();
	});

	it("distributes only to new members (incremental)", async () => {
		// First call with one recipient
		const client1 = makeClient([SENDER_ID, RECIPIENT_A]);
		await getOrCreateSenderKey(client1 as never, dir, SENDER_ID, "group@org.rine.network");

		// Now RECIPIENT_B joins
		const client2 = makeClient([SENDER_ID, RECIPIENT_A, RECIPIENT_B]);
		const { state } = await getOrCreateSenderKey(
			client2 as never, dir, SENDER_ID, "group@org.rine.network",
		);

		// Only one new distribution (to B), not two
		expect(client2.post).toHaveBeenCalledTimes(1);
		expect(state.distributedTo).toContain(RECIPIENT_A);
		expect(state.distributedTo).toContain(RECIPIENT_B);
	});

	it("rotates key when member is removed", async () => {
		// Create key distributed to A and B
		const client1 = makeClient([SENDER_ID, RECIPIENT_A, RECIPIENT_B]);
		const { state: original } = await getOrCreateSenderKey(
			client1 as never, dir, SENDER_ID, "group@org.rine.network",
		);

		// B leaves the group
		const client2 = makeClient([SENDER_ID, RECIPIENT_A]);
		const { state: rotated } = await getOrCreateSenderKey(
			client2 as never, dir, SENDER_ID, "group@org.rine.network",
		);

		// Must be a new key — not the same one
		expect(rotated.senderKeyId).not.toBe(original.senderKeyId);
		expect(rotated.messageIndex).toBe(0);
	});

	it("throws when sender is not a member", async () => {
		const client = makeClient([RECIPIENT_A, RECIPIENT_B]); // SENDER_ID not in members

		await expect(
			getOrCreateSenderKey(client as never, dir, SENDER_ID, "group@org.rine.network"),
		).rejects.toThrow("You are not a member of this group");
	});

	it("throws when group not found", async () => {
		const client = {
			get: vi.fn().mockResolvedValue({ items: [] }),
			post: vi.fn(),
		};

		await expect(
			getOrCreateSenderKey(client as never, dir, SENDER_ID, "nonexistent@org.rine.network"),
		).rejects.toThrow("Group not found");
	});
});
