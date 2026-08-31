import * as fs from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	deleteSenderKey,
	distributeSenderKey,
	getOrCreateSenderKey,
} from "../src/sender-key-ops.js";
import {
	generateAgentKeys,
	pqPublicKeyToJWK,
	saveAgentKeys,
	toBase64Url,
} from "../src/crypto/keys.js";
import type { SenderKeyState } from "../src/crypto/sender-keys.js";
import { generateSenderKey } from "../src/crypto/sender-keys.js";
import {
	loadSenderKeyStates,
	markSenderKeysRetired,
	saveSenderKeyState,
	senderKeysRetired,
} from "../src/crypto/sender-keys-helpers.js";
import { ingestSenderKeyDistribution } from "../src/crypto/index.js";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-skops-test-"));
}

/** Every regular file under `root`, recursively. */
function walkFiles(root: string): string[] {
	return fs.readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
		const path = join(root, entry.name);
		return entry.isDirectory() ? walkFiles(path) : [path];
	});
}

const SENDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const RECIPIENT_A = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const RECIPIENT_B = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const GROUP_ID = "d4e5f6a7-b8c9-0123-defa-234567890123";

/**
 * The handle the roster carries for each id — `GroupMemberRead.agent_handle`,
 * the field the deployed server actually sends.
 *
 * `RECIPIENT_B` is spelled in another org on purpose: it is a member of the
 * group and NOT an agent of the caller, so a refusal that named it would be
 * telling the caller to act as somebody else's agent.
 */
const HANDLES: Record<string, string> = {
	[SENDER_ID]: "sender@acme.rine.network",
	[RECIPIENT_A]: "sales@acme.rine.network",
	[RECIPIENT_B]: "ops@other.rine.network",
};

/**
 * The refusal that replaced *"You are not a member of this group"*,
 * for a caller whose sibling `RECIPIENT_A` holds the seat it does not.
 *
 * A literal, never a call to the composer that produces it: a pin built by the
 * code under test passes whatever that code says. Two tests reach this exact
 * sentence — the seat check itself and the retirement it must not lift — and
 * they run the same fixture, so they assert the same bytes.
 */
const SIBLING_REFUSAL =
	`Refusing to send to group@org.rine.network: agent ${SENDER_ID} holds no` +
	" seat in that group. Agents of your org seated there:" +
	" sales@acme.rine.network. Send this message again as one of them: the" +
	" acting agent is chosen with --agent on the rine CLI, agent on every" +
	" other surface. Nothing was sent, and no sender key was distributed.";

function setupAgent(dir: string, agentId: string) {
	const keys = generateAgentKeys();
	saveAgentKeys(dir, agentId, keys);
	return keys;
}

function makeBatchKeysResponse(agentIds: string[]) {
	const keys: Record<
		string,
		{ signing_public_key: object; encryption_public_key: object }
	> = {};
	for (const id of agentIds) {
		const k = generateAgentKeys();
		keys[id] = {
			signing_public_key: {
				kty: "OKP",
				crv: "Ed25519",
				x: toBase64Url(k.signing.publicKey),
			},
			encryption_public_key: {
				kty: "OKP",
				crv: "X25519",
				x: toBase64Url(k.encryption.publicKey),
			},
		};
	}
	return { keys };
}

/**
 * Batch fixture where each recipient also advertises a REAL ML-KEM
 * pq_encryption_public_key, so the hybrid encrypt path genuinely runs.
 */
function makeHybridBatchKeysResponse(agentIds: string[]) {
	const keys: Record<
		string,
		{
			signing_public_key: object;
			encryption_public_key: object;
			pq_encryption_public_key: object;
		}
	> = {};
	for (const id of agentIds) {
		const k = generateAgentKeys();
		if (!k.pqEncryption) throw new Error("expected generated PQ key");
		keys[id] = {
			signing_public_key: {
				kty: "OKP",
				crv: "Ed25519",
				x: toBase64Url(k.signing.publicKey),
			},
			encryption_public_key: {
				kty: "OKP",
				crv: "X25519",
				x: toBase64Url(k.encryption.publicKey),
			},
			pq_encryption_public_key: pqPublicKeyToJWK(k.pqEncryption.publicKey),
		};
	}
	return { keys };
}

/**
 * A client whose `/agents/keys` answers only the ids it was actually asked for,
 * and records every id list it saw — the server refuses more than 200 per call,
 * so the chunking is only observable from the requests themselves.
 */
function makeKeyFetchClient(
	recipientIds: string[],
	opts?: { failChunk?: number },
) {
	const chunks: string[][] = [];
	return {
		chunks,
		get: vi
			.fn()
			.mockImplementation((path: string, params?: { ids?: string }) => {
				if (path !== "/agents/keys") {
					return Promise.reject(new Error(`Unexpected GET: ${path}`));
				}
				const ids = (params?.ids ?? "").split(",").filter(Boolean);
				chunks.push(ids);
				if (opts?.failChunk === chunks.length - 1) {
					return Promise.reject(new Error("Maximum 200 IDs per request"));
				}
				return Promise.resolve(
					makeBatchKeysResponse(ids.filter((id) => recipientIds.includes(id))),
				);
			}),
		post: vi.fn().mockResolvedValue({ id: "msg-1" }),
	};
}

/** `count` distinct, well-formed agent UUIDs. */
function manyRecipients(count: number): string[] {
	return Array.from({ length: count }, (_, i) => {
		const tail = i.toString(16).padStart(12, "0");
		return `b2c3d4e5-f6a7-8901-bcde-${tail}`;
	});
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
			get: vi
				.fn()
				.mockResolvedValue(makeBatchKeysResponse([RECIPIENT_A, RECIPIENT_B])),
			post: vi.fn().mockResolvedValue({ id: "msg-1" }),
		};

		const result = await distributeSenderKey(
			client as never,
			dir,
			SENDER_ID,
			state,
			GROUP_ID,
			[RECIPIENT_A, RECIPIENT_B],
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

	it("seals distribution as hpke-hybrid-v1 when a recipient advertises a PQ key", async () => {
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		const client = {
			get: vi
				.fn()
				.mockResolvedValue(makeHybridBatchKeysResponse([RECIPIENT_A])),
			post: vi.fn().mockResolvedValue({ id: "msg-1" }),
		};

		const result = await distributeSenderKey(
			client as never,
			dir,
			SENDER_ID,
			state,
			GROUP_ID,
			[RECIPIENT_A],
		);

		expect(result.succeeded).toEqual([RECIPIENT_A]);
		expect(result.failed).toEqual([]);
		expect(client.post).toHaveBeenCalledTimes(1);

		const call = client.post.mock.calls[0]!;
		expect(call[0]).toBe("/messages");
		expect(call[1].type).toBe("rine.v1.sender_key_distribution");
		expect(call[1].encryption_version).toBe("hpke-hybrid-v1");
	});

	it("reports missing keys as failures", async () => {
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		// Only return keys for RECIPIENT_A
		const client = {
			get: vi.fn().mockResolvedValue(makeBatchKeysResponse([RECIPIENT_A])),
			post: vi.fn().mockResolvedValue({ id: "msg-1" }),
		};

		const result = await distributeSenderKey(
			client as never,
			dir,
			SENDER_ID,
			state,
			GROUP_ID,
			[RECIPIENT_A, RECIPIENT_B],
		);

		expect(result.succeeded).toEqual([RECIPIENT_A]);
		expect(result.failed).toEqual([RECIPIENT_B]);
		expect(client.post).toHaveBeenCalledTimes(1);
	});

	it("test_distribute_when_recipients_exceed_the_batch_cap_chunks_the_key_fetch", async () => {
		// The server refuses more than 200 ids in one GET /agents/keys, and that
		// refusal used to reach the caller before a single key was distributed.
		const recipients = manyRecipients(201);
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		const client = makeKeyFetchClient(recipients);

		const result = await distributeSenderKey(
			client as never,
			dir,
			SENDER_ID,
			state,
			GROUP_ID,
			recipients,
		);

		expect(client.chunks).toHaveLength(2);
		for (const chunk of client.chunks)
			expect(chunk.length).toBeLessThanOrEqual(200);
		expect(client.chunks.flat()).toEqual(recipients);
		expect(result.succeeded).toEqual(recipients);
		expect(result.failed).toEqual([]);
		expect(client.post).toHaveBeenCalledTimes(201);
	});

	it("test_distribute_when_one_key_chunk_fails_still_distributes_the_others", async () => {
		const recipients = manyRecipients(250);
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		const client = makeKeyFetchClient(recipients, { failChunk: 0 });

		const result = await distributeSenderKey(
			client as never,
			dir,
			SENDER_ID,
			state,
			GROUP_ID,
			recipients,
		);

		// A failed chunk costs its own recipients their copy of the key and
		// nothing else — the remaining 50 are still reached.
		expect(result.failed).toEqual(recipients.slice(0, 200));
		expect(result.succeeded).toEqual(recipients.slice(200));
		expect(client.post).toHaveBeenCalledTimes(50);
	});

	it("test_distribute_when_every_key_chunk_fails_refuses_rather_than_reporting_all_failed", async () => {
		// Reporting "everyone failed" is worse than raising: no caller reads the
		// result, so the message would be sealed and sent under a key nobody
		// holds, and the chain key ratchets past it — undecryptable for good.
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		const client = {
			get: vi.fn().mockRejectedValue(new Error("service unavailable")),
			post: vi.fn().mockResolvedValue({ id: "msg-1" }),
		};

		await expect(
			distributeSenderKey(client as never, dir, SENDER_ID, state, GROUP_ID, [
				RECIPIENT_A,
				RECIPIENT_B,
			]),
		).rejects.toThrow("service unavailable");
		expect(client.post).not.toHaveBeenCalled();
	});

	it("test_distribute_when_many_recipients_keeps_posts_parallel_but_bounded", async () => {
		const recipients = manyRecipients(50);
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		const client = makeKeyFetchClient(recipients);
		let inFlight = 0;
		let maxInFlight = 0;
		client.post.mockImplementation(async () => {
			inFlight++;
			maxInFlight = Math.max(maxInFlight, inFlight);
			await new Promise((resolve) => setTimeout(resolve, 0));
			inFlight--;
			return { id: "msg-1" };
		});

		const result = await distributeSenderKey(
			client as never,
			dir,
			SENDER_ID,
			state,
			GROUP_ID,
			recipients,
		);

		expect(result.succeeded).toEqual(recipients);
		// Parallel — a send no longer pays one round trip per member in series.
		expect(maxInFlight).toBeGreaterThan(1);
		// Bounded — never the whole group at once.
		expect(maxInFlight).toBeLessThan(recipients.length);
	});

	it("returns empty arrays for empty recipients", async () => {
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		const client = { get: vi.fn(), post: vi.fn() };

		const result = await distributeSenderKey(
			client as never,
			dir,
			SENDER_ID,
			state,
			GROUP_ID,
			[],
		);

		expect(result.succeeded).toEqual([]);
		expect(result.failed).toEqual([]);
		expect(client.get).not.toHaveBeenCalled();
	});
});

describe("getOrCreateSenderKey", () => {
	let dir: string;

	/**
	 * The server as this path sees it: the group, its roster, and the caller's
	 * own agents.
	 *
	 * `orgAgentIds` is `GET /agents` — read on the refusal path alone, to work
	 * out which of the CALLER's agents hold a seat. The roster rows carry
	 * `agent_handle` because that is the field the refusal spells them by, and
	 * the two lists are deliberately different: a member of another org is on the
	 * roster and not in this list.
	 */
	function makeClient(memberIds: string[], orgAgentIds: string[] = [SENDER_ID]) {
		return {
			get: vi.fn().mockImplementation((path: string) => {
				if (path === "/groups") {
					return Promise.resolve({ items: [{ id: GROUP_ID }] });
				}
				if (path.includes("/members")) {
					return Promise.resolve({
						items: memberIds.map((id) => ({
							agent_id: id,
							role: "member",
							agent_handle: HANDLES[id],
						})),
					});
				}
				if (path === "/agents/keys") {
					const recipientIds = memberIds.filter((id) => id !== SENDER_ID);
					return Promise.resolve(makeBatchKeysResponse(recipientIds));
				}
				if (path === "/agents") {
					return Promise.resolve({
						items: orgAgentIds.map((id) => ({
							id,
							name: HANDLES[id]?.split("@")[0],
							handle: HANDLES[id],
						})),
					});
				}
				return Promise.reject(new Error(`Unexpected GET: ${path}`));
			}),
			post: vi.fn().mockResolvedValue({ id: "msg-1" }),
		};
	}

	/**
	 * The message a refused send threw, whole.
	 *
	 * `rejects.toThrow(string)` passes on a SUBSTRING, and a substring is not
	 * what these pins assert: this refusal's entire text was replaced, so
	 * the pin is the whole sentence or it pins nothing.
	 */
	async function refusalMessage(call: Promise<unknown>): Promise<string> {
		const err = await call.then(
			() => null,
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(Error);
		return (err as Error).message;
	}

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, SENDER_ID);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("generates new key on first send", async () => {
		const client = makeClient([SENDER_ID, RECIPIENT_A]);

		const { state, groupId } = await getOrCreateSenderKey(
			client as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
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
			client as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		client.post.mockClear();

		// Second call reuses — no new distribution needed
		const { state: second } = await getOrCreateSenderKey(
			client as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		expect(second.senderKeyId).toBe(first.senderKeyId);
		expect(client.post).not.toHaveBeenCalled();
	});

	it("test_getorcreatesenderkey_when_the_stored_own_state_differs_only_in_id_case_then_it_is_reused", async () => {
		// Own-vs-peer decides two invariants at once: misread the stored id and the
		// agent rekeys on every send AND stacks its own past states as "peers"
		// forever. Every other id comparison in the function is
		// case-insensitive, and `validatePathId` accepts a UUID in either case.
		const own = generateSenderKey(GROUP_ID, SENDER_ID.toUpperCase());
		own.distributedTo = [RECIPIENT_A];
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [own]);
		const client = makeClient([SENDER_ID, RECIPIENT_A]);

		const { state } = await getOrCreateSenderKey(
			client as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		expect(state.senderKeyId).toBe(own.senderKeyId);
		expect(client.post).not.toHaveBeenCalled();
		expect(loadSenderKeyStates(dir, SENDER_ID, GROUP_ID)).toHaveLength(1);
	});

	it("distributes only to new members (incremental)", async () => {
		// First call with one recipient
		const client1 = makeClient([SENDER_ID, RECIPIENT_A]);
		await getOrCreateSenderKey(
			client1 as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		// Now RECIPIENT_B joins
		const client2 = makeClient([SENDER_ID, RECIPIENT_A, RECIPIENT_B]);
		const { state } = await getOrCreateSenderKey(
			client2 as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
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
			client1 as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		// B leaves the group
		const client2 = makeClient([SENDER_ID, RECIPIENT_A]);
		const { state: rotated } = await getOrCreateSenderKey(
			client2 as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		// Must be a new key — not the same one
		expect(rotated.senderKeyId).not.toBe(original.senderKeyId);
		expect(rotated.messageIndex).toBe(0);
	});

	it("test_getorcreate_after_one_departure_rekeys_once_over_ten_sends", async () => {
		const client1 = makeClient([SENDER_ID, RECIPIENT_A, RECIPIENT_B]);
		const { state: original } = await getOrCreateSenderKey(
			client1 as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		// B leaves, then this agent sends ten more times. One departure is one
		// rotation — it used to be one rotation per send, each with a full
		// redistribution to every remaining member.
		const keyIds = new Set<string>();
		for (let i = 0; i < 10; i++) {
			const client = makeClient([SENDER_ID, RECIPIENT_A]);
			const { state } = await getOrCreateSenderKey(
				client as never,
				dir,
				SENDER_ID,
				"group@org.rine.network",
			);
			keyIds.add(state.senderKeyId);
		}

		expect(keyIds.size).toBe(1);
		expect(keyIds.has(original.senderKeyId)).toBe(false);
	});

	it("test_getorcreate_after_ten_sends_keeps_at_most_two_states_for_this_agent", async () => {
		const client1 = makeClient([SENDER_ID, RECIPIENT_A, RECIPIENT_B]);
		await getOrCreateSenderKey(
			client1 as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		for (let i = 0; i < 10; i++) {
			const client = makeClient([SENDER_ID, RECIPIENT_A]);
			await getOrCreateSenderKey(
				client as never,
				dir,
				SENDER_ID,
				"group@org.rine.network",
			);
		}

		// Every send loads and scans this file, so a state per rotation is a leak
		// that grows for the life of the group. Two is the bound: the current key
		// and the one it superseded, whose cached keys still open this agent's own
		// recent messages.
		const own = loadSenderKeyStates(dir, SENDER_ID, GROUP_ID).filter(
			(state) => state.senderAgentId === SENDER_ID,
		);
		expect(own).toHaveLength(2);
	});

	it("test_getorcreate_when_rotating_keeps_the_superseded_key_for_self_read", async () => {
		const client1 = makeClient([SENDER_ID, RECIPIENT_A, RECIPIENT_B]);
		const { state: original } = await getOrCreateSenderKey(
			client1 as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		// A send caches the message key it used on its own state, and that cache is
		// the only way the sender can re-read its own group messages.
		const stored = loadSenderKeyStates(dir, SENDER_ID, GROUP_ID);
		const mine = stored.find((s) => s.senderKeyId === original.senderKeyId);
		if (!mine) throw new Error("expected the agent's own state to be stored");
		mine.skippedKeys = { 0: "c2VsZi1yZWFkLWtleQ" };
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, stored);

		const client2 = makeClient([SENDER_ID, RECIPIENT_A]);
		const { state: rotated } = await getOrCreateSenderKey(
			client2 as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		expect(rotated.senderKeyId).not.toBe(original.senderKeyId);
		const superseded = loadSenderKeyStates(dir, SENDER_ID, GROUP_ID).find(
			(state) => state.senderKeyId === original.senderKeyId,
		);
		expect(superseded?.skippedKeys).toEqual({ 0: "c2VsZi1yZWFkLWtleQ" });
	});

	it("test_getorcreate_when_rotating_keeps_the_keys_of_members_who_stayed", async () => {
		const client1 = makeClient([SENDER_ID, RECIPIENT_A, RECIPIENT_B]);
		await getOrCreateSenderKey(
			client1 as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		// A key ingested from a peer opens traffic that peer already sent; a
		// rotation of OUR key must not take it away.
		const peerState = generateSenderKey(GROUP_ID, RECIPIENT_A);
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [
			...loadSenderKeyStates(dir, SENDER_ID, GROUP_ID),
			peerState,
		]);

		const client2 = makeClient([SENDER_ID, RECIPIENT_A]);
		await getOrCreateSenderKey(
			client2 as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		const states = loadSenderKeyStates(dir, SENDER_ID, GROUP_ID);
		expect(
			states
				.filter((state) => state.senderAgentId === RECIPIENT_A)
				.map((state) => state.senderKeyId),
		).toEqual([peerState.senderKeyId]);
		expect(
			states.filter((state) => state.senderAgentId === SENDER_ID),
		).toHaveLength(2);
	});

	it("test_getorcreate_when_an_older_client_stacked_states_uses_the_newest", async () => {
		// What an older client left on disk: a superseded own state whose
		// distributedTo still names a departed member, then the current one.
		const superseded = generateSenderKey(GROUP_ID, SENDER_ID);
		superseded.distributedTo = [RECIPIENT_A, RECIPIENT_B];
		const current = generateSenderKey(GROUP_ID, SENDER_ID);
		current.distributedTo = [RECIPIENT_A];
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [superseded, current]);

		const client = makeClient([SENDER_ID, RECIPIENT_A]);
		const { state } = await getOrCreateSenderKey(
			client as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		expect(state.senderKeyId).toBe(current.senderKeyId);
		expect(client.post).not.toHaveBeenCalled();
	});

	it("test_getorcreate_when_the_sender_holds_no_seat_then_it_names_the_group_the_seated_sibling_and_the_move", async () => {
		// The old refusal was eight words — "You are not a member of
		// this group" — naming no group, no sibling to act as and no remedy. This
		// pins the whole replacement, including which of the roster's rows it may
		// name: RECIPIENT_B is seated and belongs to another org, so the caller
		// cannot act as it and the sentence must not offer it.
		const client = makeClient(
			[RECIPIENT_A, RECIPIENT_B], // SENDER_ID not in members
			[SENDER_ID, RECIPIENT_A],
		);

		expect(
			await refusalMessage(
				getOrCreateSenderKey(
					client as never,
					dir,
					SENDER_ID,
					"group@org.rine.network",
				),
			),
		).toBe(SIBLING_REFUSAL);
		// The last clause is a property of WHERE the refusal is raised, not a
		// reassurance: one POST here is one distribution DM in another org's inbox.
		expect(client.post).not.toHaveBeenCalled();
	});

	it("test_getorcreate_when_no_agent_of_the_org_is_seated_then_it_says_so_and_names_no_one", async () => {
		// The arm with no remedy the caller can perform alone. It must not fall
		// through to the sibling arm and name a member of another org.
		const client = makeClient([RECIPIENT_B], [SENDER_ID, RECIPIENT_A]);

		expect(
			await refusalMessage(
				getOrCreateSenderKey(
					client as never,
					dir,
					SENDER_ID,
					"group@org.rine.network",
				),
			),
		).toBe(
			`Refusing to send to group@org.rine.network: agent ${SENDER_ID} holds` +
				" no seat in that group. No agent of your org holds a seat there" +
				" either, so there is nobody to send as: a member must invite one of" +
				" your agents before this org can post to the group. Nothing was sent," +
				" and no sender key was distributed.",
		);
	});

	it("test_getorcreate_when_the_org_agent_list_cannot_be_read_then_the_refusal_stands_and_claims_nothing", async () => {
		// "No agent of yours is seated" and "this client could not find out" are
		// different facts. The decoration failing may not turn the refusal into
		// the agent list's own error, and it may not claim the org has no seat.
		const client = {
			get: vi.fn().mockImplementation((path: string) => {
				if (path === "/groups") {
					return Promise.resolve({ items: [{ id: GROUP_ID }] });
				}
				if (path.includes("/members")) {
					return Promise.resolve({
						items: [
							{
								agent_id: RECIPIENT_A,
								role: "member",
								agent_handle: HANDLES[RECIPIENT_A],
							},
						],
					});
				}
				return Promise.reject(new Error("agent list unavailable"));
			}),
			post: vi.fn(),
		};

		expect(
			await refusalMessage(
				getOrCreateSenderKey(
					client as never,
					dir,
					SENDER_ID,
					"group@org.rine.network",
				),
			),
		).toBe(
			`Refusing to send to group@org.rine.network: agent ${SENDER_ID} holds` +
				" no seat in that group. rine could not read your org's agent list, so" +
				" it cannot say which of your agents is seated there: read the group's" +
				" members and send again as one of yours that is listed. Nothing was" +
				" sent, and no sender key was distributed.",
		);
	});

	it("test_getorcreate_when_the_agent_list_answers_200_without_items_then_the_refusal_still_stands", async () => {
		// A 200 carrying no `items` throws NOTHING — `fetchAgents` returns
		// `data.items` unvalidated — so it walks straight past the catch that the
		// test above exercises. Before the guard, reading `.filter` on `undefined`
		// raised a TypeError OUT of the refusal path and the caller was told
		// "Cannot read properties of undefined" instead of why its send was
		// refused. Same arm as an unreachable list: this client could not find out.
		const client = {
			get: vi.fn().mockImplementation((path: string) => {
				if (path === "/groups") {
					return Promise.resolve({ items: [{ id: GROUP_ID }] });
				}
				if (path.includes("/members")) {
					return Promise.resolve({
						items: [
							{
								agent_id: RECIPIENT_A,
								role: "member",
								agent_handle: HANDLES[RECIPIENT_A],
							},
						],
					});
				}
				return Promise.resolve({ detail: "no items here" });
			}),
			post: vi.fn(),
		};

		expect(
			await refusalMessage(
				getOrCreateSenderKey(
					client as never,
					dir,
					SENDER_ID,
					"group@org.rine.network",
				),
			),
		).toBe(
			`Refusing to send to group@org.rine.network: agent ${SENDER_ID} holds` +
				" no seat in that group. rine could not read your org's agent list, so" +
				" it cannot say which of your agents is seated there: read the group's" +
				" members and send again as one of yours that is listed. Nothing was" +
				" sent, and no sender key was distributed.",
		);
	});

	it("test_getorcreate_when_the_agent_is_a_member_again_then_the_retirement_is_lifted", async () => {
		// A re-admitted member has to be able to take its new peers' keys, or its
		// client is silently unable to read the group for good.
		markSenderKeysRetired(dir, SENDER_ID, GROUP_ID);
		const client = makeClient([SENDER_ID, RECIPIENT_A]);

		await getOrCreateSenderKey(
			client as never,
			dir,
			SENDER_ID,
			"group@org.rine.network",
		);

		expect(senderKeysRetired(dir, SENDER_ID, GROUP_ID)).toBe(false);
	});

	it("test_getorcreate_when_the_agent_is_no_longer_a_member_then_the_retirement_stands", async () => {
		// The membership check is what makes the retirement permanent for the agent
		// it exists for: a departed agent attempting a send must not be able to lift
		// its own marker on the way to being refused.
		markSenderKeysRetired(dir, SENDER_ID, GROUP_ID);
		const client = makeClient(
			[RECIPIENT_A, RECIPIENT_B],
			[SENDER_ID, RECIPIENT_A],
		);

		expect(
			await refusalMessage(
				getOrCreateSenderKey(
					client as never,
					dir,
					SENDER_ID,
					"group@org.rine.network",
				),
			),
		).toBe(SIBLING_REFUSAL);

		expect(senderKeysRetired(dir, SENDER_ID, GROUP_ID)).toBe(true);
	});

	it("throws when group not found", async () => {
		const client = {
			get: vi.fn().mockResolvedValue({ items: [] }),
			post: vi.fn(),
		};

		await expect(
			getOrCreateSenderKey(
				client as never,
				dir,
				SENDER_ID,
				"nonexistent@org.rine.network",
			),
		).rejects.toThrow("Group not found");
	});
});

describe("deleteSenderKey", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, SENDER_ID);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("test_deletesenderkey_when_the_group_holds_material_removes_it", () => {
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [
			generateSenderKey(GROUP_ID, SENDER_ID),
			generateSenderKey(GROUP_ID, RECIPIENT_A),
		]);
		expect(loadSenderKeyStates(dir, SENDER_ID, GROUP_ID)).toHaveLength(2);

		deleteSenderKey(dir, SENDER_ID, GROUP_ID);

		expect(loadSenderKeyStates(dir, SENDER_ID, GROUP_ID)).toEqual([]);
		expect(
			fs.existsSync(
				join(dir, "keys", SENDER_ID, "sender_keys", `${GROUP_ID}.json`),
			),
		).toBe(false);
	});

	it("test_deletesenderkey_when_another_groups_material_exists_leaves_it", () => {
		const otherGroup = "e5f6a7b8-c9d0-1234-efab-345678901234";
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [
			generateSenderKey(GROUP_ID, SENDER_ID),
		]);
		saveSenderKeyState(dir, SENDER_ID, otherGroup, [
			generateSenderKey(otherGroup, SENDER_ID),
		]);

		deleteSenderKey(dir, SENDER_ID, GROUP_ID);

		expect(loadSenderKeyStates(dir, SENDER_ID, otherGroup)).toHaveLength(1);
	});

	it("test_deletesenderkey_when_the_group_holds_nothing_is_not_an_error", () => {
		expect(() => deleteSenderKey(dir, SENDER_ID, GROUP_ID)).not.toThrow();
	});

	it("test_deletesenderkey_when_the_group_id_is_a_path_refuses", () => {
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [
			generateSenderKey(GROUP_ID, SENDER_ID),
		]);

		expect(() => deleteSenderKey(dir, SENDER_ID, "../../keys")).toThrow(
			/Invalid group ID/,
		);
		expect(loadSenderKeyStates(dir, SENDER_ID, GROUP_ID)).toHaveLength(1);
	});

	it("test_deletesenderkey_when_material_is_wiped_then_no_cached_message_key_is_left_on_disk", () => {
		const cachedMessageKey = toBase64Url(new Uint8Array(32).fill(7));
		const own = generateSenderKey(GROUP_ID, SENDER_ID);
		own.skippedKeys = { 0: cachedMessageKey };
		const peer = generateSenderKey(GROUP_ID, RECIPIENT_A);
		const peerChainKey = toBase64Url(peer.chainKey);
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [own, peer]);

		deleteSenderKey(dir, SENDER_ID, GROUP_ID);

		// The whole config dir, not just the state file: the acceptance criterion
		// is that nothing anywhere would open this group's traffic afterwards.
		const onDisk = walkFiles(dir).map((p) => fs.readFileSync(p, "utf-8"));
		expect(onDisk.some((c) => c.includes(cachedMessageKey))).toBe(false);
		expect(onDisk.some((c) => c.includes(peerChainKey))).toBe(false);
	});

	it("test_deletesenderkey_when_the_group_id_is_upper_cased_then_the_material_is_still_removed", () => {
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [
			generateSenderKey(GROUP_ID, SENDER_ID),
		]);

		deleteSenderKey(dir, SENDER_ID, GROUP_ID.toUpperCase());

		expect(loadSenderKeyStates(dir, SENDER_ID, GROUP_ID)).toEqual([]);
	});

	it("test_deletesenderkey_when_the_material_was_written_upper_cased_then_it_is_still_removed", () => {
		const upper = GROUP_ID.toUpperCase();
		saveSenderKeyState(dir, SENDER_ID, upper, [
			generateSenderKey(upper, SENDER_ID),
		]);

		deleteSenderKey(dir, SENDER_ID, upper);

		expect(loadSenderKeyStates(dir, SENDER_ID, upper)).toEqual([]);
	});

	/** The distribution DM that carried `peer`'s key, as the inbox still holds it. */
	function distributionOf(peer: SenderKeyState) {
		return {
			plaintext: JSON.stringify({
				group_id: peer.groupId,
				sender_key_id: peer.senderKeyId,
				chain_key: toBase64Url(peer.chainKey),
				message_index: peer.messageIndex,
				sender_agent_id: peer.senderAgentId,
			}),
			senderKid: `rine:${peer.senderAgentId}`,
			verified: true,
			verificationStatus: "verified" as const,
		};
	}

	it("test_deletesenderkey_when_a_peer_distribution_is_reingested_then_it_is_refused", () => {
		// The wipe used to be point-in-time and this test pinned that as a FINDING:
		// the distribution DM that carried this peer key is still in the agent's
		// inbox — leaving a group takes nothing out of an inbox — so
		// `fetchAndIngestPendingSKDistributions` put it straight back on the next
		// group read that missed. That is closed with a retirement marker
		// `crypto/ingest.ts` reads, and this expectation is the flip.
		const peer = generateSenderKey(GROUP_ID, RECIPIENT_A);
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [peer]);

		deleteSenderKey(dir, SENDER_ID, GROUP_ID);
		expect(loadSenderKeyStates(dir, SENDER_ID, GROUP_ID)).toEqual([]);

		const reingested = ingestSenderKeyDistribution(
			dir,
			SENDER_ID,
			"rine.v1.sender_key_distribution",
			distributionOf(peer),
		);

		expect(reingested).toBe(false);
		expect(loadSenderKeyStates(dir, SENDER_ID, GROUP_ID)).toEqual([]);
	});

	it("test_deletesenderkey_when_the_group_held_nothing_then_a_pending_distribution_is_still_refused", () => {
		// The marker is written whether or not there was anything to delete. A
		// distribution DM this agent never opened is material the wipe never saw,
		// and it is in the same inbox — recording only what was on disk would let
		// exactly those through.
		const peer = generateSenderKey(GROUP_ID, RECIPIENT_A);

		deleteSenderKey(dir, SENDER_ID, GROUP_ID);

		expect(
			ingestSenderKeyDistribution(
				dir,
				SENDER_ID,
				"rine.v1.sender_key_distribution",
				distributionOf(peer),
			),
		).toBe(false);
	});

	it("test_deletesenderkey_when_the_process_restarts_then_the_refusal_survives", () => {
		// The marker is a file, not memory: nothing in this module holds the
		// retirement in process state, so a fresh client on the same config dir
		// refuses exactly as this one does.
		const peer = generateSenderKey(GROUP_ID, RECIPIENT_A);
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [peer]);
		deleteSenderKey(dir, SENDER_ID, GROUP_ID);

		expect(senderKeysRetired(dir, SENDER_ID, GROUP_ID)).toBe(true);
		expect(
			fs.existsSync(
				join(dir, "keys", SENDER_ID, "sender_keys", `${GROUP_ID}.retired.json`),
			),
		).toBe(true);
	});

	it("test_deletesenderkey_when_the_group_id_is_upper_cased_then_the_refusal_still_matches", () => {
		const peer = generateSenderKey(GROUP_ID, RECIPIENT_A);
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [peer]);

		deleteSenderKey(dir, SENDER_ID, GROUP_ID.toUpperCase());

		// The distribution payload spells the group as the server does.
		expect(
			ingestSenderKeyDistribution(
				dir,
				SENDER_ID,
				"rine.v1.sender_key_distribution",
				distributionOf(peer),
			),
		).toBe(false);
	});

	it("test_deletesenderkey_when_another_group_is_retired_then_this_one_still_ingests", () => {
		const otherGroup = "e5f6a7b8-c9d0-1234-efab-345678901234";
		const peer = generateSenderKey(GROUP_ID, RECIPIENT_A);

		deleteSenderKey(dir, SENDER_ID, otherGroup);

		expect(
			ingestSenderKeyDistribution(
				dir,
				SENDER_ID,
				"rine.v1.sender_key_distribution",
				distributionOf(peer),
			),
		).toBe(true);
	});
});
