/**
 * The negative cache: one empty scan answers every
 * post that needs the same missing key, until a distribution from that sender
 * arrives or 15 minutes pass. `group sync` is never cached.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ingestSenderKeyDistribution } from "../src/crypto/ingest.js";
import { decryptMessage, encryptMessage } from "../src/crypto/message.js";
import { encryptGroupMessage } from "../src/crypto/sender-key-seal.js";
import { generateSenderKey } from "../src/crypto/sender-keys.js";
import { saveSenderKeyState } from "../src/crypto/sender-keys-helpers.js";
import {
	NEGATIVE_MAX_ENTRIES,
	NEGATIVE_TTL_MS,
	ROW_FAILURE_LIMIT,
	clearSender,
	isCached,
	recordMissing,
	settleRowFailures,
} from "../src/sender-key-negative-cache.js";
import {
	decryptGroupMessageWithRecovery,
	fetchAndIngestPendingSKDistributions,
	scanPendingSKDistributions,
} from "../src/sender-key-recovery.js";
import { SenderKeyUnavailableError } from "../src/sender-key-words.js";
import { World } from "./crypto/world.js";

const READER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const PEER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const DM_ID = "d4e5f6a7-b8c9-0123-defa-234567890123";

const missing = (keyId: string, sender = PEER_ID) => ({
	agentId: READER_ID,
	groupId: GROUP_ID,
	senderAgentId: sender,
	keyId,
});

describe("the negative cache", () => {
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"] });
		clearSender(READER_ID, PEER_ID);
	});
	afterEach(() => vi.useRealTimers());

	it("test_cache_when_an_entry_is_recorded_then_it_lives_fifteen_minutes", () => {
		recordMissing(missing("k1"));
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, "k1")).toBe(true);

		vi.advanceTimersByTime(NEGATIVE_TTL_MS - 1);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, "k1")).toBe(true);

		vi.advanceTimersByTime(1);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, "k1")).toBe(false);
	});

	it("test_cache_when_the_key_differs_in_any_part_then_it_is_a_miss", () => {
		recordMissing(missing("k1"));
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, "k2")).toBe(false);
		expect(isCached(READER_ID, GROUP_ID, READER_ID, "k1")).toBe(false);
		expect(isCached(PEER_ID, GROUP_ID, PEER_ID, "k1")).toBe(false);
		expect(isCached(READER_ID, PEER_ID, PEER_ID, "k1")).toBe(false);
	});

	it("test_cache_when_ids_differ_only_in_case_then_they_are_the_same_entry", () => {
		recordMissing(missing("k1"));
		expect(isCached(READER_ID.toUpperCase(), GROUP_ID, PEER_ID, "k1")).toBe(true);
	});

	it("test_cache_when_the_sender_is_cleared_then_only_that_sender_goes", () => {
		const other = "e5f6a7b8-c9d0-1234-efab-345678901234";
		recordMissing(missing("k1"));
		recordMissing(missing("k2", other));
		clearSender(READER_ID, PEER_ID);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, "k1")).toBe(false);
		expect(isCached(READER_ID, GROUP_ID, other, "k2")).toBe(true);
		clearSender(READER_ID, other);
	});

	it("test_cache_when_it_is_full_then_the_oldest_entry_is_dropped", () => {
		for (let i = 0; i < NEGATIVE_MAX_ENTRIES; i++) recordMissing(missing(`k${i}`));
		recordMissing(missing("overflow"));
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, "k0")).toBe(false);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, "k1")).toBe(true);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, "overflow")).toBe(true);
	});
});

describe("recovery through the negative cache", () => {
	let dir: string;
	let ciphertext: string;
	let peerKeyId: string;
	let distribution: Record<string, unknown>;
	let inboxLists: number;
	let client: {
		get: ReturnType<typeof vi.fn>;
		post: ReturnType<typeof vi.fn>;
		markDelivered: ReturnType<typeof vi.fn>;
	};
	let inboxItems: Array<{ id: string }>;

	beforeEach(async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		clearSender(READER_ID, PEER_ID);
		dir = fs.mkdtempSync(join(tmpdir(), "rine-sknegcache-test-"));
		const world = new World();
		const reader = world.addAgent({ id: READER_ID });
		const peer = world.addAgent({ id: PEER_ID });
		world.save(dir, reader);
		world.save(dir, peer);

		const peerState = generateSenderKey(GROUP_ID, PEER_ID);
		peerKeyId = peerState.senderKeyId;
		// The distribution is sealed before the post advances the peer's chain, so
		// the reader's copy still opens the first message.
		const sealed = await encryptMessage(
			dir,
			PEER_ID,
			READER_ID,
			{
				encryption: reader.derived.x25519.publicKey,
				pqEncryption: reader.derived.mlKem768.publicKey,
			},
			{
				group_id: GROUP_ID,
				sender_key_id: peerState.senderKeyId,
				chain_key: Buffer.from(peerState.chainKey).toString("base64url"),
				message_index: peerState.messageIndex,
				sender_agent_id: PEER_ID,
			},
		);
		distribution = {
			id: DM_ID,
			type: "rine.v1.sender_key_distribution",
			from_agent_id: PEER_ID,
			encrypted_payload: sealed.encrypted_payload,
		};
		saveSenderKeyState(dir, PEER_ID, GROUP_ID, [peerState]);
		const { result } = await encryptGroupMessage(dir, PEER_ID, GROUP_ID, peerState, {
			announcement: "hello",
		});
		ciphertext = result.encrypted_payload;

		inboxLists = 0;
		inboxItems = [];
		const base = world.client();
		client = {
			markDelivered: vi.fn().mockResolvedValue({ marked: 1 }),
			get: vi.fn((path: string, params?: Record<string, string | number | boolean>) => {
				if (path.includes("/keys")) return base.get(path, params);
				if (path === `/agents/${READER_ID}/messages`) {
					inboxLists++;
					return Promise.resolve({ items: inboxItems, total: inboxItems.length });
				}
				if (path === `/messages/${DM_ID}`) return Promise.resolve(distribution);
				return Promise.reject(new Error(`Unexpected GET: ${path}`));
			}),
			post: vi.fn(),
		};
	});
	afterEach(() => {
		vi.useRealTimers();
		fs.rmSync(dir, { recursive: true });
	});

	const read = () =>
		decryptGroupMessageWithRecovery(
			client as never,
			dir,
			READER_ID,
			GROUP_ID,
			ciphertext,
			PEER_ID,
		);

	it("test_recovery_when_twenty_posts_miss_the_same_key_then_one_list_call_is_made", async () => {
		for (let i = 0; i < 20; i++) {
			await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);
		}
		expect(inboxLists).toBe(1);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, peerKeyId)).toBe(true);
	});

	it("test_recovery_when_the_entry_is_older_than_fifteen_minutes_then_it_scans_again", async () => {
		await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);
		vi.advanceTimersByTime(NEGATIVE_TTL_MS);
		await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);
		expect(inboxLists).toBe(2);
	});

	it("test_recovery_when_the_key_arrives_later_then_the_cached_post_opens", async () => {
		await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);

		// The sender's distribution lands, and an explicit scan ingests it.
		inboxItems = [{ id: DM_ID }];
		const scan = await scanPendingSKDistributions(client as never, dir, READER_ID);
		expect(scan.ingested).toBe(1);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, peerKeyId)).toBe(false);

		const opened = await read();
		expect(opened.verified).toBe(true);
		expect(inboxLists).toBe(2);
	});

	it("test_recovery_when_the_sync_verb_scans_then_a_cached_entry_does_not_stop_it", async () => {
		await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);
		await scanPendingSKDistributions(client as never, dir, READER_ID, peerKeyId, GROUP_ID);
		await scanPendingSKDistributions(client as never, dir, READER_ID, peerKeyId, GROUP_ID);
		expect(inboxLists).toBe(3);
	});

	it("test_recovery_when_the_sender_is_not_named_then_nothing_is_cached", async () => {
		await fetchAndIngestPendingSKDistributions(client as never, dir, READER_ID, peerKeyId, GROUP_ID);
		await fetchAndIngestPendingSKDistributions(client as never, dir, READER_ID, peerKeyId, GROUP_ID);
		expect(inboxLists).toBe(2);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, peerKeyId)).toBe(false);
	});

	it("test_recovery_when_the_key_is_ingested_by_another_path_then_the_entry_is_cleared", async () => {
		await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, peerKeyId)).toBe(true);

		// The distribution arrives on the live stream, not through a scan.
		const opened = await decryptMessage(
			dir,
			READER_ID,
			distribution.encrypted_payload as string,
			client as never,
			PEER_ID,
		);
		expect(ingestSenderKeyDistribution(dir, READER_ID, "rine.v1.sender_key_distribution", opened)).toBe(true);

		expect(isCached(READER_ID, GROUP_ID, PEER_ID, peerKeyId)).toBe(false);
	});

	it("test_recovery_when_the_scan_did_not_cover_the_inbox_then_nothing_is_cached", async () => {
		client.get.mockImplementation((path: string, params?: Record<string, string | number | boolean>) => {
			if (path.includes("/keys")) return Promise.resolve({});
			if (path === `/agents/${READER_ID}/messages`) {
				inboxLists++;
				return Promise.resolve({ items: [], total: 101 });
			}
			return Promise.reject(new Error(`Unexpected GET: ${path} ${JSON.stringify(params)}`));
		});
		await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, peerKeyId)).toBe(false);
		await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);
		expect(inboxLists).toBe(2);
	});

	it("test_recovery_when_a_row_fails_to_fetch_then_nothing_is_cached", async () => {
		inboxItems = [{ id: DM_ID }];
		const get = client.get.getMockImplementation() as (...a: unknown[]) => unknown;
		client.get.mockImplementation((path: string, ...rest: unknown[]) =>
			path === `/messages/${DM_ID}` ? Promise.reject(new Error("503")) : get(path, ...rest),
		);
		await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, peerKeyId)).toBe(false);
	});

	it("test_recovery_when_one_row_fails_every_scan_then_the_miss_is_cached_after_the_limit", async () => {
		const poison = "c9d0e1f2-a3b4-5678-cdef-789012345678";
		inboxItems = [{ id: poison }];
		const get = client.get.getMockImplementation() as (...a: unknown[]) => unknown;
		client.get.mockImplementation((path: string, ...rest: unknown[]) =>
			path === `/messages/${poison}` ? Promise.reject(new Error("bad row")) : get(path, ...rest),
		);
		for (let i = 0; i < ROW_FAILURE_LIMIT; i++) {
			await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);
			expect(isCached(READER_ID, GROUP_ID, PEER_ID, peerKeyId)).toBe(false);
		}
		await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, peerKeyId)).toBe(true);
		await expect(read()).rejects.toBeInstanceOf(SenderKeyUnavailableError);
		expect(inboxLists).toBe(ROW_FAILURE_LIMIT + 1);
	});

	it("test_recovery_when_a_scan_installs_something_then_the_key_is_not_cached", async () => {
		inboxItems = [{ id: DM_ID }];
		const ingested = await fetchAndIngestPendingSKDistributions(
			client as never,
			dir,
			READER_ID,
			peerKeyId,
			GROUP_ID,
			PEER_ID,
		);
		expect(ingested).toBe(1);
		expect(isCached(READER_ID, GROUP_ID, PEER_ID, peerKeyId)).toBe(false);
	});
});

describe("settleRowFailures", () => {
	const AGENT = "f6a7b8c9-d0e1-2345-fabc-456789012345";
	const scan = (openedIds: string[], failedIds: string[]) =>
		settleRowFailures(AGENT, openedIds, failedIds);

	it("test_settle_when_one_row_fails_the_limit_in_a_row_then_it_stops_counting", () => {
		const id = "e5f6a7b8-c9d0-1234-efab-345678901234";
		for (let i = 0; i < ROW_FAILURE_LIMIT; i++) {
			expect(scan([id], [id])).toBe(1);
		}
		expect(scan([id], [id])).toBe(0);
		expect(scan([id], [id])).toBe(0);
	});

	it("test_settle_when_the_row_opens_between_failures_then_the_streak_restarts", () => {
		const id = "a7b8c9d0-e1f2-3456-abcd-567890123456";
		for (let i = 0; i < ROW_FAILURE_LIMIT; i++) scan([id], [id]);
		expect(scan([id], [])).toBe(0);
		for (let i = 0; i < ROW_FAILURE_LIMIT; i++) {
			expect(scan([id], [id])).toBe(1);
		}
	});

	it("test_settle_when_the_row_was_not_opened_this_scan_then_its_streak_is_kept", () => {
		const id = "b8c9d0e1-f2a3-4567-bcde-678901234567";
		for (let i = 0; i < ROW_FAILURE_LIMIT; i++) scan([id], [id]);
		expect(scan([], [])).toBe(0);
		expect(scan([id], [id])).toBe(0);
	});
});
