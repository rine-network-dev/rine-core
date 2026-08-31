import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ACTING_AGENT_HEADER } from "../src/actor.js";
import {
	decryptGroupMessageWithRecovery,
	fetchAndIngestPendingSKDistributions,
	scanPendingSKDistributions,
} from "../src/sender-key-recovery.js";
import {
	SENDER_KEY_UNAVAILABLE_CODE,
	SenderKeyUnavailableError,
	unknownSenderKeyId,
} from "../src/sender-key-words.js";
import type { AgentKeys } from "../src/crypto/keys.js";
import {
	generateAgentKeys,
	saveAgentKeys,
	toBase64Url,
} from "../src/crypto/keys.js";
import {
	encryptGroupMessage,
	encryptMessage,
	getAgentPublicKeys,
} from "../src/crypto/message.js";
import { generateSenderKey } from "../src/crypto/sender-keys.js";
import {
	loadSenderKeyStates,
	markSenderKeysRetired,
	senderKeysRetired,
} from "../src/crypto/sender-keys-helpers.js";

/**
 * The recovery path is the whole reason the leave-time wipe used to be
 * point-in-time: a leave removes the state file and takes nothing out of the
 * inbox, so the DMs that carried every peer key are still listed by
 * `GET /agents/{id}/messages`. These exercise it with REAL sealed envelopes,
 * because the refusal has to hold on the path that actually decrypts.
 */

const READER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const PEER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const DM_ID = "d4e5f6a7-b8c9-0123-defa-234567890123";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-skrecovery-test-"));
}

/**
 * A client that answers exactly the four reads the recovery path makes: the
 * group's roster, the inbox listing, the one DM in it, and the peer's published
 * keys. `memberIds` is who the server says the group holds right now — the only
 * fact that may lift a retirement.
 *
 * `total` is what the server says the whole listing holds, against the rows this
 * page carries. Omitted by default, which is a server that answered without one
 * — the case the shortfall must refuse to invent.
 *
 * `rows` is how many rows the page carries, all of them the same DM: more than
 * one is only needed to prove what a targeted scan's `break` leaves behind, and
 * the second row is never opened in that test, so its identity is nothing.
 */
function makeClient(
	peerKeys: AgentKeys,
	dm: Record<string, unknown>,
	memberIds: string[] = [PEER_ID],
	total?: number,
	rows = 1,
) {
	return {
		get: vi.fn().mockImplementation((path: string) => {
			if (path === `/groups/${GROUP_ID}/members`) {
				return Promise.resolve({
					items: memberIds.map((id) => ({ agent_id: id })),
				});
			}
			if (path === `/agents/${READER_ID}/messages`) {
				return Promise.resolve({
					items: Array.from({ length: rows }, () => ({ id: DM_ID })),
					...(total === undefined ? {} : { total }),
				});
			}
			if (path === `/messages/${DM_ID}`) return Promise.resolve(dm);
			if (path.includes("/keys")) {
				return Promise.resolve({
					agent_id: PEER_ID,
					...getAgentPublicKeys("", PEER_ID, peerKeys),
				});
			}
			return Promise.reject(new Error(`Unexpected GET: ${path}`));
		}),
		post: vi.fn(),
	};
}

// Named for both because it holds both: the count-only wrapper and the pass it
// is one line over. A label naming only the wrapper mislabels most of its own
// contents in the reporter, which is where a failure is read.
describe("scanPendingSKDistributions / fetchAndIngestPendingSKDistributions", () => {
	let dir: string;
	let peerKeys: AgentKeys;
	let dm: Record<string, unknown>;
	let client: ReturnType<typeof makeClient>;
	let peerSenderKeyId: string;

	beforeEach(async () => {
		dir = makeTmpDir();
		const readerKeys = generateAgentKeys();
		saveAgentKeys(dir, READER_ID, readerKeys);
		peerKeys = generateAgentKeys();
		saveAgentKeys(dir, PEER_ID, peerKeys);

		const peerState = generateSenderKey(GROUP_ID, PEER_ID);
		peerSenderKeyId = peerState.senderKeyId;
		const sealed = await encryptMessage(
			dir,
			PEER_ID,
			readerKeys.encryption.publicKey,
			{
				group_id: GROUP_ID,
				sender_key_id: peerState.senderKeyId,
				chain_key: toBase64Url(peerState.chainKey),
				message_index: peerState.messageIndex,
				sender_agent_id: PEER_ID,
			},
		);
		dm = {
			id: DM_ID,
			type: "rine.v1.sender_key_distribution",
			from_agent_id: PEER_ID,
			encrypted_payload: sealed.encrypted_payload,
		};
		client = makeClient(peerKeys, dm);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("test_recovery_when_the_group_is_live_then_the_pending_key_is_ingested", async () => {
		const ingested = await fetchAndIngestPendingSKDistributions(
			client as never,
			dir,
			READER_ID,
		);

		expect(ingested).toBe(1);
		expect(loadSenderKeyStates(dir, READER_ID, GROUP_ID)).toHaveLength(1);
	});

	it("test_recovery_when_it_reads_the_dm_then_it_says_which_agent_is_reading", async () => {
		// The recovery scan opens someone's mail on their behalf, and the
		// server marks the delivery row of the agent the header names — nobody
		// else's. Without the header this read marks nothing in a multi-agent org
		// and the DM stays queued forever. The stub above absorbs extra arguments
		// silently, so this is the only thing that can see the header go missing.
		await fetchAndIngestPendingSKDistributions(client as never, dir, READER_ID);

		const read = client.get.mock.calls.find(
			(call) => call[0] === `/messages/${DM_ID}`,
		);
		expect(read).toBeDefined();
		expect(read?.[2]).toEqual({ [ACTING_AGENT_HEADER]: READER_ID });
	});

	it("test_recovery_when_the_group_was_retired_then_the_pending_key_is_refused", async () => {
		// Same inbox, same sealed DM, same client — only the marker differs. This is
		// the defect the marker closes: without it the wipe held until this call.
		markSenderKeysRetired(dir, READER_ID, GROUP_ID);

		const ingested = await fetchAndIngestPendingSKDistributions(
			client as never,
			dir,
			READER_ID,
		);

		expect(ingested).toBe(0);
		expect(loadSenderKeyStates(dir, READER_ID, GROUP_ID)).toEqual([]);
	});

	it("test_recovery_when_a_readmitted_agent_only_reads_then_the_retirement_lifts_here", async () => {
		// The CLI's read/stream and the TypeScript SDK's decrypt call THIS function,
		// never `decryptGroupMessageWithRecovery`, so a lift that lived only up
		// there left a re-admitted member refusing its new peers' keys for ever.
		markSenderKeysRetired(dir, READER_ID, GROUP_ID);
		client = makeClient(peerKeys, dm, [PEER_ID, READER_ID]);

		const ingested = await fetchAndIngestPendingSKDistributions(
			client as never,
			dir,
			READER_ID,
			undefined,
			GROUP_ID,
		);

		expect(ingested).toBe(1);
		expect(loadSenderKeyStates(dir, READER_ID, GROUP_ID)).toHaveLength(1);
		expect(senderKeysRetired(dir, READER_ID, GROUP_ID)).toBe(false);
	});

	it("test_recovery_when_a_departed_agent_names_the_group_then_the_inbox_is_never_read", async () => {
		markSenderKeysRetired(dir, READER_ID, GROUP_ID);

		const ingested = await fetchAndIngestPendingSKDistributions(
			client as never,
			dir,
			READER_ID,
			undefined,
			GROUP_ID,
		);

		expect(ingested).toBe(0);
		expect(senderKeysRetired(dir, READER_ID, GROUP_ID)).toBe(true);
		// The roster read is the only one the refusal pays for.
		expect(client.get).toHaveBeenCalledTimes(1);
		expect(client.get).toHaveBeenCalledWith(`/groups/${GROUP_ID}/members`);
	});

	/**
	 * The second number: what one page of the inbox did NOT reach.
	 *
	 * The scan reads `limit: 100` and follows no cursor, so an agent with a
	 * longer distribution inbox gets a partial pass — and the count of what was
	 * installed cannot say so. The server's own `total` is already in the
	 * response, which is why the shortfall costs no extra request.
	 */
	describe("what the one page did not reach", () => {
		it("test_scan_when_the_server_counts_more_than_the_page_then_the_rest_is_reported", async () => {
			client = makeClient(peerKeys, dm, [PEER_ID], 137);

			const scan = await scanPendingSKDistributions(
				client as never,
				dir,
				READER_ID,
			);

			expect(scan).toEqual({ ingested: 1, unscanned: 136 });
		});

		it("test_scan_when_the_page_holds_the_whole_listing_then_nothing_is_reported", async () => {
			client = makeClient(peerKeys, dm, [PEER_ID], 1);

			const scan = await scanPendingSKDistributions(
				client as never,
				dir,
				READER_ID,
			);

			expect(scan).toEqual({ ingested: 1, unscanned: 0 });
		});

		it("test_scan_when_the_server_sends_no_total_then_no_shortfall_is_invented", async () => {
			// `include_total` can be turned off on the list route, and a shortfall
			// computed from a missing field is worse than none at all.
			const scan = await scanPendingSKDistributions(
				client as never,
				dir,
				READER_ID,
			);

			expect(scan).toEqual({ ingested: 1, unscanned: 0 });
		});

		it("test_scan_when_the_group_is_retired_then_no_page_is_read_and_none_is_missed", async () => {
			markSenderKeysRetired(dir, READER_ID, GROUP_ID);
			client = makeClient(peerKeys, dm, [PEER_ID], 137);

			const scan = await scanPendingSKDistributions(
				client as never,
				dir,
				READER_ID,
				undefined,
				GROUP_ID,
			);

			expect(scan).toEqual({ ingested: 0, unscanned: 0 });
		});

		it("test_scan_when_a_target_ends_the_pass_early_then_the_rest_of_the_page_counts_too", async () => {
			// The targeted arm `break`s the moment it installs the key it was sent
			// for, and the rows after that break were listed and never opened —
			// which is the same state as the rows past the end of the page. A
			// version that computed the shortfall before the loop reported those
			// rows as scanned, on exactly the path that stops early.
			client = makeClient(peerKeys, dm, [PEER_ID], 137, 2);

			const scan = await scanPendingSKDistributions(
				client as never,
				dir,
				READER_ID,
				peerSenderKeyId,
			);

			// 135 past the two-row page, plus the one row the break left behind.
			expect(scan).toEqual({ ingested: 1, unscanned: 136 });
		});

		it("test_scan_when_the_count_only_wrapper_is_called_then_it_is_the_same_pass", async () => {
			// 🔴 `fetchAndIngestPendingSKDistributions` returns `number` and every
			// read path in the product calls it. It is this function with the second
			// number dropped, never a second implementation.
			client = makeClient(peerKeys, dm, [PEER_ID], 137);

			const ingested = await fetchAndIngestPendingSKDistributions(
				client as never,
				dir,
				READER_ID,
			);

			expect(ingested).toBe(1);
		});
	});
});

describe("decryptGroupMessageWithRecovery", () => {
	let dir: string;
	let ciphertext: string;
	let readerKeys: AgentKeys;
	let peerKeys: AgentKeys;
	let client: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };

	beforeEach(async () => {
		dir = makeTmpDir();
		readerKeys = generateAgentKeys();
		saveAgentKeys(dir, READER_ID, readerKeys);
		peerKeys = generateAgentKeys();
		saveAgentKeys(dir, PEER_ID, peerKeys);

		const { result } = await encryptGroupMessage(
			dir,
			PEER_ID,
			GROUP_ID,
			generateSenderKey(GROUP_ID, PEER_ID),
			{ announcement: "after you left" },
		);
		ciphertext = result.encrypted_payload;
		// The reader holds no state for this group, so the decrypt misses.
		client = { get: vi.fn(), post: vi.fn() };
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	/** The one read a retired group is allowed to make: who is a member now. */
	function membersAnswer(memberIds: string[]) {
		return (path: string) => {
			if (path === `/groups/${GROUP_ID}/members`) {
				return Promise.resolve({
					items: memberIds.map((id) => ({ agent_id: id })),
				});
			}
			if (path === `/agents/${READER_ID}/messages`) {
				return Promise.resolve({ items: [] });
			}
			return Promise.reject(new Error(`Unexpected GET: ${path}`));
		};
	}

	it("test_recovery_when_the_group_was_retired_then_the_inbox_is_never_read", async () => {
		markSenderKeysRetired(dir, READER_ID, GROUP_ID);
		client.get.mockImplementation(membersAnswer([PEER_ID]));

		await expect(
			decryptGroupMessageWithRecovery(
				client as never,
				dir,
				READER_ID,
				GROUP_ID,
				ciphertext,
				PEER_ID,
			),
		).rejects.toThrow(SenderKeyUnavailableError);

		// The membership read is the only one: the inbox scan is what the
		// retirement declines to pay for.
		expect(client.get).toHaveBeenCalledTimes(1);
		expect(client.get).toHaveBeenCalledWith(`/groups/${GROUP_ID}/members`);
		expect(senderKeysRetired(dir, READER_ID, GROUP_ID)).toBe(true);
	});

	it("test_recovery_when_the_agent_is_a_member_again_then_the_retirement_lifts", async () => {
		markSenderKeysRetired(dir, READER_ID, GROUP_ID);
		client.get.mockImplementation(membersAnswer([PEER_ID, READER_ID]));

		// Still fails — the inbox this fixture serves is empty — but it FAILED
		// having scanned, which a wedged re-admitted reader never got to do.
		await expect(
			decryptGroupMessageWithRecovery(
				client as never,
				dir,
				READER_ID,
				GROUP_ID,
				ciphertext,
				PEER_ID,
			),
		).rejects.toThrow(SenderKeyUnavailableError);

		expect(senderKeysRetired(dir, READER_ID, GROUP_ID)).toBe(false);
		expect(client.get).toHaveBeenCalledWith(
			`/agents/${READER_ID}/messages`,
			expect.anything(),
		);
	});

	it("test_recovery_when_no_key_arrives_then_the_refusal_says_what_to_do_instead", async () => {
		// The recovery has run and found nothing, so this is the whole
		// answer an agent gets. It has to carry the cause, a move that actually
		// works, and the fact that this particular message is not coming back —
		// the library's own control string carried none of the three.
		client.get.mockImplementation(membersAnswer([PEER_ID, READER_ID]));

		const err = (await decryptGroupMessageWithRecovery(
			client as never,
			dir,
			READER_ID,
			GROUP_ID,
			ciphertext,
			PEER_ID,
		).catch((e: unknown) => e)) as SenderKeyUnavailableError;

		expect(err).toBeInstanceOf(SenderKeyUnavailableError);
		expect(err.groupId).toBe(GROUP_ID);
		// The cause, in the reader's terms, naming the key it would need.
		expect(err.message).toContain(err.senderKeyId);
		// A move that works: the sender's NEXT post distributes the key.
		expect(err.message).toContain("Ask the sender to post to the group again");
		// And the part an operator would otherwise wait for in vain.
		expect(err.message).toContain("This message stays sealed");
		// What the world did not lose, on the model of the seat-403 refusal.
		expect(err.message).toContain("no key was consumed");
		// 🔴 The internal control string never reaches a reader.
		expect(err.message).not.toContain("unknown sender key id");
		// The throw it stands in front of is still reachable for a debugger.
		expect(unknownSenderKeyId(err.cause)).toBe(err.senderKeyId);
	});

	it("test_recovery_when_the_retry_still_misses_then_the_same_verdict_comes_back", async () => {
		// The other end of the recovery. The scan brought key material — just not
		// THIS key — so the retry ran and missed, and the library threw its control
		// string a second time. That arm used to propagate exactly as thrown, so
		// `unknown sender key id: <uuid>` was what a reader got on the one path
		// where the recovery had done the most work. The verdict is the same as an
		// empty scan's, and is now said in the same words.
		const otherState = generateSenderKey(GROUP_ID, PEER_ID);
		const sealed = await encryptMessage(
			dir,
			PEER_ID,
			readerKeys.encryption.publicKey,
			{
				group_id: GROUP_ID,
				sender_key_id: otherState.senderKeyId,
				chain_key: toBase64Url(otherState.chainKey),
				message_index: otherState.messageIndex,
				sender_agent_id: PEER_ID,
			},
		);
		const scanning = makeClient(
			peerKeys,
			{
				id: DM_ID,
				type: "rine.v1.sender_key_distribution",
				from_agent_id: PEER_ID,
				encrypted_payload: sealed.encrypted_payload,
			},
			[PEER_ID, READER_ID],
		);

		const err = (await decryptGroupMessageWithRecovery(
			scanning as never,
			dir,
			READER_ID,
			GROUP_ID,
			ciphertext,
			PEER_ID,
		).catch((e: unknown) => e)) as SenderKeyUnavailableError;

		// This is the retry arm and not the empty-scan one: a key did land.
		expect(loadSenderKeyStates(dir, READER_ID, GROUP_ID)).toHaveLength(1);
		expect(err).toBeInstanceOf(SenderKeyUnavailableError);
		expect(err.code).toBe(SENDER_KEY_UNAVAILABLE_CODE);
		// 🔴 The control string never reaches a reader on this arm either.
		expect(err.message).not.toContain("unknown sender key id");
		expect(err.message).toContain("Ask the sender to post to the group again");
		// It names the key the message needs, not the one that happened to arrive.
		expect(err.senderKeyId).not.toBe(otherState.senderKeyId);
	});

	it("test_recovery_when_the_failure_is_not_a_missing_key_then_it_passes_through", async () => {
		// Only the missing-key failure is translated. Everything else is a
		// different fact with a different remedy and is handed back as thrown.
		const other = new Error("message key expired or already consumed");
		client.get.mockImplementation(membersAnswer([PEER_ID, READER_ID]));

		await expect(
			decryptGroupMessageWithRecovery(
				client as never,
				dir,
				READER_ID,
				GROUP_ID,
				"not-base64url-ciphertext!!",
				PEER_ID,
			),
		).rejects.not.toBeInstanceOf(SenderKeyUnavailableError);
		expect(unknownSenderKeyId(other)).toBeNull();
	});

	it("test_recovery_when_membership_cannot_be_read_then_the_retirement_holds", async () => {
		markSenderKeysRetired(dir, READER_ID, GROUP_ID);
		client.get.mockRejectedValue(new Error("403: Access denied"));

		await expect(
			decryptGroupMessageWithRecovery(
				client as never,
				dir,
				READER_ID,
				GROUP_ID,
				ciphertext,
				PEER_ID,
			),
		).rejects.toThrow(SenderKeyUnavailableError);

		// A failed read proves nothing, so it is never a lift.
		expect(senderKeysRetired(dir, READER_ID, GROUP_ID)).toBe(true);
	});
});
