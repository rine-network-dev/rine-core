/**
 * A group message is readable more than once per reader.
 *
 * Both regimes spend a one-time key at the first decrypt, so the second read of
 * an inbox entry used to be an error — "message key expired or already
 * consumed" on Sender Keys, "key not available" on MLS. These tests drive the
 * real sender-key crypto and the real native MLS core through the public decrypt
 * function and hold the difference to ONE variable: the cache file. The control
 * arm in each regime deletes it and asks the same client for the same row, which
 * is what makes the replay attributable to the cache rather than to anything
 * else the read path does.
 *
 * 🔴 **Both arms are required, and the MLS one is the one that was missing.**
 * MLS is the default regime for new groups, and the only MLS re-read test that
 * existed (`rine-sdk/tests/test_mls_messages.py` `TestRowsSeenTwice`) predates
 * the on-disk cache and passes without it — its second read comes from an
 * in-process memo. A green suite that a different mechanism satisfies is not
 * evidence for this one.
 */

import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	GROUP_READ_MAX_ENTRIES,
	deleteGroupReadCache,
	lookupGroupRead,
	recordGroupRead,
} from "../../src/crypto/group-read-cache.js";
import {
	type AgentKeys,
	generateAgentKeys,
	saveAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
} from "../../src/crypto/keys.js";
import {
	decryptGroupMessage,
	encryptGroupMessage,
	encryptMlsGroupMessage,
} from "../../src/crypto/message.js";
import { mlsGroupIdBytes, openMlsClient } from "../../src/crypto/mls.js";
import {
	markSenderKeysRetired,
	saveSenderKeyState,
} from "../../src/crypto/sender-keys-helpers.js";
import { generateSenderKey } from "../../src/crypto/sender-keys.js";
import { resetMlsCatchUpGate } from "../../src/mls-catchup.js";

const SENDER_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const READER_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
const IMPOSTOR_ID = "cccccccc-3333-4333-8333-cccccccccccc";
const GROUP_ID = "dddddddd-4444-4444-8444-dddddddddddd";
const TEXT = "the last thing anyone said";

/**
 * The reads a group decrypt makes: the signing-key lookup `verifyEnvelopeSender`
 * performs, plus — on the MLS path only — the empty catch-up and welcome batches
 * the successful-read and recovery paths perform.
 *
 * `calls` records the `extraHeaders` of every GET, because whether a group-scoped
 * route is asked as a named agent is itself under test: without `X-Rine-Agent`
 * the server resolves the actor by "the org's single active agent" and answers
 * 422 for any org with two or more.
 */
function keyServer(published: Record<string, AgentKeys>) {
	const calls: { path: string; headers?: Record<string, string> }[] = [];
	const get = vi.fn(
		async (
			path: string,
			_params?: Record<string, string>,
			headers?: Record<string, string>,
		) => {
			calls.push({ path, headers });
			const match = /^\/agents\/([^/]+)\/keys$/.exec(path);
			if (match) {
				const keys = published[match[1] as string];
				if (!keys) throw new Error(`unexpected GET ${path}`);
				return {
					agent_id: match[1],
					signing_public_key: signingPublicKeyToJWK(keys.signing.publicKey),
					encryption_public_key: {
						kty: "OKP",
						crv: "X25519",
						x: toBase64Url(keys.encryption.publicKey),
					},
				};
			}
			if (path.endsWith("/mls/handshakes")) return { handshakes: [] };
			if (path.endsWith("/mls/welcomes")) return { welcomes: [] };
			throw new Error(`unexpected GET ${path}`);
		},
	);
	return { get, post: vi.fn(), calls };
}

describe("reading a sender-key group message twice", () => {
	let dir: string;
	let sender: AgentKeys;
	let ciphertext: string;

	beforeEach(async () => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-read-cache-"));
		sender = generateAgentKeys();
		saveAgentKeys(dir, SENDER_ID, sender);
		saveAgentKeys(dir, READER_ID, generateAgentKeys());
		saveAgentKeys(dir, IMPOSTOR_ID, generateAgentKeys());
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		// The sender's own copy, which `encryptGroupMessage` advances in place. A
		// stand-in sender needs it as much as a real one does: the tail refuses a
		// state that is on no disk at all rather than discarding the advance.
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [state]);
		const { result } = await encryptGroupMessage(
			dir,
			SENDER_ID,
			GROUP_ID,
			state,
			{
				text: TEXT,
			},
		);
		saveSenderKeyState(dir, READER_ID, GROUP_ID, [state]);
		ciphertext = result.encrypted_payload;
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	function read(fromAgentId = SENDER_ID) {
		const client = keyServer({ [SENDER_ID]: sender });
		return decryptGroupMessage(
			dir,
			READER_ID,
			GROUP_ID,
			ciphertext,
			client as never,
			fromAgentId,
		);
	}

	it("test_second_read_when_the_key_is_spent_then_returns_the_same_plaintext", async () => {
		const first = await read();
		const second = await read();

		expect(JSON.parse(first.plaintext)).toEqual({ text: TEXT });
		expect(JSON.parse(second.plaintext)).toEqual({ text: TEXT });
		expect(second.senderKid).toBe(first.senderKid);
		expect(second.verificationStatus).toBe("verified");
	});

	it("test_second_read_when_the_cache_is_removed_then_the_key_is_gone", async () => {
		// The control arm. One variable changes — the cache file — and the same
		// client, config dir, sender-key state and ciphertext ask again. Without
		// this the replay above could be explained by anything.
		await read();
		deleteGroupReadCache(dir, READER_ID, GROUP_ID);

		await expect(read()).rejects.toThrow(
			"message key expired or already consumed",
		);
	});

	it("test_replay_when_the_row_names_a_different_sender_then_refuses", async () => {
		await read();

		// The cache answers what the bytes SAID; who they are attributed to is
		// decided per read, against the sender the server stamps on the row being
		// read now. A replay that carried the first read's verdict would let a
		// re-served row come back as verified content from an agent that did not
		// sign it.
		await expect(read(IMPOSTOR_ID)).rejects.toThrow(
			"Envelope sender does not match the message sender",
		);
	});

	it("test_replay_when_the_group_is_retired_then_the_cache_stays_shut", async () => {
		await read();

		// A leave writes a retirement marker beside the keys it wipes, and
		// the marker has to be re-armable. A message opened while it was absent
		// must stop opening once it is back, or a departed member keeps a reader
		// the marker cannot close.
		markSenderKeysRetired(dir, READER_ID, GROUP_ID);

		await expect(read()).rejects.toThrow(
			"message key expired or already consumed",
		);
	});

	it("test_cache_file_when_written_then_is_owner_only", async () => {
		await read();

		const path = join(
			dir,
			"keys",
			READER_ID,
			"group_reads",
			`${GROUP_ID}.json`,
		);
		expect(fs.statSync(path).mode & 0o777).toBe(0o600);
	});
});

describe("reading an MLS group message twice", () => {
	let dir: string;
	let founder: AgentKeys;
	let ciphertext: string;
	let client: ReturnType<typeof keyServer>;

	beforeEach(async () => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-read-cache-mls-"));
		founder = generateAgentKeys();
		saveAgentKeys(dir, SENDER_ID, founder);
		saveAgentKeys(dir, READER_ID, generateAgentKeys());
		saveAgentKeys(dir, IMPOSTOR_ID, generateAgentKeys());

		// A real two-member native group on the default suite: the reader is
		// welcomed into the founder's tree, so the decrypt below spends a real
		// secret-tree entry the core will not hand back a second time.
		const readerClient = openMlsClient(dir, READER_ID);
		const keyPackage = readerClient.generateKeyPackage();
		const group = openMlsClient(dir, SENDER_ID).createGroupWithMembers(
			mlsGroupIdBytes(GROUP_ID),
			[keyPackage],
		);
		const bundle = group.lastCommit();
		if (!bundle) throw new Error("founding commit missing");
		group.save();
		readerClient.joinFromWelcome(bundle.welcomes[0] as Uint8Array).save();

		const result = await encryptMlsGroupMessage(dir, SENDER_ID, GROUP_ID, {
			text: TEXT,
		});
		ciphertext = result.encrypted_payload;
		// The eager catch-up's gate is per process, and these cases read the same
		// (dir, agent, group) more than once.
		resetMlsCatchUpGate();
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
		resetMlsCatchUpGate();
	});

	function read(fromAgentId = SENDER_ID) {
		client = keyServer({ [SENDER_ID]: founder });
		return decryptGroupMessage(
			dir,
			READER_ID,
			GROUP_ID,
			ciphertext,
			client as never,
			fromAgentId,
		);
	}

	it("test_second_read_of_an_mls_row_when_the_ratchet_is_spent_then_returns_the_same_plaintext", async () => {
		const first = await read();
		const second = await read();

		expect(JSON.parse(first.plaintext)).toEqual({ text: TEXT });
		expect(JSON.parse(second.plaintext)).toEqual({ text: TEXT });
		expect(second.senderKid).toBe(first.senderKid);
		expect(second.verificationStatus).toBe("verified");
	});

	it("test_second_read_of_an_mls_row_when_the_cache_is_removed_then_the_secret_is_gone", async () => {
		// The control arm, and the whole reason the case above is evidence. One
		// variable changes — the cache file — and the same client, config dir, MLS
		// state and ciphertext ask again. MLS deletes the secret-tree entry at the
		// first decrypt, so the recovery path cannot bring it back either.
		await read();
		deleteGroupReadCache(dir, READER_ID, GROUP_ID);

		await expect(read()).rejects.toThrow(/key not available/);
	});

	it("test_mls_replay_when_the_row_names_a_different_sender_then_refuses", async () => {
		await read();

		// The replay is re-verified exactly as a first read is, against the sender
		// the server stamps on the row being read NOW — the same rule as the
		// sender-key arm, reached through the other regime's branch.
		await expect(read(IMPOSTOR_ID)).rejects.toThrow(
			"Envelope sender does not match the message sender",
		);
	});

	it("test_mls_replay_when_the_group_is_retired_then_the_cache_stays_shut", async () => {
		await read();

		// The retirement gate is regime-independent on this stack: `decryptGroupMessage`
		// consults the marker before the cache for MLS rows too. READ: today the
		// only writer is `deleteSenderKey`, a sender-key leave path that deletes the
		// cache in the same breath, so on an MLS group this is defensive rather than
		// live — and it is the half the Python MLS path does not have.
		markSenderKeysRetired(dir, READER_ID, GROUP_ID);

		await expect(read()).rejects.toThrow(/key not available/);
	});

	it("test_catch_up_after_a_successful_mls_read_when_named_then_pins_the_acting_agent", async () => {
		await read();

		// Without the header the server resolves the actor by "the org's single
		// active agent" and answers 422 for an org with two or more — and
		// `catchUpMlsGroup` swallows that by contract AND has already stamped its
		// 60 s gate, so the eager catch-up would be a silent no-op for every
		// multi-agent org. The reading agent is named one argument away.
		const handshakes = client.calls.filter((c) =>
			c.path.endsWith("/mls/handshakes"),
		);
		expect(handshakes).toHaveLength(1);
		expect(handshakes[0]?.headers).toEqual({ "X-Rine-Agent": READER_ID });
	});
});

describe("the read cache's bounds", () => {
	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-read-cache-bounds-"));
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	/** The ciphertext of the i-th recorded read. */
	function nth(i: number): Uint8Array {
		return new Uint8Array([1, i & 0xff, (i >> 8) & 0xff]);
	}

	it("test_recording_when_past_the_entry_bound_then_drops_the_oldest", async () => {
		const overflow = GROUP_READ_MAX_ENTRIES + 5;
		for (let i = 0; i < overflow; i++) {
			recordGroupRead(dir, READER_ID, GROUP_ID, nth(i), new Uint8Array([9, i]));
		}

		// A re-read buffer, never an archive: the oldest five are gone and the
		// newest are still answerable.
		expect(lookupGroupRead(dir, READER_ID, GROUP_ID, nth(0))).toBeNull();
		expect(lookupGroupRead(dir, READER_ID, GROUP_ID, nth(4))).toBeNull();
		expect(lookupGroupRead(dir, READER_ID, GROUP_ID, nth(5))).not.toBeNull();
		expect(
			lookupGroupRead(dir, READER_ID, GROUP_ID, nth(overflow - 1)),
		).not.toBeNull();
	});

	it("test_lookup_when_the_file_is_damaged_then_answers_nothing_rather_than_throwing", async () => {
		recordGroupRead(
			dir,
			READER_ID,
			GROUP_ID,
			new Uint8Array([1, 2, 3]),
			new Uint8Array([4, 5, 6]),
		);
		const path = join(
			dir,
			"keys",
			READER_ID,
			"group_reads",
			`${GROUP_ID}.json`,
		);
		fs.writeFileSync(path, "{not json");

		// It holds no authority and no key material, so a damaged buffer degrades
		// into "decrypt it again" rather than failing a read the ratchet could
		// still answer.
		expect(
			lookupGroupRead(dir, READER_ID, GROUP_ID, new Uint8Array([1, 2, 3])),
		).toBeNull();
	});
});
