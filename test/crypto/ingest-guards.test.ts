/**
 * A sender-key distribution's payload is the sender's own plaintext.
 *
 * The envelope proves WHO sent the DM. It proves nothing at all about what the
 * JSON inside it says, and any agent that can DM this one can send one — a former
 * member, a stranger who learned the group's UUID, anybody. These are the three
 * things the ingest used to take at their word:
 *
 * - **The key id.** The duplicate check asked only "do I already hold this
 *   `sender_key_id`", so the FIRST distribution to claim an id owned that slot for
 *   good. An attacker who reads a peer's key id out of its own copy of that peer's
 *   distribution, then sends one of its own naming that id, makes the genuine
 *   distribution a no-op — permanently, because every later scan re-skips it. The
 *   peer's group posts stop opening and the refusal reads as a crypto regression.
 * - **The group id.** It becomes a FILENAME, and `validatePathId` accepts either
 *   case while the retirement marker and the read cache lower-case theirs. An
 *   upper-cased spelling therefore opened a second state-file namespace for one
 *   logical group: a file no honest reader looks in, no leave unlinks, and whose
 *   contents do not count as "already held" against the canonical file.
 * - **The chain key and the message index.** HMAC takes a key of any length and
 *   nothing downstream re-reads the index, so a 0-byte root or an index no uint32
 *   can name was stored exactly as sent.
 *
 * 🔴 The load-bearing assertion for the squat is the DECRYPT of the genuine
 * member's post, not the shape of the state file. A fix that stored both rows and
 * left the reader unable to open the post would satisfy a `toHaveLength(2)` and
 * still have handed the group away.
 *
 * Twin: `rine-sdk/tests/test_sender_key_ingest_guards.py`.
 */

import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ingestSenderKeyDistribution } from "../../src/crypto/ingest.js";
import { type DecryptResult } from "../../src/crypto/message.js";
import { encryptGroupMessage } from "../../src/crypto/sender-key-seal.js";
import { decryptGroupMessage } from "../../src/message-group.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
} from "../../src/crypto/sender-keys-helpers.js";
import {
	type SenderKeyState,
	generateSenderKey,
} from "../../src/crypto/sender-keys.js";
import { toBase64Url } from "../../src/crypto/keys.js";
import { World, type WorldAgent } from "./world.js";

/** The agent under attack — the one taking delivery of the distributions. */
const READER_ID = "77777777-8888-4999-8aaa-bbbbbbbbbbbb";
/** A seated peer whose group post the reader has to be able to open. */
const MEMBER_A_ID = "11111111-2222-4333-8444-555555555555";
/** Any agent that can DM the reader. It never has to be a member. */
const ATTACKER_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const GROUP_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
/** Recognisable material the reader must never end up ratcheting from. */
const SHADOW_CHAIN_KEY = toBase64Url(new Uint8Array(32).fill(0x41));

const DISTRIBUTION = "rine.v1.sender_key_distribution";

/** A verified decrypt result, as the DM read path hands one to the ingest. */
function fromSigner(signerId: string, payload: unknown): DecryptResult {
	return {
		plaintext: JSON.stringify(payload),
		senderKid: `rine:${signerId}#0`,
		verified: true,
		verificationStatus: "verified",
	};
}

function ingest(
	dir: string,
	signerId: string,
	payload: unknown,
	type = DISTRIBUTION,
): boolean {
	return ingestSenderKeyDistribution(
		dir,
		READER_ID,
		type,
		fromSigner(signerId, payload),
	);
}

/** The distribution an honest member sends for a state it holds. */
function distributionFor(state: SenderKeyState, groupId = GROUP_ID) {
	return {
		group_id: groupId,
		sender_key_id: state.senderKeyId,
		chain_key: toBase64Url(state.chainKey),
		message_index: state.messageIndex,
		sender_agent_id: state.senderAgentId,
	};
}

describe("sender-key distribution ingest — the payload is not evidence", () => {
	/** The reader's own config dir. */
	let dir: string;
	/** Member A's dir. Its private signing key is one no attacker holds. */
	let foreignDir: string;
	let world: World;
	let member: WorldAgent;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-ingest-guard-"));
		foreignDir = fs.mkdtempSync(join(tmpdir(), "rine-ingest-guard-foreign-"));
		world = new World();
		member = world.addAgent({ id: MEMBER_A_ID });
		world.save(foreignDir, member);
		world.save(dir, world.addAgent({ id: READER_ID }));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
		fs.rmSync(foreignDir, { recursive: true, force: true });
	});

	function readerStates(groupId = GROUP_ID): SenderKeyState[] {
		return loadSenderKeyStates(dir, READER_ID, groupId);
	}

	/**
	 * Member A mints a key, distributes it at index 0, and posts under it — the
	 * order the product uses. Returns the distribution the reader is owed and the
	 * ciphertext it has to be able to open.
	 */
	async function memberPost(
		text: string,
	): Promise<{ distribution: ReturnType<typeof distributionFor>; ciphertext: string }> {
		const state = generateSenderKey(GROUP_ID, MEMBER_A_ID);
		const distribution = distributionFor(state);
		// The sender's own copy: the tail of `encryptGroupMessage` refuses a state
		// that is on no disk at all rather than discarding the advance.
		saveSenderKeyState(foreignDir, MEMBER_A_ID, GROUP_ID, [state]);
		const { result } = await encryptGroupMessage(
			foreignDir,
			MEMBER_A_ID,
			GROUP_ID,
			state,
			{ text },
		);
		return { distribution, ciphertext: result.encrypted_payload };
	}

	describe("the key-id squat", () => {
		it("test_ingest_when_a_stranger_squats_the_key_id_then_the_members_post_still_opens", async () => {
			const { distribution, ciphertext } = await memberPost("ship it");
			// The attacker's DM is the later one, so the newest-first inbox hands it
			// to the scan first. No race is needed — this is the ordinary ordering.
			expect(
				ingest(dir, ATTACKER_ID, {
					...distribution,
					chain_key: SHADOW_CHAIN_KEY,
					sender_agent_id: MEMBER_A_ID,
				}),
			).toBe(true);

			expect(ingest(dir, MEMBER_A_ID, distribution)).toBe(true);

			const opened = await decryptGroupMessage(
				dir,
				READER_ID,
				GROUP_ID,
				ciphertext,
				world.client() as never,
				MEMBER_A_ID,
			);
			expect(JSON.parse(opened.plaintext as string)).toEqual({ text: "ship it" });
		});

		it("test_ingest_when_a_stranger_squats_the_key_id_then_it_is_filed_under_the_stranger", async () => {
			const { distribution } = await memberPost("ship it");
			ingest(dir, ATTACKER_ID, {
				...distribution,
				chain_key: SHADOW_CHAIN_KEY,
				sender_agent_id: MEMBER_A_ID,
			});
			ingest(dir, MEMBER_A_ID, distribution);

			// `sender_agent_id` in the payload said MEMBER_A on both rows; the stored
			// identity comes from the verified kid, so the two are told apart.
			const senders = readerStates().map((s) => s.senderAgentId);
			expect(senders).toEqual([ATTACKER_ID, MEMBER_A_ID]);
		});

		it("test_ingest_when_the_same_sender_repeats_its_key_in_another_case_then_it_is_a_duplicate", async () => {
			const { distribution } = await memberPost("ship it");
			expect(ingest(dir, MEMBER_A_ID, distribution)).toBe(true);

			// A kid is canonical: `parseSigningKid` accepts only a lower-case UUID, so
			// a differently-cased spelling is refused outright rather than handed a
			// fresh slot per spelling.
			expect(
				ingest(dir, MEMBER_A_ID.toUpperCase(), distribution),
			).toBe(false);
			expect(readerStates()).toHaveLength(1);
		});
	});

	describe("the group-id namespace", () => {
		it("test_ingest_when_the_group_id_is_upper_cased_then_it_lands_in_the_canonical_file", async () => {
			const { distribution } = await memberPost("ship it");

			expect(
				ingest(dir, MEMBER_A_ID, {
					...distribution,
					group_id: GROUP_ID.toUpperCase(),
				}),
			).toBe(true);

			// The spelling every honest reader passes — the server's own.
			expect(readerStates()).toHaveLength(1);
			expect(readerStates()[0]!.groupId).toBe(GROUP_ID);
		});

		it("test_ingest_when_the_group_id_is_upper_cased_then_it_is_still_a_duplicate", async () => {
			const { distribution } = await memberPost("ship it");
			expect(ingest(dir, MEMBER_A_ID, distribution)).toBe(true);

			expect(
				ingest(dir, MEMBER_A_ID, {
					...distribution,
					group_id: GROUP_ID.toUpperCase(),
				}),
			).toBe(false);
			expect(readerStates()).toHaveLength(1);
		});
	});

	describe("the unbounded fields", () => {
		it("test_ingest_when_the_chain_key_is_short_then_it_is_refused", async () => {
			const { distribution } = await memberPost("ship it");

			expect(
				ingest(dir, MEMBER_A_ID, {
					...distribution,
					chain_key: toBase64Url(new Uint8Array(0)),
				}),
			).toBe(false);
			expect(readerStates()).toEqual([]);
		});

		it("test_ingest_when_the_chain_key_is_oversized_then_it_is_refused", async () => {
			const { distribution } = await memberPost("ship it");

			expect(
				ingest(dir, MEMBER_A_ID, {
					...distribution,
					chain_key: toBase64Url(new Uint8Array(4096)),
				}),
			).toBe(false);
			expect(readerStates()).toEqual([]);
		});

		it("test_ingest_when_the_message_index_is_negative_then_it_is_refused", async () => {
			const { distribution } = await memberPost("ship it");

			expect(
				ingest(dir, MEMBER_A_ID, { ...distribution, message_index: -1 }),
			).toBe(false);
			expect(readerStates()).toEqual([]);
		});

		it("test_ingest_when_the_message_index_exceeds_the_wire_then_it_is_refused", async () => {
			const { distribution } = await memberPost("ship it");

			// The wire carries the index in a big-endian uint32, so this state can
			// never be reached by a real message.
			expect(
				ingest(dir, MEMBER_A_ID, {
					...distribution,
					message_index: 0x1_0000_0000,
				}),
			).toBe(false);
			expect(readerStates()).toEqual([]);
		});

		it("test_ingest_when_the_message_index_is_not_an_integer_then_it_is_refused", async () => {
			const { distribution } = await memberPost("ship it");

			for (const index of ["4", 1.5, true, null]) {
				expect(
					ingest(dir, MEMBER_A_ID, { ...distribution, message_index: index }),
				).toBe(false);
			}
			expect(readerStates()).toEqual([]);
		});

		it("test_ingest_when_the_key_id_is_not_a_uuid_then_it_is_refused", async () => {
			const { distribution } = await memberPost("ship it");

			// It is a map key on both stacks and a path component on neither — but a
			// reader that stores an arbitrary string here hands the next component
			// that DOES build a path from it a value nothing checked.
			expect(
				ingest(dir, MEMBER_A_ID, {
					...distribution,
					sender_key_id: "../../../etc/passwd",
				}),
			).toBe(false);
			expect(readerStates()).toEqual([]);
		});
	});
});
