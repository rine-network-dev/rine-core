/**
 * The SEND TAIL of one group's sender-key state file — the write
 * `encryptGroupMessage` makes one call after `getOrCreateSenderKey` chose the
 * key.
 *
 * `sender-key-state-race.test.ts` covers the inbound half, where a render opens
 * many rows against one file. This is its twin on the way out, and the window is
 * the same one: `getOrCreateSenderKey` fans the key out as one DM **per member**,
 * so the file can move under a single send several times over — a peer's key
 * arriving from the ingest, another holder's rotation, a `group leave` in the
 * next terminal. The send then hands its PRE-fan-out state object to
 * `encryptGroupMessage`, which writes this agent's own row back.
 *
 * 🔴 That write used to filter the row out by id and re-append it LAST, and
 * `sender-key-ops.ts` reads the last own row as the current key — so position
 * there is not cosmetic, it decides what the next send seals under. A rotation
 * landing during the fan-out retains the row it superseded BELOW the new one, so
 * the re-append moved a key this agent had already rotated away from back to
 * last and the next post went out under it; where the rotation dropped the row
 * instead, or a leave unlinked the file, the same re-append RESURRECTED it and
 * put live chain material back on disk under a group that had moved on. One
 * change closes both: replace the row where it sits, and write nothing at all if
 * it is gone.
 *
 * 🔴 The rotation case is asserted through the SELECTOR, not off the file.
 * Nothing goes missing there — only the order moves — and "the last own row" is
 * `getOrCreateSenderKey`'s rule rather than a property of the file, so a
 * file-shape assertion alone would pass a rewrite that reordered the rows and
 * read them differently. What the defect costs is *which key the group is sealed
 * under*, so that is what is measured.
 *
 * Twin: `rine-sdk/tests/test_crypto/test_sender_key_send_race.py`, same defect,
 * same fix, asserted the same way.
 */

import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentKeysResponse } from "../../src/api-types.js";
import { toBase64Url } from "../../src/crypto/keys.js";
import {
	UnpersistedSenderKeyStateError,
	encryptGroupMessage,
} from "../../src/crypto/sender-key-seal.js";
import { decryptGroupMessage } from "../../src/message-group.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
} from "../../src/crypto/sender-keys-helpers.js";
import { generateSenderKey } from "../../src/crypto/sender-keys.js";
import {
	deleteSenderKey,
	getOrCreateSenderKey,
} from "../../src/sender-key-ops.js";
import { World } from "./world.js";

const SENDER_ID = "a1b2c3d4-e5f6-4890-abcd-ef1234567890";
/** Already holds this agent's key, so the fan-out is not for it. */
const MEMBER_A_ID = "b2c3d4e5-f6a7-4901-bcde-f12345678901";
/** Seated since the last send: the one recipient each fan-out here has. */
const MEMBER_B_ID = "c3d4e5f6-a7b8-4012-cdef-123456789012";
/** Sends to the group, never a recipient — its row is what must not move. */
const PEER_ID = "e5f6a7b8-c9d0-4234-8fab-345678901234";
const GROUP_ID = "d4e5f6a7-b8c9-4123-8efa-234567890123";
const GROUP_HANDLE = "#ops@acme.rine.network";

let world: World;

/** A real org world, with every party this file names seated in `dir`. */
function setupWorld(dir: string): void {
	world = new World();
	for (const id of [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID, PEER_ID]) {
		world.save(dir, world.addAgent({ id }));
	}
}

/** `GET /agents/keys` for a fan-out, in the batch shape the server sends. */
function makeBatchKeys(agentIds: string[]) {
	const keys: Record<string, AgentKeysResponse> = {};
	for (const id of agentIds) {
		const generations = world.agents.get(id);
		const newest = generations?.[generations.length - 1];
		if (newest) keys[id] = newest.response;
	}
	return { keys };
}

/**
 * The group resolve, roster read, batch key read and distribution POST one send
 * makes — with a hook that runs INSIDE the fan-out.
 *
 * `onPost` fires once the DM is sealed and before the caller records the
 * delivery, which is the window every test here writes into. Each of these sends
 * has exactly one undistributed recipient, so it fires once.
 */
function makeClient(memberIds: string[], onPost?: () => void) {
	const base = world.client();
	return {
		get: vi.fn(
			async (
				path: string,
				params?: Record<string, string | number | boolean>,
			) => {
				if (path === "/groups") return { items: [{ id: GROUP_ID }] };
				if (path === `/groups/${GROUP_ID}/members`) {
					return {
						items: memberIds.map((id) => ({ agent_id: id, role: "member" })),
					};
				}
				if (path === "/agents/keys") {
					return makeBatchKeys(memberIds.filter((id) => id !== SENDER_ID));
				}
				return base.get(path, params);
			},
		),
		post: vi.fn(async () => {
			onPost?.();
			return { id: "dddddddd-eeee-4fff-8000-111111111111" };
		}),
	};
}

describe("the send tail's write of this agent's own row", () => {
	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-sk-send-race-"));
		setupWorld(dir);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	function statePath(): string {
		return join(dir, "keys", SENDER_ID, "sender_keys", `${GROUP_ID}.json`);
	}

	/** This agent's own rows in FILE order, which is the order the send reads. */
	function ownIds(): string[] {
		return loadSenderKeyStates(dir, SENDER_ID, GROUP_ID)
			.filter((s) => s.senderAgentId === SENDER_ID)
			.map((s) => s.senderKeyId);
	}

	it("test_own_row_when_the_tail_writes_it_back_then_it_stays_where_it_sat", async () => {
		const own = generateSenderKey(GROUP_ID, SENDER_ID);
		const peer = generateSenderKey(GROUP_ID, PEER_ID);
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [own, peer]);

		await encryptGroupMessage(dir, SENDER_ID, GROUP_ID, own, { body: "hi" });

		const rows = loadSenderKeyStates(dir, SENDER_ID, GROUP_ID);
		expect(rows.map((s) => s.senderKeyId)).toEqual([
			own.senderKeyId,
			peer.senderKeyId,
		]);
		// The row is replaced where it sits, not left alone: the advance landed.
		expect(rows[0]?.messageIndex).toBe(1);
	});

	it("test_peer_row_when_it_shares_this_agents_key_id_then_the_tail_leaves_it_alone", async () => {
		// 🔴 Matching on the key id alone made the write a whole-array `map` that
		// replaced EVERY row carrying that id with this agent's own state — so an
		// ordinary send overwrote a peer's chain key with the sender's, and the
		// peer's posts stopped opening for good. A peer may hold a row under this
		// agent's id because `ingestSenderKeyDistribution` scopes its already-held
		// check to the (sender, key) pair. Planted FIRST, so an id-only match finds
		// it. The Python twin is in `tests/test_crypto/test_sender_key_send_race.py`.
		const own = generateSenderKey(GROUP_ID, SENDER_ID);
		own.distributedTo = [MEMBER_A_ID];
		const squat = {
			...generateSenderKey(GROUP_ID, PEER_ID),
			senderKeyId: own.senderKeyId,
		};
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [squat, own]);

		await encryptGroupMessage(dir, SENDER_ID, GROUP_ID, own, { body: "hi" });

		const rows = loadSenderKeyStates(dir, SENDER_ID, GROUP_ID);
		expect(rows).toHaveLength(2);
		const peerRow = rows.find((s) => s.senderAgentId === PEER_ID);
		expect(toBase64Url(peerRow?.chainKey as Uint8Array)).toBe(
			toBase64Url(squat.chainKey),
		);
		expect(peerRow?.messageIndex).toBe(0);
		expect(rows.find((s) => s.senderAgentId === SENDER_ID)?.messageIndex).toBe(1);
	});

	it("test_delivery_when_a_peer_row_shares_this_key_id_then_it_is_recorded_on_the_own_row", async () => {
		// `recordDistribution` searched the file by key id alone, so it wrote the
		// fan-out onto whichever such row came first — a peer's — leaving this
		// agent's own row unrecorded and the next send fanning the same key out
		// again.
		const own = generateSenderKey(GROUP_ID, SENDER_ID);
		own.distributedTo = [MEMBER_A_ID];
		const squat = {
			...generateSenderKey(GROUP_ID, PEER_ID),
			senderKeyId: own.senderKeyId,
		};
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [squat, own]);
		const client = makeClient([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID]);

		const { state } = await getOrCreateSenderKey(
			client as never,
			dir,
			SENDER_ID,
			GROUP_HANDLE,
		);
		expect(state.senderKeyId).toBe(own.senderKeyId);

		const recorded: Record<string, string[]> = {};
		for (const s of loadSenderKeyStates(dir, SENDER_ID, GROUP_ID)) {
			recorded[s.senderAgentId] = [...(s.distributedTo ?? [])];
		}
		expect(recorded).toEqual({
			[PEER_ID]: [],
			[SENDER_ID]: [MEMBER_A_ID, MEMBER_B_ID],
		});
	});

	it("test_group_when_rotated_during_the_fan_out_then_the_send_tail_leaves_it_gone", async () => {
		const own = generateSenderKey(GROUP_ID, SENDER_ID);
		own.distributedTo = [MEMBER_A_ID];
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [own]);

		// The rotation's own shape, as `getOrCreateSenderKey` writes it: the new
		// key appended and exactly the one row it supersedes kept below it.
		// Already distributed, so the selection after it is a clean read with no
		// fan-out of its own.
		const replacement = generateSenderKey(GROUP_ID, SENDER_ID);
		replacement.distributedTo = [MEMBER_A_ID, MEMBER_B_ID];
		const client = makeClient([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID], () => {
			saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [own, replacement]);
		});

		const { state } = await getOrCreateSenderKey(
			client as never,
			dir,
			SENDER_ID,
			GROUP_HANDLE,
		);
		await encryptGroupMessage(dir, SENDER_ID, GROUP_ID, state, { body: "hi" });

		// The superseded row is still there — it is what lets this agent re-read
		// the post it just sent — but it stays where the rotation put it.
		expect(ownIds()).toEqual([own.senderKeyId, replacement.senderKeyId]);

		const after = makeClient([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID]);
		const { state: picked } = await getOrCreateSenderKey(
			after as never,
			dir,
			SENDER_ID,
			GROUP_HANDLE,
		);

		expect(picked.senderKeyId).toBe(replacement.senderKeyId);
		// The material, not just the label: this is what the next post is sealed
		// under, and a retired chain key here is the whole defect.
		expect(toBase64Url(picked.chainKey)).toBe(
			toBase64Url(replacement.chainKey),
		);
	});

	it("test_group_when_left_during_the_fan_out_then_the_send_tail_leaves_it_gone", async () => {
		const own = generateSenderKey(GROUP_ID, SENDER_ID);
		own.distributedTo = [MEMBER_A_ID];
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [own]);

		// A `group leave` completing while the fan-out runs. `recordDistribution`
		// already refuses to re-create the file; the tail is the second writer,
		// and it used to put this agent's live chain key back under a group it had
		// just left.
		const client = makeClient([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID], () => {
			deleteSenderKey(dir, SENDER_ID, GROUP_ID);
		});

		const { state } = await getOrCreateSenderKey(
			client as never,
			dir,
			SENDER_ID,
			GROUP_HANDLE,
		);
		expect(fs.existsSync(statePath())).toBe(false);

		await encryptGroupMessage(dir, SENDER_ID, GROUP_ID, state, { body: "hi" });

		expect(fs.existsSync(statePath())).toBe(false);
		expect(loadSenderKeyStates(dir, SENDER_ID, GROUP_ID)).toEqual([]);
	});

	it("test_own_row_when_two_rotations_dropped_it_then_the_send_tail_does_not_restore_it", async () => {
		// 🔴 The case the two above cannot see, and the one a "re-append it when the
		// file is not empty" rewrite passes both of them on: the row is GONE while
		// the file still holds other keys of this agent's.
		//
		// A rotation retains exactly the one own row it superseded, so the SECOND
		// rotation to land during a single fan-out drops the row this send is
		// holding. Re-appending it there puts a key retired two rotations ago at the
		// end of the file, and the end is where `getOrCreateSenderKey` looks — so
		// the next post goes out under it, with a `distributedTo` naming a roster
		// two rosters old. Neither the leave case (empty file) nor the single
		// rotation (row still present) distinguishes that rewrite from this one.
		const own = generateSenderKey(GROUP_ID, SENDER_ID);
		own.distributedTo = [MEMBER_A_ID];
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [own]);

		const first = generateSenderKey(GROUP_ID, SENDER_ID);
		const second = generateSenderKey(GROUP_ID, SENDER_ID);
		second.distributedTo = [MEMBER_A_ID, MEMBER_B_ID];
		const client = makeClient([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID], () => {
			saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [own, first]);
			saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [first, second]);
		});

		const { state } = await getOrCreateSenderKey(
			client as never,
			dir,
			SENDER_ID,
			GROUP_HANDLE,
		);
		await encryptGroupMessage(dir, SENDER_ID, GROUP_ID, state, { body: "hi" });

		expect(ownIds()).toEqual([first.senderKeyId, second.senderKeyId]);

		// Through the selector, because that is what the defect costs: the key the
		// next post is sealed under.
		const after = makeClient([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID]);
		const { state: picked } = await getOrCreateSenderKey(
			after as never,
			dir,
			SENDER_ID,
			GROUP_HANDLE,
		);
		expect(picked.senderKeyId).toBe(second.senderKeyId);
		expect(toBase64Url(picked.chainKey)).toBe(toBase64Url(second.chainKey));
	});
});

/**
 * The third absence: a state that was never on disk at all.
 *
 * The tail writes this agent's row back IN PLACE and writes nothing where the
 * row is gone, because gone means RETIRED — a rotation dropped it, or a `group
 * leave` unlinked the file. `encryptGroupMessage` is in the public
 * `@rine-network/core` barrel next to `generateSenderKey` and
 * `saveSenderKeyState`, so a consumer can compose the two and hand in a state
 * nothing ever wrote. Silently skipping that produces a real, transmittable
 * ciphertext whose ratchet advance and self-read key go nowhere: the sender
 * cannot re-read its own post, and the next send starts from index zero again.
 *
 * The three are told apart rather than collapsed, and each arm is held here.
 */
describe("the send tail's refusal of a state nothing persisted", () => {
	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-sk-unpersisted-"));
		setupWorld(dir);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	function statePath(): string {
		return join(dir, "keys", SENDER_ID, "sender_keys", `${GROUP_ID}.json`);
	}

	it("test_send_tail_when_the_state_was_never_persisted_then_it_refuses", async () => {
		const unsaved = generateSenderKey(GROUP_ID, SENDER_ID);

		await expect(
			encryptGroupMessage(dir, SENDER_ID, GROUP_ID, unsaved, { body: "hi" }),
		).rejects.toBeInstanceOf(UnpersistedSenderKeyStateError);
	});

	it("test_send_tail_when_the_state_was_never_persisted_then_it_creates_no_file", async () => {
		// The refusal must not leave the half-state it refused: a file created here
		// would make `senderKeyStateExists` — which a leave reads to say which
		// encryption it just retired — answer for a group holding nothing.
		const unsaved = generateSenderKey(GROUP_ID, SENDER_ID);

		await expect(
			encryptGroupMessage(dir, SENDER_ID, GROUP_ID, unsaved, { body: "hi" }),
		).rejects.toThrow();

		expect(fs.existsSync(statePath())).toBe(false);
	});

	it("test_send_tail_when_the_row_was_rotated_away_then_it_seals_without_raising", async () => {
		// Same absence, different history: this agent DOES hold keys for the group,
		// so the missing row was retired by a rotation. Silent by design — the
		// message is already sealed and its advance is only meaningful to a key
		// nobody sends under again.
		const rotatedAway = generateSenderKey(GROUP_ID, SENDER_ID);
		const current = generateSenderKey(GROUP_ID, SENDER_ID);
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [current]);

		const { result } = await encryptGroupMessage(
			dir,
			SENDER_ID,
			GROUP_ID,
			rotatedAway,
			{ body: "hi" },
		);

		expect(result.encryption_version).toBe("sender-key-v1");
		expect(
			loadSenderKeyStates(dir, SENDER_ID, GROUP_ID).map((s) => s.senderKeyId),
		).toEqual([current.senderKeyId]);
	});

	it("test_send_tail_when_the_group_was_left_then_it_seals_without_raising", async () => {
		// No own row anywhere AND a retirement marker: the group was left. Also
		// silent, and still writes nothing back.
		const own = generateSenderKey(GROUP_ID, SENDER_ID);
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [own]);
		deleteSenderKey(dir, SENDER_ID, GROUP_ID);

		const { result } = await encryptGroupMessage(dir, SENDER_ID, GROUP_ID, own, {
			body: "hi",
		});

		expect(result.encryption_version).toBe("sender-key-v1");
		expect(fs.existsSync(statePath())).toBe(false);
	});
});

/**
 * What an agent can still read of its OWN posts once its key rotates.
 *
 * The rotation retains exactly one superseded own row, and this is what that
 * retention is FOR: a sender caches its own self-read key on the row it sent
 * under, and never distributes its key to itself, so a dropped row takes every
 * own post with it — permanently, with no distribution DM for the recovery scan
 * to re-ingest and a refusal whose two explanations are both false of one's own
 * post.
 *
 * 🔴 Asserted end to end, through the public decrypt. `sender-key-ops.test.ts`
 * asserts the retained row's `skippedKeys` survive the rotation, which is the
 * mechanism; this is the property a user has — and it is what makes deleting the
 * retention fail HERE rather than only there.
 *
 * Twin: `rine-sdk/tests/test_crypto/test_sender_key_send_race.py`,
 * `TestRotationAndSelfRead`.
 */
describe("rotation and self-read", () => {
	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-sk-self-read-"));
		setupWorld(dir);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	it("test_own_post_when_the_key_rotates_then_it_still_opens", async () => {
		const own = generateSenderKey(GROUP_ID, SENDER_ID);
		own.distributedTo = [MEMBER_A_ID, MEMBER_B_ID];
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [own]);

		const seated = makeClient([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID]);
		const { state } = await getOrCreateSenderKey(
			seated as never,
			dir,
			SENDER_ID,
			GROUP_HANDLE,
		);
		const { result } = await encryptGroupMessage(dir, SENDER_ID, GROUP_ID, state, {
			body: "my own post",
		});

		// MEMBER_B is gone from the roster, which is a rotation trigger.
		const after = makeClient([SENDER_ID, MEMBER_A_ID]);
		const { state: rotated } = await getOrCreateSenderKey(
			after as never,
			dir,
			SENDER_ID,
			GROUP_HANDLE,
		);
		expect(rotated.senderKeyId).not.toBe(state.senderKeyId);

		const opened = await decryptGroupMessage(
			dir,
			SENDER_ID,
			GROUP_ID,
			result.encrypted_payload,
			after as never,
			SENDER_ID,
		);
		expect(JSON.parse(opened.plaintext as string)).toEqual({
			body: "my own post",
		});
	});
});
