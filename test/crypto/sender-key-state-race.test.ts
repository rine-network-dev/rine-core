/**
 * One group's sender-key state file is a shared read-modify-write, and these
 * tests hold it to that.
 *
 * The defect they exist for: rendering a group transcript after being away came
 * back mostly `[no sender key: ask the sender to post to the group again]`, and
 * asking for the same transcript a second time showed all of it. Every row of a
 * render opens against the same file — a concurrent map had each row load the
 * array, advance its own copy and write the whole thing back, so every advance
 * but the last was discarded and a peer's key installed in the meantime went
 * with it. Nothing in any suite decrypted two group rows at once, so nothing
 * saw it.
 *
 * These drive the public decrypt/save functions, not the lock: a rewrite that
 * keeps `decryptGroupMessage`'s signature and gets the answers right passes.
 */

import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ingestSenderKeyDistribution } from "../../src/crypto/ingest.js";
import { toBase64Url } from "../../src/crypto/keys.js";
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
import { deleteSenderKey } from "../../src/sender-key-ops.js";
import { World } from "./world.js";

const READER_ID = "11111111-1111-4111-8111-111111111111";
const PEER_A_ID = "22222222-2222-4222-8222-222222222222";
const PEER_B_ID = "33333333-3333-4333-8333-333333333333";
const GROUP_ID = "44444444-4444-4444-8444-444444444444";
// One sender key id claimed by two senders — what the per-sender ingest check admits.
const SHARED_KEY_ID = "55555555-5555-4555-8555-555555555555";

let world: World;

/**
 * Answers `GET /agents/{id}/keys` from the world, and runs `onFetch` while the
 * caller awaits.
 *
 * 🔴 Concurrent callers are answered in REVERSE arrival order, and that is
 * what gives the first test below its discriminating power. Answering them FIFO
 * makes the LAST row to arrive the last row to write, and that row is the one
 * carrying the highest ratchet index — so an implementation that merges by
 * `senderKeyId` but serialises nothing records the right index by accident, and
 * the lock could be deleted against a green suite. Answering backwards makes
 * the first, lowest-index row the last writer: only a holder that reloads under
 * exclusion still gets the arithmetic right. The queue is counted `setImmediate`
 * rounds, never a wall-clock timer: an immediate round drains the microtask
 * queue, so every concurrent row has reached this point before the first one is
 * answered. Microtask ticks are NOT enough here and were tried — a row's own
 * ratchet work is microtasks too, so the two interleave and arrival order
 * survives, which is the ordering that hides the bug.
 */
function keyServer(onFetch?: () => void) {
	const base = world.client();
	let arrived = 0;
	const get = vi.fn(
		async (
			path: string,
			params?: Record<string, string | number | boolean>,
		) => {
			if (!/^\/agents\/[^/]+\/keys$/.test(path)) {
				throw new Error(`unexpected GET ${path}`);
			}
			// The window this whole file is about: real work lands between a decrypt's
			// load and its save because the decrypt goes to the network in between.
			onFetch?.();
			for (let rounds = Math.max(1, 32 - 4 * arrived++); rounds > 0; rounds--) {
				await new Promise((r) => setImmediate(r));
			}
			return base.get(path, params);
		},
	);
	return { get, post: vi.fn() } as never;
}

describe("sender-key state file under concurrent writers", () => {
	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-sk-race-"));
		world = new World();
		for (const id of [READER_ID, PEER_A_ID, PEER_B_ID]) {
			world.save(dir, world.addAgent({ id }));
		}
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	function statePath(): string {
		return join(dir, "keys", READER_ID, "sender_keys", `${GROUP_ID}.json`);
	}

	/** `count` posts from one peer, plus the state a reader needs to open them. */
	async function backlog(
		peerId: string,
		count: number,
	): Promise<{ readerState: SenderKeyState; payloads: string[] }> {
		const readerState = generateSenderKey(GROUP_ID, peerId);
		// The peer's own copy, which `encryptGroupMessage` advances in place. A
		// stand-in sender needs it as much as a real one does: the tail refuses a
		// state that is on no disk at all rather than discarding the advance. It
		// lands under the PEER's own directory, never the reader's.
		saveSenderKeyState(dir, peerId, GROUP_ID, [{ ...readerState }]);
		let state: SenderKeyState = { ...readerState };
		const payloads: string[] = [];
		for (let i = 0; i < count; i++) {
			const { result, updatedState } = await encryptGroupMessage(
				dir,
				peerId,
				GROUP_ID,
				state,
				{ text: `post ${i} from ${peerId}` },
			);
			payloads.push(result.encrypted_payload);
			state = updatedState;
		}
		return { readerState, payloads };
	}

	/**
	 * One post from A, plus a row from B claiming A's key id, on the reader's disk.
	 *
	 * Two rows sharing one `senderKeyId` is the state `ingestSenderKeyDistribution`
	 * admits ON PURPOSE: the id is minted by whoever sends it, so refusing a second
	 * row by id alone would let whoever claims a peer's id first take its slot for
	 * good. What the reader holds afterwards is exactly this — the honest peer's
	 * key, and another agent's key filed under the same name.
	 */
	async function collision(squatterLast: boolean): Promise<string> {
		const genuine: SenderKeyState = {
			...generateSenderKey(GROUP_ID, PEER_A_ID),
			senderKeyId: SHARED_KEY_ID,
		};
		saveSenderKeyState(dir, PEER_A_ID, GROUP_ID, [{ ...genuine }]);
		const { result } = await encryptGroupMessage(
			dir,
			PEER_A_ID,
			GROUP_ID,
			{ ...genuine },
			{ text: "from the honest peer" },
		);
		// A different chain key under the same name: nothing this row holds opens
		// A's post, which is what makes displacement visible rather than silent.
		const squat: SenderKeyState = {
			...generateSenderKey(GROUP_ID, PEER_B_ID),
			senderKeyId: SHARED_KEY_ID,
		};
		saveSenderKeyState(
			dir,
			READER_ID,
			GROUP_ID,
			squatterLast ? [genuine, squat] : [squat, genuine],
		);
		return result.encrypted_payload;
	}

	/** Which sender key id the reader holds for each sender. */
	function rowsBySender(): Record<string, string> {
		const out: Record<string, string> = {};
		for (const s of loadSenderKeyStates(dir, READER_ID, GROUP_ID)) {
			out[s.senderAgentId] = s.senderKeyId;
		}
		return out;
	}

	it("test_honest_post_when_a_squatted_row_landed_last_then_it_still_opens", async () => {
		// 🔴 A row from the sender the SERVER named wins the id it shares. Keyed by
		// `senderKeyId` alone the map keeps whichever row landed last, which an
		// attacker controls: it plants one, the honest peer's posts open against the
		// wrong chain key and stop rendering, and re-planting after every decrypt
		// makes it permanent. The Python twin is `TestCollidingSenderKeyIds`.
		const payload = await collision(true);

		const opened = await decryptGroupMessage(
			dir,
			READER_ID,
			GROUP_ID,
			payload,
			keyServer(),
			PEER_A_ID,
		);
		expect(JSON.parse(opened.plaintext as string)).toEqual({
			text: "from the honest peer",
		});
		// The merge is keyed by the (sender, key) pair too: keyed by the id alone it
		// would collapse the pair on load and write one of them out of existence.
		expect(rowsBySender()).toEqual({
			[PEER_A_ID]: SHARED_KEY_ID,
			[PEER_B_ID]: SHARED_KEY_ID,
		});
	});

	it("test_squatted_row_when_a_decrypt_persists_then_it_is_still_on_disk", async () => {
		// The genuine row first, so the decrypt succeeds either way: what this
		// pins is the WRITE. Asserting only the returned plaintext passes with the
		// other row already deleted.
		const payload = await collision(false);
		const before = rowsBySender();
		expect(before).toEqual({
			[PEER_A_ID]: SHARED_KEY_ID,
			[PEER_B_ID]: SHARED_KEY_ID,
		});

		await decryptGroupMessage(
			dir,
			READER_ID,
			GROUP_ID,
			payload,
			keyServer(),
			PEER_A_ID,
		);

		expect(rowsBySender()).toEqual(before);
		// The advance belongs to the row it came from, not to whoever shares its id.
		const advanced: Record<string, number> = {};
		for (const s of loadSenderKeyStates(dir, READER_ID, GROUP_ID)) {
			advanced[s.senderAgentId] = s.messageIndex;
		}
		expect(advanced).toEqual({ [PEER_A_ID]: 1, [PEER_B_ID]: 0 });
	});

	it("test_group_rows_when_decrypted_concurrently_then_every_advance_persists", async () => {
		const a = await backlog(PEER_A_ID, 3);
		const b = await backlog(PEER_B_ID, 3);
		saveSenderKeyState(dir, READER_ID, GROUP_ID, [a.readerState, b.readerState]);
		const client = keyServer();

		// The shape a render used to have. Both keys are loaded by every row before
		// any row saves — that is forced, not lucky: the load is synchronous and the
		// first await in each row comes after it, so the whole fan-out has read the
		// same array before the first write lands.
		const rows = [
			...a.payloads.map((p) => [p, PEER_A_ID] as const),
			...b.payloads.map((p) => [p, PEER_B_ID] as const),
		];
		const opened = await Promise.all(
			rows.map(([payload, from]) =>
				decryptGroupMessage(dir, READER_ID, GROUP_ID, payload, client, from),
			),
		);
		expect(opened).toHaveLength(6);

		// Three posts per sender were opened, so each sender's ratchet stands at 3.
		// A writer that asserts the whole array from a pre-network snapshot leaves
		// at most one of them advanced and the other exactly where it was loaded.
		const advanced = Object.fromEntries(
			loadSenderKeyStates(dir, READER_ID, GROUP_ID).map((s) => [
				s.senderAgentId,
				s.messageIndex,
			]),
		);
		expect(advanced).toEqual({ [PEER_A_ID]: 3, [PEER_B_ID]: 3 });
	});

	it("test_peer_key_when_ingested_during_a_decrypts_verify_then_it_survives", async () => {
		const a = await backlog(PEER_A_ID, 1);
		const b = await backlog(PEER_B_ID, 1);
		// The reader starts holding A's key only. B's arrives as its distribution DM
		// is opened — which is what `fetchAndIngestPendingSKDistributions` does while
		// a cold render is in flight.
		saveSenderKeyState(dir, READER_ID, GROUP_ID, [a.readerState]);

		let ingested = false;
		const client = keyServer(() => {
			if (ingested) return;
			ingested = true;
			const took = ingestSenderKeyDistribution(
				dir,
				READER_ID,
				"rine.v1.sender_key_distribution",
				{
					plaintext: JSON.stringify({
						group_id: GROUP_ID,
						sender_key_id: b.readerState.senderKeyId,
						chain_key: toBase64Url(b.readerState.chainKey),
						message_index: b.readerState.messageIndex,
						sender_agent_id: PEER_B_ID,
					}),
					senderKid: `rine:${PEER_B_ID}#0`,
					verified: true,
					verificationStatus: "verified",
				},
			);
			expect(took).toBe(true);
		});

		await decryptGroupMessage(
			dir,
			READER_ID,
			GROUP_ID,
			a.payloads[0] as string,
			client,
			PEER_A_ID,
		);

		// The decrypt knew about A's key and nothing else, so it must not have had
		// an opinion about B's. Losing it is exactly what makes the next row report
		// the group sealed under a key "no later message reopens" — and the render
		// after that opens it.
		expect(
			loadSenderKeyStates(dir, READER_ID, GROUP_ID)
				.map((s) => s.senderAgentId)
				.sort(),
		).toEqual([PEER_A_ID, PEER_B_ID].sort());

		// And B's key still opens B's post, which is the part a reader sees.
		const opened = await decryptGroupMessage(
			dir,
			READER_ID,
			GROUP_ID,
			b.payloads[0] as string,
			client,
			PEER_B_ID,
		);
		expect(JSON.parse(opened.plaintext as string)).toEqual({
			text: `post 0 from ${PEER_B_ID}`,
		});
	});

	it("test_group_when_retired_during_a_decrypts_verify_then_the_wipe_holds", async () => {
		const a = await backlog(PEER_A_ID, 1);
		saveSenderKeyState(dir, READER_ID, GROUP_ID, [a.readerState]);

		// A leave lands while a render is parked on its sender-key fetch: one
		// terminal running `group leave` against the config dir another is reading.
		// The decrypt loaded this peer's chain key before the wipe and is still
		// holding it, so its save is the one writer that can put retired key
		// material back on disk — and the retirement marker does not stop it,
		// because the marker only refuses INGESTS.
		const client = keyServer(() => {
			deleteSenderKey(dir, READER_ID, GROUP_ID);
		});

		await decryptGroupMessage(
			dir,
			READER_ID,
			GROUP_ID,
			a.payloads[0] as string,
			client,
			PEER_A_ID,
		);

		// "Retiring the group is removing that file" has to survive the writer that
		// was already running, or a leave is undone by whatever was in flight.
		expect(fs.existsSync(statePath())).toBe(false);
		expect(loadSenderKeyStates(dir, READER_ID, GROUP_ID)).toEqual([]);
	});

	it("test_own_row_when_a_rotation_drops_it_during_a_self_read_then_the_merge_leaves_it_gone", async () => {
		// 🔴 The merge's asymmetry, driven through the REAL path rather than a
		// hand-built array: `decryptGroupMessage` loads inside the lock, goes to the
		// network to verify, and merges its pre-network row back afterwards. A
		// rotation runs on another thread of control in that window — on Python
		// literally another thread, since the send is `asyncio.to_thread` and an
		// `asyncio.Lock` cannot exclude it — and rotations DROP own rows.
		//
		// The merge is keyed by id over a map seeded from disk, so a row that is no
		// longer on disk would be INSERTED, and insertion means last. Last is
		// exactly where `sender-key-ops.ts` looks for the current key, so the
		// resurrected row becomes what the next post is sealed under: a key this
		// agent rotated away from, whose `distributedTo` names a roster that has
		// moved on. Peer rows must still be added — that is the merge's whole
		// purpose, and the peer-ingest test above holds it to that.
		const own = generateSenderKey(GROUP_ID, READER_ID);
		saveSenderKeyState(dir, READER_ID, GROUP_ID, [own]);
		const { result } = await encryptGroupMessage(dir, READER_ID, GROUP_ID, own, {
			text: "my own post",
		});

		// Where two rotations leave the file: each keeps exactly the one own row it
		// superseded, so the second one drops `own` altogether while the file stays
		// non-empty. The decrypt below is still holding `own` — it loaded before
		// either of them landed.
		const first = generateSenderKey(GROUP_ID, READER_ID);
		const second = generateSenderKey(GROUP_ID, READER_ID);
		let rotated = false;
		const client = keyServer(() => {
			if (rotated) return;
			rotated = true;
			saveSenderKeyState(dir, READER_ID, GROUP_ID, [own, first]);
			saveSenderKeyState(dir, READER_ID, GROUP_ID, [first, second]);
		});

		const opened = await decryptGroupMessage(
			dir,
			READER_ID,
			GROUP_ID,
			result.encrypted_payload,
			client,
			READER_ID,
		);
		expect(JSON.parse(opened.plaintext as string)).toEqual({
			text: "my own post",
		});

		// The rotation's file, unchanged: the retired row is not back, and the row
		// the next send picks is still the one the rotation minted.
		const after = loadSenderKeyStates(dir, READER_ID, GROUP_ID);
		expect(after.map((s) => s.senderKeyId)).toEqual([
			first.senderKeyId,
			second.senderKeyId,
		]);
		expect(after[after.length - 1]?.senderKeyId).toBe(second.senderKeyId);
	});

	it("test_state_save_when_it_rewrites_the_file_then_no_reader_sees_a_partial_one", async () => {
		const a = await backlog(PEER_A_ID, 1);
		const b = await backlog(PEER_B_ID, 1);
		saveSenderKeyState(dir, READER_ID, GROUP_ID, [a.readerState]);

		// A second name for the bytes a concurrent reader already has open. If the
		// save writes through the existing file it is visible here mid-write, which
		// is the same file a crash would leave truncated; if it lands in a sidecar
		// and renames, this name keeps the whole previous version.
		const asOpenedBefore = `${statePath()}.observer`;
		fs.linkSync(statePath(), asOpenedBefore);

		saveSenderKeyState(dir, READER_ID, GROUP_ID, [a.readerState, b.readerState]);

		expect(JSON.parse(fs.readFileSync(asOpenedBefore, "utf-8"))).toHaveLength(1);
		expect(loadSenderKeyStates(dir, READER_ID, GROUP_ID)).toHaveLength(2);
		// Nothing half-written left beside it either.
		expect(
			fs
				.readdirSync(join(dir, "keys", READER_ID, "sender_keys"))
				.filter((f) => f.endsWith(".tmp")),
		).toEqual([]);
	});
});
