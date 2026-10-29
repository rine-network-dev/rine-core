import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { A2A_CLEARTEXT_NOTICE } from "../../src/a2a-cleartext.js";
import { encryptMessage } from "../../src/crypto/message.js";
import { encryptGroupMessage } from "../../src/crypto/sender-key-seal.js";
import { saveSenderKeyState } from "../../src/crypto/sender-keys-helpers.js";
import { generateSenderKey } from "../../src/crypto/sender-keys.js";
import {
	THREAD_UNAVAILABLE,
	type ThreadRow,
	decryptThreadRow,
	decryptThreadRows,
	renderThreadText,
} from "../../src/crypto/thread.js";
import { SENDER_KEY_UNAVAILABLE_PREVIEW } from "../../src/sender-key-words.js";
import { World, type WorldAgent } from "./world.js";

const SENDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const RECIPIENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const THIRD_PARTY_ID = "c3d4e5f6-a7b8-9012-cdef-123456789013";
const GROUP_ID = "d4e5f6a7-b8c9-0123-defa-234567890124";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-thread-test-"));
}

/** The recipient's chain-verified encryption keys, as `fetchRecipientKeys` returns them. */
function recipientKeysOf(agent: WorldAgent) {
	return {
		encryption: agent.derived.x25519.publicKey,
		pqEncryption: agent.derived.mlKem768.publicKey,
	};
}

/** A world client whose `get` is a spy, so a test can count key lookups. */
function clientWith(world: World) {
	const base = world.client();
	// No `keyCache`: every row really goes to the network for its sender's key,
	// which is what the sequential-render test measures.
	return { get: vi.fn(base.get), post: base.post };
}

const baseRow = (over: Partial<ThreadRow>): ThreadRow => ({
	type: "rine.v1.task_request",
	encrypted_payload: "",
	encryption_version: "hpke-hybrid-v2",
	created_at: "2026-06-20T00:00:00Z",
	...over,
});

// The row classifier, exercised through the single-row entry point. No surface
// calls `decryptThreadRow` any more — the CLI's `message thread` and MCP's
// `rine_thread` both go through the plural — so the label that called it "the
// shared CLI/MCP helper" pointed nine tests at a claim that had stopped being
// true. What they measure is still the production path: the plural's per-row
// work IS this function.
describe("decryptThreadRow (the row classifier, one row at a time)", () => {
	let dir: string;
	let world: World;
	let recipient: WorldAgent;

	beforeEach(() => {
		dir = makeTmpDir();
		world = new World();
		world.save(dir, world.addAgent({ id: SENDER_ID }));
		recipient = world.addAgent({ id: RECIPIENT_ID });
		world.save(dir, recipient);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("decrypts the self-blob for a direction:sent 1:1 row", async () => {
		const enc = await encryptMessage(
			dir,
			SENDER_ID,
			RECIPIENT_ID,
			recipientKeysOf(recipient),
			{ text: "from me" },
		);
		const row = baseRow({
			direction: "sent",
			sender_handle: "me@org",
			to_agent_id: RECIPIENT_ID,
			encrypted_payload: enc.encrypted_payload,
			self_encrypted_payload: enc.self_encrypted_payload,
		});
		const entry = await decryptThreadRow(
			dir,
			SENDER_ID,
			row,
			clientWith(world) as never,
		);
		expect(entry.direction).toBe("sent");
		expect(entry.text).toBe("from me");
		expect(entry.verification_status).toBe("verified");
	});

	it("decrypts encrypted_payload for a direction:received row", async () => {
		const enc = await encryptMessage(
			dir,
			SENDER_ID,
			RECIPIENT_ID,
			recipientKeysOf(recipient),
			{ text: "to you" },
		);
		const row = baseRow({
			direction: "received",
			sender_handle: "alice@org",
			from_agent_id: SENDER_ID,
			encrypted_payload: enc.encrypted_payload,
		});
		const entry = await decryptThreadRow(
			dir,
			RECIPIENT_ID,
			row,
			clientWith(world) as never,
		);
		expect(entry.direction).toBe("received");
		expect(entry.sender_handle).toBe("alice@org");
		expect(entry.text).toBe("to you");
		expect(entry.verification_status).toBe("verified");
	});

	it("renders [unavailable] for a sent row with no self-blob (legacy)", async () => {
		const enc = await encryptMessage(
			dir,
			SENDER_ID,
			RECIPIENT_ID,
			recipientKeysOf(recipient),
			{ text: "legacy" },
		);
		const row = baseRow({
			direction: "sent",
			encrypted_payload: enc.encrypted_payload,
			self_encrypted_payload: null,
		});
		const entry = await decryptThreadRow(
			dir,
			SENDER_ID,
			row,
			clientWith(world) as never,
		);
		expect(entry.text).toBe(THREAD_UNAVAILABLE);
	});

	it("fails closed to [unavailable] for an undecryptable row", async () => {
		// A received row the caller has no key for: garbage ciphertext → throw → degrade.
		const row = baseRow({
			direction: "received",
			from_agent_id: SENDER_ID,
			encrypted_payload: "AAAA",
		});
		const entry = await decryptThreadRow(
			dir,
			RECIPIENT_ID,
			row,
			clientWith(world) as never,
		);
		expect(entry.text).toBe(THREAD_UNAVAILABLE);
		expect(entry.verification_status).toBe("unverifiable");
	});

	it("degrades a received row that carries no authenticated sender", async () => {
		// Nothing to check the envelope's claim of authorship against, so the turn is
		// never rendered as trusted content.
		const enc = await encryptMessage(
			dir,
			SENDER_ID,
			RECIPIENT_ID,
			recipientKeysOf(recipient),
			{ text: "who sent this?" },
		);
		const row = baseRow({
			direction: "received",
			encrypted_payload: enc.encrypted_payload,
		});
		const client = clientWith(world);

		const entry = await decryptThreadRow(
			dir,
			RECIPIENT_ID,
			row,
			client as never,
		);

		expect(entry.text).toBe(THREAD_UNAVAILABLE);
		expect(entry.verification_status).toBe("unverifiable");
		expect(client.get).not.toHaveBeenCalled();
	});

	it("degrades a received row whose envelope names another agent", async () => {
		const enc = await encryptMessage(
			dir,
			SENDER_ID,
			RECIPIENT_ID,
			recipientKeysOf(recipient),
			{ text: "release the funds" },
		);
		// Genuinely signed by SENDER_ID, but the server says a third agent sent it.
		const row = baseRow({
			direction: "received",
			from_agent_id: THIRD_PARTY_ID,
			encrypted_payload: enc.encrypted_payload,
		});

		const entry = await decryptThreadRow(
			dir,
			RECIPIENT_ID,
			row,
			clientWith(world) as never,
		);

		expect(entry.text).toBe(THREAD_UNAVAILABLE);
		expect(entry.verification_status).toBe("sender-mismatch");
	});

	it("degrades a group row whose envelope names another agent", async () => {
		// The group decrypt refuses by throwing, so the verdict has to survive the
		// catch: an operator doing forensics must not read an active misattribution
		// as the transient key-lookup miss every other failure here is.
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		// The sender's own copy, which `encryptGroupMessage` advances in place. A
		// stand-in sender needs it as much as a real one does: the tail refuses a
		// state that is on no disk at all rather than discarding the advance.
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [state]);
		const { result: enc } = await encryptGroupMessage(
			dir,
			SENDER_ID,
			GROUP_ID,
			state,
			{ text: "approve the transfer" },
		);
		saveSenderKeyState(dir, RECIPIENT_ID, GROUP_ID, [state]);
		const row = baseRow({
			direction: "received",
			from_agent_id: THIRD_PARTY_ID,
			group_id: GROUP_ID,
			encryption_version: "sender-key-v1",
			encrypted_payload: enc.encrypted_payload,
		});

		const entry = await decryptThreadRow(
			dir,
			RECIPIENT_ID,
			row,
			clientWith(world) as never,
		);

		expect(entry.text).toBe(THREAD_UNAVAILABLE);
		expect(entry.verification_status).toBe("sender-mismatch");
	});

	it("renders a group row from a peer", async () => {
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [state]);
		const { result: enc } = await encryptGroupMessage(
			dir,
			SENDER_ID,
			GROUP_ID,
			state,
			{ text: "group hello" },
		);
		saveSenderKeyState(dir, RECIPIENT_ID, GROUP_ID, [state]);
		const row = baseRow({
			direction: "received",
			from_agent_id: SENDER_ID,
			group_id: GROUP_ID,
			encryption_version: "sender-key-v1",
			encrypted_payload: enc.encrypted_payload,
		});

		const entry = await decryptThreadRow(
			dir,
			RECIPIENT_ID,
			row,
			clientWith(world) as never,
		);

		expect(entry.text).toBe("group hello");
		expect(entry.verification_status).toBe("verified");
	});

	/**
	 * A group row this agent has no sender key for, with the recovery scan
	 * answering empty — so the one-shot fetch has had its turn and come back
	 * with nothing, which is what makes the refusal a verdict.
	 */
	async function unopenableGroupRow(): Promise<ThreadRow> {
		const state = generateSenderKey(GROUP_ID, SENDER_ID);
		saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [state]);
		const { result: enc } = await encryptGroupMessage(
			dir,
			SENDER_ID,
			GROUP_ID,
			state,
			{ text: "you cannot read this" },
		);
		// Deliberately no saveSenderKeyState for RECIPIENT_ID.
		return baseRow({
			direction: "received",
			from_agent_id: SENDER_ID,
			group_id: GROUP_ID,
			encryption_version: "sender-key-v1",
			encrypted_payload: enc.encrypted_payload,
		});
	}

	/** `clientWith`, plus an empty pending-distribution inbox for the recovery. */
	function clientWithNoDistributions(world: World) {
		const base = world.client();
		const get = vi.fn(async (path: string, params?: Record<string, string | number | boolean>) => {
			if (path.endsWith("/messages")) return { items: [] };
			return base.get(path, params);
		});
		return { ...base, get };
	}

	it("names the cause and the move for a row whose sender key never arrived", async () => {
		// One row asked for, so the whole sentence: `[unavailable]` named neither
		// the cause nor the one thing that fixes it.
		const entry = await decryptThreadRow(
			dir,
			RECIPIENT_ID,
			await unopenableGroupRow(),
			clientWithNoDistributions(world) as never,
		);

		expect(entry.text).toContain("sealed under sender key");
		expect(entry.text).toContain("post to the group again");
		expect(entry.text).not.toBe(THREAD_UNAVAILABLE);
		// The library's control string is never what a reader is handed.
		expect(entry.text).not.toContain("unknown sender key id");
		// A closed four-value enum, and no signature was ever checked here.
		expect(entry.verification_status).toBe("unverifiable");
	});

	it("explains the missing sender key once per render, then marks", async () => {
		const rows = [
			await unopenableGroupRow(),
			await unopenableGroupRow(),
			await unopenableGroupRow(),
		];

		const entries = await decryptThreadRows(
			dir,
			RECIPIENT_ID,
			rows,
			clientWithNoDistributions(world) as never,
		);

		expect(entries[0]?.text).toContain("sealed under sender key");
		expect(entries[1]?.text).toBe(SENDER_KEY_UNAVAILABLE_PREVIEW);
		expect(entries[2]?.text).toBe(SENDER_KEY_UNAVAILABLE_PREVIEW);
		// The bounded marker names no id, no group and no agent.
		expect(entries[1]?.text).not.toContain(GROUP_ID);
	});

	it("explains again on the next render (the state is not module-global)", async () => {
		const rows = [await unopenableGroupRow(), await unopenableGroupRow()];
		const client = clientWithNoDistributions(world) as never;

		const first = await decryptThreadRows(dir, RECIPIENT_ID, rows, client);
		const second = await decryptThreadRows(dir, RECIPIENT_ID, rows, client);

		expect(first[0]?.text).toContain("sealed under sender key");
		expect(second[0]?.text).toContain("sealed under sender key");
		expect(second[1]?.text).toBe(SENDER_KEY_UNAVAILABLE_PREVIEW);
	});

	it("does not pool the explanation with any other unavailable cause", async () => {
		// A row with no authenticated sender keeps `[unavailable]` and does not
		// spend the render's one explanation.
		const rows = [
			baseRow({ direction: "received", encrypted_payload: "AAAA" }),
			await unopenableGroupRow(),
			await unopenableGroupRow(),
		];

		const entries = await decryptThreadRows(
			dir,
			RECIPIENT_ID,
			rows,
			clientWithNoDistributions(world) as never,
		);

		expect(entries[0]?.text).toBe(THREAD_UNAVAILABLE);
		expect(entries[1]?.text).toContain("sealed under sender key");
		expect(entries[2]?.text).toBe(SENDER_KEY_UNAVAILABLE_PREVIEW);
	});

	it("test_render_when_it_has_many_rows_then_they_decrypt_one_at_a_time", async () => {
		// The render is sequential, and it is the ONLY thing asserting that. Every
		// row of a group render opens against one ratchet in one state file, and a
		// concurrent map over the rows is what produced a mostly-sealed transcript
		// on the first read and a readable one on the second. The state file now
		// carries its own lock, which is precisely why this needs a gate of its
		// own: with the lock in place a parallel render is no longer WRONG, so a
		// reader who finds this loop slow can restore the fan-out and every other
		// test in both stacks stays green.
		const rows: ThreadRow[] = [];
		for (let i = 0; i < 4; i++) {
			const enc = await encryptMessage(
				dir,
				SENDER_ID,
				RECIPIENT_ID,
				recipientKeysOf(recipient),
				{ text: `row ${i}` },
			);
			rows.push(
				baseRow({
					direction: "received",
					from_agent_id: SENDER_ID,
					encrypted_payload: enc.encrypted_payload,
				}),
			);
		}

		const client = clientWith(world);
		const answer = client.get.getMockImplementation();
		if (!answer) throw new Error("clientWith must install an implementation");
		let inFlight = 0;
		let peak = 0;
		client.get.mockImplementation(async (path: string) => {
			inFlight++;
			peak = Math.max(peak, inFlight);
			// One immediate round drains the microtask queue, so every row a
			// concurrent render would already have started is counted before this
			// answer lands. Counted rounds, not a wall-clock timer.
			await new Promise((r) => setImmediate(r));
			inFlight--;
			return answer(path);
		});

		const entries = await decryptThreadRows(
			dir,
			RECIPIENT_ID,
			rows,
			client as never,
		);

		expect(entries.map((e) => e.text)).toEqual([
			"row 0",
			"row 1",
			"row 2",
			"row 3",
		]);
		// Every row went to the network for its sender's key — so the per-row work
		// is not the "local AEAD open" it reads like, and the loop is what keeps
		// those verifies from overlapping.
		expect(client.get).toHaveBeenCalledTimes(4);
		expect(peak).toBe(1);
	});

	it("unwraps the {text} payload shape (parity with the SDK render contract)", async () => {
		const enc = await encryptMessage(
			dir,
			SENDER_ID,
			RECIPIENT_ID,
			recipientKeysOf(recipient),
			{ text: "hello world" },
		);
		const row = baseRow({
			direction: "received",
			from_agent_id: SENDER_ID,
			encrypted_payload: enc.encrypted_payload,
		});
		const entry = await decryptThreadRow(
			dir,
			RECIPIENT_ID,
			row,
			clientWith(world) as never,
		);
		expect(entry.text).toBe("hello world");
	});

	it("test_thread_row_when_a2a_cleartext_then_readable_led_by_notice_and_unverifiable", async () => {
		// The server sets the sender on every A2A row, and the body is the posted
		// parts in unpadded base64url — no keys exist for it, so none are looked up.
		const row = baseRow({
			type: "rine.v1.a2a_message",
			encryption_version: "none",
			from_agent_id: SENDER_ID,
			encrypted_payload: Buffer.from('[{"text": "plain"}]').toString("base64url"),
		});
		const client = clientWith(world);

		const [entry] = await decryptThreadRows(dir, RECIPIENT_ID, [row], client as never);

		expect(entry?.text).toBe(`[${A2A_CLEARTEXT_NOTICE}] [{"text":"plain"}]`);
		expect(entry?.verification_status).toBe("unverifiable");
		expect(client.get).not.toHaveBeenCalled();
	});

	it("test_thread_row_when_the_none_row_is_not_a2a_then_it_stays_unavailable", async () => {
		const row = baseRow({
			encryption_version: "none",
			from_agent_id: SENDER_ID,
			encrypted_payload: Buffer.from('{"text":"x"}').toString("base64url"),
		});

		const entry = await decryptThreadRow(dir, RECIPIENT_ID, row, clientWith(world) as never);

		expect(entry.text).toBe(THREAD_UNAVAILABLE);
	});
});

describe("renderThreadText (content-type-gated SDK parity)", () => {
	it("unwraps {text} for an application/json body (the default)", () => {
		expect(renderThreadText('{"text":"hi"}')).toBe("hi");
		expect(renderThreadText('{"text":"hi"}', "application/json")).toBe("hi");
		expect(renderThreadText('{"text":"hi"}', null)).toBe("hi");
	});

	it("surfaces a non-JSON content type verbatim, even if it looks like JSON", () => {
		// SDK `autoParsePlaintext` only parses application/json — text/plain is raw.
		expect(renderThreadText('{"text":"hi"}', "text/plain")).toBe('{"text":"hi"}');
		expect(renderThreadText("plain body", "text/plain")).toBe("plain body");
	});

	it("normalizes a JSON object with no text key via JSON.stringify (SDK renderText)", () => {
		// Whitespace is normalized to match the SDK's stringify, not the raw input.
		expect(renderThreadText('{ "a": 1 }')).toBe('{"a":1}');
	});

	it("returns a JSON string scalar unwrapped", () => {
		expect(renderThreadText('"bare"')).toBe("bare");
	});

	it("returns malformed JSON (claimed application/json) as the raw string", () => {
		expect(renderThreadText("{not json")).toBe("{not json");
	});
});
