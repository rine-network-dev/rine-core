import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	type ThreadRow,
	decryptThreadRow,
	decryptThreadRows,
} from "../src/crypto/thread.js";
import { OperatorWorld, SEAT_ID, statement } from "./operator-fixture.js";

describe("thread rows carry the operator class", () => {
	let w: OperatorWorld;
	beforeEach(() => {
		w = new OperatorWorld();
	});
	afterEach(() => w.close());

	async function threadRow(over: Partial<ThreadRow> = {}): Promise<ThreadRow> {
		const input = await w.consoleRow();
		return {
			id: input.rowId,
			type: "rine.v1.task_request",
			encrypted_payload: input.encryptedPayload,
			encryption_version: input.encryptionVersion,
			direction: "received",
			sender_handle: "ops@acme.rine.network",
			from_agent_id: SEAT_ID,
			created_at: "2026-10-31T11:59:00Z",
			...over,
		};
	}

	const read = (
		row: ThreadRow,
		operator: ReturnType<OperatorWorld["context"]> | null,
	) =>
		decryptThreadRow(
			w.dir,
			w.self.id,
			row,
			w.world.client() as never,
			operator,
		);

	it("test_thread_when_the_seat_sent_a_fresh_console_message_then_operator_and_the_id_rides_along", async () => {
		const entry = await read(await threadRow(), w.context());
		expect(entry.sender_class).toBe("operator");
		expect(entry.from_agent_id).toBe(SEAT_ID);
	});

	it("test_thread_when_the_same_message_is_read_again_then_operator_history", async () => {
		const row = await threadRow();
		await read(row, w.context());
		expect((await read(row, w.context())).sender_class).toBe(
			"operator_history",
		);
	});

	it.each(["held", "sender_held", "recipient_held"])(
		"test_thread_when_the_server_marked_the_row_context_only_%s_then_operator_history",
		async (mark) => {
			const entry = await read(
				await threadRow({ context_only: mark }),
				w.context(),
			);
			expect(entry.sender_class).toBe("operator_history");
		},
	);

	it("test_thread_when_no_operator_context_then_other", async () => {
		expect((await read(await threadRow(), null)).sender_class).toBe("other");
	});

	it("test_thread_when_the_row_is_one_the_agent_sent_then_other", async () => {
		const input = await w.consoleRow();
		const sent = await threadRow({
			direction: "sent",
			from_agent_id: w.self.id,
			to_agent_id: SEAT_ID,
			self_encrypted_payload: input.encryptedPayload,
		});
		expect((await read(sent, w.context())).sender_class).toBe("other");
	});

	it("test_thread_when_a_stranger_sends_a_statement_without_text_then_the_turn_shows_none", async () => {
		const forged = await w.row(
			{ body: "hello", "rine.operator": statement() },
			{},
			w.stranger,
		);
		const row = await threadRow({
			from_agent_id: w.stranger.id,
			encrypted_payload: forged.encryptedPayload,
		});
		const entry = await read(row, w.context());
		expect(entry.text).toBe('{"body":"hello"}');
		expect(entry.sender_class).toBe("other");
	});

	it("test_thread_when_an_operator_signed_row_is_an_invite_then_other_and_the_statement_is_not_used_up", async () => {
		const row = await threadRow();
		const invite = { ...row, type: "rine.v1.group_invite" };
		expect((await read(invite, w.context())).sender_class).toBe("other");
		expect((await read(row, w.context())).sender_class).toBe("operator");
	});

	it("test_thread_when_an_operator_signed_row_is_key_material_then_other_and_the_statement_is_not_used_up", async () => {
		const row = await threadRow();
		const keyFrame = { ...row, type: "rine.v1.sender_key_distribution" };
		expect((await read(keyFrame, w.context())).sender_class).toBe("other");
		expect((await read(row, w.context())).sender_class).toBe("operator");
	});

	it("test_thread_when_a_page_mixes_rows_then_each_gets_its_own_class", async () => {
		const operatorRow = await threadRow();
		const strangerRow = await threadRow({
			id: "row-2",
			from_agent_id: w.stranger.id,
		});
		const entries = await decryptThreadRows(
			w.dir,
			w.self.id,
			[operatorRow, strangerRow],
			w.world.client() as never,
			w.context(),
		);
		expect(entries.map((e) => e.sender_class)).toEqual(["operator", "other"]);
	});
});
