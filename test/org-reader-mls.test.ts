import { randomUUID } from "node:crypto";
import type { EpochReader } from "@rine-network/mls";
import { describe, expect, it, vi } from "vitest";
import { EscrowBook, type EpochCopies } from "../src/org-reader/escrow-book.js";
import {
	escrowForged,
	escrowInvalid,
	forkUnmatched,
	keysUnavailable,
	memberRejected,
	noEscrow,
	ratchetGap,
	unreadable,
} from "../src/org-reader/gaps.js";
import { ReaderNetworkError } from "../src/org-reader/fetch-budget.js";
import { EpochReaderCache } from "../src/org-reader/mls-open.js";
import { MlsReader } from "../src/org-reader/mls.js";
import { jsonResponse } from "./org-reader-client-fixture.js";
import {
	EARLY,
	EPOCH,
	escrowRowOf,
	closedGroupSuite,
	foreignPlaintext,
	foundGroup,
	serveEscrow,
} from "./org-reader-mls-fixture.js";
import { native, nativeError } from "./org-reader-native-seam.js";
import { contextFor, orgWorld } from "./org-reader-world.js";

vi.mock("@rine-network/mls", async (importActual) => {
	const { wrapNative } = await import("./org-reader-native-seam.js");
	return wrapNative(await importActual<typeof import("@rine-network/mls")>());
});

// A stale addon without the epoch reader would read as a gap on every message.
it("has_the_epoch_reader_in_the_addon", async () => {
	const { EpochReader } =
		await vi.importActual<typeof import("@rine-network/mls")>(
			"@rine-network/mls",
		);
	expect([typeof EpochReader, typeof EpochReader.fromEscrow]).toEqual([
		"function",
		"function",
	]);
});

const { world, key, group, goodRow, setup, read } = closedGroupSuite();

describe("MlsReader.open", () => {
	it("opens_a_member_message_by_escrow_and_verifies_its_sender", async () => {
		const s = setup();
		const message = await read(s, group.rowFor(group.send("hello group")));
		expect(message.text).toBe("hello group");
		expect(message.verification).toBeNull();
		expect(message.gap).toBeNull();
		expect(message.epoch).toBe(EPOCH);
		expect(message.slot).not.toBeNull();
		expect(s.reader.findings).toEqual([]);
	});

	it("accepts_a_signer_key_from_a_past_generation", async () => {
		const own = orgWorld();
		const founded = foundGroup(own.world);
		try {
			own.world.addAgent({ id: founded.sender.id, gen: 1 });
			const ctx = contextFor(own.key, [own.world]);
			serveEscrow(ctx, [
				escrowRowOf(
					own.world,
					founded.founder,
					founded.groupId,
					founded.exported,
				),
			]);
			const row = {
				...founded.rowFor(founded.send("before the rotation")),
				createdAt: EARLY,
				createdAtMicros: Date.parse(EARLY) * 1000,
			};
			ctx.pinRow(row);
			const reader = new MlsReader(ctx, new EpochReaderCache());
			await reader.prepare([row]);
			expect((await reader.open(row)).text).toBe("before the rotation");
		} finally {
			founded.remove();
		}
	});

	it("withholds_a_message_whose_signing_leaf_is_not_the_named_senders", async () => {
		const s = setup();
		const row = group.rowFor(group.send("who sent this"), group.founder);
		expect((await read(s, row)).gap).toEqual(memberRejected(EPOCH));
	});

	it("names_the_epoch_when_no_escrow_covers_it", async () => {
		const s = setup([]);
		expect((await read(s, group.rowFor(group.send("x")))).gap).toEqual(
			noEscrow(EPOCH),
		);
	});

	it("is_unreadable_when_the_header_names_another_group", async () => {
		const s = setup();
		const row = { ...group.rowFor(group.send("x")), groupId: randomUUID() };
		expect((await read(s, row)).gap).toEqual(unreadable());
	});

	it("is_unreadable_when_the_group_id_is_no_uuid", async () => {
		const s = setup();
		const row = { ...group.rowFor(group.send("x")), groupId: "not-a-group" };
		expect((await read(s, row)).gap).toEqual(unreadable());
	});

	it("is_unreadable_when_the_payload_has_no_readable_header", async () => {
		const s = setup();
		const row = group.rowFor(Uint8Array.of(4, 0, 1, 0));
		expect((await read(s, row)).gap).toEqual(unreadable());
	});

	it("reports_a_forged_escrow_once_however_often_it_is_read", async () => {
		const forged = { ...goodRow(), uploader_sig: goodRow().sealed };
		const s = setup([forged]);
		const row = group.rowFor(group.send("x"));
		expect((await read(s, row)).gap).toEqual(escrowForged(EPOCH));
		await s.reader.open(row);
		expect(s.reader.findings).toEqual([{ groupId: group.groupId, gap: escrowForged(EPOCH) }]);
	});

	it("reports_the_same_gap_once_per_group", async () => {
		const other = foundGroup(world);
		try {
			const forge = (g: typeof group) => {
				const row = escrowRowOf(world, g.founder, g.groupId, g.exported);
				return { ...row, uploader_sig: row.sealed };
			};
			const rows = new Map([
				[group.groupId, [forge(group)]],
				[other.groupId, [forge(other)]],
			]);
			const s = setup();
			vi.spyOn(s.ctx.client, "escrowRows").mockImplementation(
				async (groupId) => ({ rows: rows.get(groupId) ?? [], complete: true }),
			);
			for (const g of [group, other]) await read(s, g.rowFor(g.send("x")));
			expect(s.reader.findings).toEqual([
				{ groupId: group.groupId, gap: escrowForged(EPOCH) },
				{ groupId: other.groupId, gap: escrowForged(EPOCH) },
			]);
		} finally {
			other.remove();
		}
	});

	it("names_an_uploader_whose_signed_copy_does_not_open_the_message", async () => {
		const liar = world.addAgent();
		const copy = (uploader: typeof liar, plaintext: Uint8Array, byte: number) =>
			escrowRowOf(world, uploader, group.groupId, {
				epoch: EPOCH,
				fp: new Uint8Array(16).fill(byte),
				plaintext,
			});
		const row = group.rowFor(group.send("still readable"));
		const withHonest = setup([goodRow(), copy(liar, foreignPlaintext, 9)]);
		expect((await read(withHonest, row)).text).toBe("still readable");
		expect(withHonest.reader.findings).toEqual([{ groupId: group.groupId, gap: escrowInvalid(EPOCH, liar.id) }]);
		const alone = setup([copy(liar, foreignPlaintext, 9)]);
		expect((await read(alone, row)).gap).toEqual(escrowInvalid(EPOCH, liar.id));
	});

	it("tries_every_good_copy_of_the_epoch", async () => {
		const second = world.addAgent();
		const s = setup([
			goodRow(),
			escrowRowOf(world, second, group.groupId, group.exported),
		]);
		const message = await read(s, group.rowFor(group.send("twice")));
		expect(message.text).toBe("twice");
		expect(native.opened).toBe(2);
		expect(s.cache.size).toBe(2);
	});

	it("withholds_when_a_copy_of_the_same_fork_rejects_what_another_opened", async () => {
		const second = world.addAgent();
		const s = setup([
			goodRow(),
			escrowRowOf(world, second, group.groupId, group.exported),
		]);
		native.opens.push(undefined, nativeError("RINE_MLS_MEMBER_REJECTED"));
		expect((await read(s, group.rowFor(group.send("x")))).gap).toEqual(
			memberRejected(EPOCH),
		);
	});

	it("ignores_a_rejecting_copy_of_another_fork", async () => {
		const second = world.addAgent();
		const s = setup([
			goodRow(),
			escrowRowOf(world, second, group.groupId, {
				...group.exported,
				fp: new Uint8Array(16).fill(5),
			}),
		]);
		native.opens.push(undefined, nativeError("RINE_MLS_MEMBER_REJECTED"));
		expect((await read(s, group.rowFor(group.send("fork")))).text).toBe("fork");
	});

	it("keeps_one_finding_for_the_same_uploader_and_epoch_across_messages", async () => {
		const liar = world.addAgent();
		const s = setup([
			goodRow(),
			escrowRowOf(world, liar, group.groupId, {
				epoch: EPOCH,
				fp: new Uint8Array(16).fill(9),
				plaintext: foreignPlaintext,
			}),
		]);
		const rows = [group.send("a"), group.send("b")].map((c) => group.rowFor(c));
		await s.reader.prepare(rows);
		for (const row of rows) await s.reader.open(row);
		expect(s.reader.findings).toEqual([{ groupId: group.groupId, gap: escrowInvalid(EPOCH, liar.id) }]);
	});
});

describe("MlsReader native error routing", () => {
	it.each([
		["RINE_MLS_MEMBER_REJECTED", memberRejected(EPOCH)],
		["RINE_MLS_GENERATION_TOO_FAR", ratchetGap(group.sender.id, null)],
		["RINE_MLS_INVALID_ESCROW", escrowInvalid(EPOCH, group.founder.id)],
		["RINE_MLS_PROTOCOL", forkUnmatched(EPOCH)],
	])("routes_%s_to_its_gap", async (code, gap) => {
		const s = setup();
		native.opens.push(nativeError(code));
		expect((await read(s, group.rowFor(group.send("x")))).gap).toEqual(gap);
	});
});

describe("MlsReader rebuild and retry", () => {
	async function cachedRead() {
		const s = setup();
		const row = group.rowFor(group.send("again"));
		expect((await read(s, row)).text).toBe("again");
		native.opens = [];
		return { s, row, next: () => new MlsReader(s.ctx, s.cache) };
	}

	it("rebuilds_a_cached_reader_that_fails_and_opens_the_message", async () => {
		const { s, row, next } = await cachedRead();
		native.opens.push(nativeError("RINE_MLS_GENERATION_TOO_FAR"));
		expect((await read(s, row, next())).text).toBe("again");
		expect(native.built).toBe(2);
		expect(native.opened).toBe(3);
	});

	it("rebuilds_for_a_message_the_cached_reader_has_already_opened", async () => {
		const { s, row, next } = await cachedRead();
		expect((await read(s, row, next())).text).toBe("again");
		expect(native.built).toBe(2);
	});

	it("does_not_rebuild_after_a_refused_signature", async () => {
		const { s, row, next } = await cachedRead();
		native.opens.push(nativeError("RINE_MLS_MEMBER_REJECTED"));
		expect((await read(s, row, next())).gap).toEqual(memberRejected(EPOCH));
		expect(native.built).toBe(1);
	});

	it("does_not_retry_a_reader_built_for_this_message", async () => {
		const s = setup();
		native.opens.push(nativeError("RINE_MLS_GENERATION_TOO_FAR"), undefined);
		const message = await read(s, group.rowFor(group.send("x")));
		expect(message.gap).toEqual(ratchetGap(group.sender.id, null));
		expect(native.opened).toBe(1);
		expect(s.cache.size).toBe(0);
	});

	it("keeps_no_reader_for_an_epoch_that_ended_in_a_gap", async () => {
		const s = setup();
		const row = group.rowFor(group.send("who sent this"), group.founder);
		expect((await read(s, row)).gap).toEqual(memberRejected(EPOCH));
		expect(s.cache.size).toBe(0);
	});

	it("keeps_no_reader_for_an_epoch_gapped_by_unavailable_signer_keys", async () => {
		const s = setup();
		const row = group.rowFor(group.send("x"));
		s.ctx.pinRow(row);
		await s.reader.prepare([row]);
		vi.spyOn(s.ctx.client, "agentKeys").mockRejectedValue(
			new ReaderNetworkError("the request failed"),
		);
		expect((await s.reader.open(row)).gap).toEqual(keysUnavailable(EPOCH));
		expect(s.cache.size).toBe(0);
	});

	it("keeps_no_reader_for_an_epoch_that_opened_when_only_the_sender_keys_failed", async () => {
		const ctx = contextFor(key, [world], (agentId) =>
			agentId === group.sender.id
				? jsonResponse({ error: "busy" }, 503)
				: undefined,
		);
		serveEscrow(ctx, [goodRow()]);
		const cache = new EpochReaderCache();
		const row = group.rowFor(group.send("x"));
		ctx.pinRow(row);
		const reader = new MlsReader(ctx, cache);
		await reader.prepare([row]);
		const message = await reader.open(row);
		expect(message.gap).toEqual(keysUnavailable(EPOCH));
		expect(native.opened).toBe(1);
		expect(cache.size).toBe(0);
	});

	it("keeps_no_reader_for_an_epoch_no_copy_opened", async () => {
		const s = setup([]);
		await read(s, group.rowFor(group.send("x")));
		expect(s.cache.size).toBe(0);
		expect(native.built).toBe(0);
	});
});

describe("MlsReader.release", () => {
	it("zeroes_the_escrow_plaintexts_the_read_held", async () => {
		const copied: EpochCopies[] = [];
		const copies = EscrowBook.prototype.copies;
		vi.spyOn(EscrowBook.prototype, "copies").mockImplementation(async function (
			this: EscrowBook,
			epoch: number,
		) {
			const result = await copies.call(this, epoch);
			copied.push(result);
			return result;
		});
		const s = setup();
		await read(s, group.rowFor(group.send("x")));
		const held = copied[0]?.good[0]?.plaintext;
		expect(held?.some((byte) => byte !== 0)).toBe(true);
		s.reader.release();
		expect(held?.every((byte) => byte === 0)).toBe(true);
		vi.restoreAllMocks();
	});
});

describe("EpochReaderCache", () => {
	const entry = (byte: number) => ({
		reader: {} as EpochReader,
		plaintext: new Uint8Array(4).fill(byte),
	});

	it("evicts_the_least_recently_used_reader_and_zeroes_its_plaintext", () => {
		const cache = new EpochReaderCache(2);
		const [a, b, c] = [entry(1), entry(2), entry(3)] as const;
		cache.set("a", a);
		cache.set("b", b);
		cache.get("a");
		cache.set("c", c);
		expect(cache.get("b")).toBeUndefined();
		expect(b.plaintext).toEqual(new Uint8Array(4));
		expect(cache.get("a")).toBe(a);
		expect(a.plaintext).toEqual(new Uint8Array(4).fill(1));
		expect(cache.size).toBe(2);
	});

	it("zeroes_the_plaintext_it_replaces_and_everything_on_clear", () => {
		const cache = new EpochReaderCache();
		const [old, fresh] = [entry(1), entry(2)] as const;
		cache.set("k", old);
		cache.set("k", fresh);
		expect(old.plaintext).toEqual(new Uint8Array(4));
		cache.clear();
		expect(fresh.plaintext).toEqual(new Uint8Array(4));
		expect(cache.size).toBe(0);
	});

	it("keeps_the_plaintext_when_the_same_entry_is_set_again", () => {
		const cache = new EpochReaderCache();
		const held = entry(7);
		cache.set("k", held);
		cache.set("k", { reader: {} as EpochReader, plaintext: held.plaintext });
		expect(held.plaintext).toEqual(new Uint8Array(4).fill(7));
	});
});
