import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { sealEscrow } from "../src/crypto/escrow.js";
import { toBase64Url } from "../src/crypto/keys.js";
import { EscrowBook } from "../src/org-reader/escrow-book.js";
import { ReaderNetworkError } from "../src/org-reader/fetch-budget.js";
import {
	escrowForged,
	escrowInvalid,
	unreadable,
} from "../src/org-reader/gaps.js";
import { type World, type WorldAgent } from "./crypto/world.js";
import { kat, unhex } from "./crypto/kat-fixture.js";
import { jsonResponse } from "./org-reader-client-fixture.js";
import { contextFor, orgWorld } from "./org-reader-world.js";

const branchDefect = vi.hoisted(() => ({ armed: false }));
vi.mock("../src/crypto/derive.js", async (importActual) => {
	const actual = await importActual<typeof import("../src/crypto/derive.js")>();
	return {
		...actual,
		assertBranchName: (name: string) => {
			if (branchDefect.armed) throw new TypeError("defect");
			return actual.assertBranchName(name);
		},
	};
});

const GROUP = randomUUID();
const PLAINTEXT = unhex(kat.mls_escrow.plaintext.bytes);
const FP = new Uint8Array(16).fill(7);
/** Before and after the world's `supersededAt` (2026-01-01). */
const EARLY = "2025-12-01T00:00:00.000000Z";
const LATE = "2026-03-01T00:00:00.000000Z";

interface RowOptions {
	epoch?: number;
	fp?: Uint8Array;
	branch?: string;
	gen?: number;
	storedAt?: string;
	/** Seal to this world's escrow key instead of the reader's org's. */
	sealedTo?: World;
}

/** The server's escrow row for a copy `uploader` sealed and signed, as the book receives it. */
function escrowRow(world: World, uploader: WorldAgent, o: RowOptions = {}) {
	const { epoch = 4, fp = FP, branch = "main", gen = uploader.gen } = o;
	const escrowKey = (o.sealedTo ?? world).branch("main");
	const { sealed, uploaderSig } = sealEscrow(
		{
			orgId: world.org.orgId,
			branch,
			x25519: escrowKey.escrowX25519.publicKey,
			mlKem: escrowKey.escrowMlKem768.publicKey,
		},
		{ groupId: GROUP, epoch, fp },
		{
			agentId: uploader.id,
			keyGen: gen,
			signingPrivateKey: uploader.derived.ed25519.privateKey,
		},
		PLAINTEXT,
	);
	return {
		epoch,
		fp: toBase64Url(fp),
		branch,
		uploader_agent_id: uploader.id,
		uploader_key_gen: gen,
		uploader_sig: toBase64Url(uploaderSig),
		sealed: toBase64Url(sealed),
		created_at: o.storedAt ?? EARLY,
	};
}

/** One org, an uploader in it, and a context whose escrow route serves `rows` (re-evaluated per call). */
function setup(rows: (uploader: WorldAgent) => unknown[] = () => []) {
	const { world, key } = orgWorld();
	const uploader = world.addAgent();
	const ctx = contextFor(key, [world]);
	const served = rows(uploader);
	const escrowRows = vi
		.spyOn(ctx.client, "escrowRows")
		.mockResolvedValue({ rows: served, complete: true });
	return { world, key, uploader, ctx, escrowRows };
}

const load = (ctx: ReturnType<typeof setup>["ctx"]) =>
	EscrowBook.load(ctx, GROUP, 0, 10);

describe("EscrowBook.load", () => {
	it("asks_once_for_the_group_over_the_epoch_range", async () => {
		const { ctx, escrowRows } = setup();
		const book = await EscrowBook.load(ctx, GROUP, 2, 9);
		await book.copies(2);
		await book.copies(5);
		expect(escrowRows).toHaveBeenCalledTimes(1);
		expect(escrowRows).toHaveBeenCalledWith(GROUP, 2, 9);
	});
});

describe("EscrowBook.copies", () => {
	it("opens_a_good_copy_and_returns_its_plaintext", async () => {
		const s = setup();
		s.escrowRows.mockResolvedValue({
			rows: [escrowRow(s.world, s.uploader)],
			complete: true,
		});
		const copies = await (await load(s.ctx)).copies(4);
		expect(copies.good).toHaveLength(1);
		expect(copies.good[0]?.plaintext).toEqual(PLAINTEXT);
		expect(copies.good[0]?.copy.uploader).toBe(s.uploader.id);
		expect(copies.bad).toEqual([]);
		expect(copies.empty).toBe(false);
		expect(copies.unavailable).toBe(false);
	});

	it("is_empty_when_the_epoch_has_no_rows", async () => {
		const s = setup();
		s.escrowRows.mockResolvedValue({
			rows: [escrowRow(s.world, s.uploader)],
			complete: true,
		});
		const copies = await (await load(s.ctx)).copies(3);
		expect(copies).toEqual({
			good: [],
			bad: [],
			empty: true,
			unavailable: false,
		});
	});

	it("opens_each_epoch_once", async () => {
		const s = setup();
		s.escrowRows.mockResolvedValue({
			rows: [escrowRow(s.world, s.uploader)],
			complete: true,
		});
		const keys = vi.spyOn(s.ctx.client, "agentKeys");
		const book = await load(s.ctx);
		const [first, second] = await Promise.all([book.copies(4), book.copies(4)]);
		expect(second).toBe(first);
		expect(await book.copies(4)).toBe(first);
		expect(keys).toHaveBeenCalledTimes(1);
	});

	it("is_forged_and_names_nobody_when_the_uploader_signature_does_not_verify", async () => {
		const s = setup();
		const row = escrowRow(s.world, s.uploader);
		row.uploader_sig = toBase64Url(new Uint8Array(64));
		s.escrowRows.mockResolvedValue({ rows: [row], complete: true });
		const copies = await (await load(s.ctx)).copies(4);
		expect(copies.good).toEqual([]);
		expect(copies.bad).toEqual([escrowForged(4)]);
	});

	it("is_forged_when_the_row_was_stored_after_the_uploader_key_was_superseded", async () => {
		const s = setup();
		s.world.addAgent({ id: s.uploader.id, gen: 1 });
		const row = escrowRow(s.world, s.uploader, { storedAt: LATE });
		s.escrowRows.mockResolvedValue({ rows: [row], complete: true });
		expect((await (await load(s.ctx)).copies(4)).bad).toEqual([
			escrowForged(4),
		]);
	});

	it("opens_a_copy_under_a_superseded_generation_stored_in_its_window", async () => {
		const s = setup();
		s.world.addAgent({ id: s.uploader.id, gen: 1 });
		const row = escrowRow(s.world, s.uploader, { storedAt: EARLY });
		s.escrowRows.mockResolvedValue({ rows: [row], complete: true });
		const keys = vi.spyOn(s.ctx.client, "agentKeys");
		const copies = await (await load(s.ctx)).copies(4);
		expect(copies.good).toHaveLength(1);
		expect(keys.mock.calls).toEqual([[s.uploader.id], [s.uploader.id, 0]]);
	});

	it("judges_a_superseded_generation_against_the_current_one_and_is_forged_without_a_window", async () => {
		const s = setup();
		s.world.addAgent({ id: s.uploader.id, gen: 1 });
		const row = escrowRow(s.world, s.uploader);
		s.escrowRows.mockResolvedValue({ rows: [row], complete: true });
		const read = s.ctx.client.agentKeys.bind(s.ctx.client);
		vi.spyOn(s.ctx.client, "agentKeys").mockImplementation(async (id, gen) => ({
			...(await read(id, gen)),
			supersededAt: undefined,
		}));
		expect((await (await load(s.ctx)).copies(4)).bad).toEqual([
			escrowForged(4),
		]);
	});

	it("names_the_uploader_when_a_signed_copy_does_not_open", async () => {
		const s = setup();
		const stranger = orgWorld().world;
		const row = escrowRow(s.world, s.uploader, { sealedTo: stranger });
		s.escrowRows.mockResolvedValue({ rows: [row], complete: true });
		const copies = await (await load(s.ctx)).copies(4);
		expect(copies.good).toEqual([]);
		expect(copies.bad).toEqual([escrowInvalid(4, s.uploader.id)]);
	});

	it("keeps_a_good_copy_and_reports_the_bad_sibling_beside_it", async () => {
		const s = setup();
		const other = s.world.addAgent();
		const sibling = escrowRow(s.world, other, {
			fp: new Uint8Array(16).fill(8),
			sealedTo: orgWorld().world,
		});
		s.escrowRows.mockResolvedValue({
			rows: [escrowRow(s.world, s.uploader), sibling],
			complete: true,
		});
		const copies = await (await load(s.ctx)).copies(4);
		expect(copies.good).toHaveLength(1);
		expect(copies.bad).toEqual([escrowInvalid(4, other.id)]);
	});

	it("is_forged_without_a_key_read_when_the_branch_name_is_hostile", async () => {
		const s = setup();
		const row = { ...escrowRow(s.world, s.uploader), branch: "../etc" };
		s.escrowRows.mockResolvedValue({ rows: [row], complete: true });
		const keys = vi.spyOn(s.ctx.client, "agentKeys");
		const copies = await (await load(s.ctx)).copies(4);
		expect(copies.bad).toEqual([escrowForged(4)]);
		expect(keys).not.toHaveBeenCalled();
	});

	it("rethrows_a_programming_error_while_checking_the_branch_name", async () => {
		const s = setup();
		s.escrowRows.mockResolvedValue({
			rows: [escrowRow(s.world, s.uploader)],
			complete: true,
		});
		branchDefect.armed = true;
		try {
			await expect((await load(s.ctx)).copies(4)).rejects.toBeInstanceOf(
				TypeError,
			);
		} finally {
			branchDefect.armed = false;
		}
	});

	it("is_forged_when_a_row_with_an_epoch_does_not_parse", async () => {
		const s = setup();
		const row = { ...escrowRow(s.world, s.uploader), sealed: 12 };
		s.escrowRows.mockResolvedValue({ rows: [row], complete: true });
		const copies = await (await load(s.ctx)).copies(4);
		expect(copies.bad).toEqual([escrowForged(4)]);
		expect(copies.empty).toBe(false);
	});

	it.each([
		["created_at", "yesterday"],
		["created_at", "2026-01-01T00:00:00"],
		["uploader_key_gen", -1],
		["uploader_key_gen", 1.5],
	])("is_forged_when_%s_is_%s", async (field, value) => {
		const s = setup();
		const row = { ...escrowRow(s.world, s.uploader), [field]: value };
		s.escrowRows.mockResolvedValue({ rows: [row], complete: true });
		expect((await (await load(s.ctx)).copies(4)).bad).toEqual([
			escrowForged(4),
		]);
	});

	it.each(["fp", "uploader_sig", "sealed"])(
		"is_forged_when_%s_is_not_base64url",
		async (field) => {
			const s = setup();
			const row = { ...escrowRow(s.world, s.uploader), [field]: "a b!" };
			s.escrowRows.mockResolvedValue({ rows: [row], complete: true });
			expect((await (await load(s.ctx)).copies(4)).bad).toEqual([
				escrowForged(4),
			]);
		},
	);

	it("holds_ten_thousand_rows_in_one_epoch_without_quadratic_copying", async () => {
		const s = setup();
		const row = escrowRow(s.world, s.uploader);
		s.escrowRows.mockResolvedValue({
			rows: Array.from({ length: 10_000 }, () => ({ ...row, sealed: 12 })),
			complete: true,
		});
		const started = performance.now();
		const copies = await (await load(s.ctx)).copies(4);
		expect(copies.bad).toHaveLength(10_000);
		expect(performance.now() - started).toBeLessThan(1000);
	});

	it("drops_a_row_that_names_no_usable_epoch", async () => {
		const s = setup();
		const row = { ...escrowRow(s.world, s.uploader), epoch: 2 ** 53 };
		s.escrowRows.mockResolvedValue({ rows: [row, null], complete: true });
		const book = await load(s.ctx);
		expect((await book.copies(4)).empty).toBe(true);
	});

	it("is_unreadable_when_the_uploaders_key_history_cannot_be_read", async () => {
		const s = setup();
		const gone = contextFor(s.key, [s.world], () =>
			jsonResponse({ error: "gone" }, 404),
		);
		vi.spyOn(gone.client, "escrowRows").mockResolvedValue({
			rows: [escrowRow(s.world, s.uploader)],
			complete: true,
		});
		const copies = await (await load(gone)).copies(4);
		expect(copies.bad).toEqual([unreadable(4)]);
		expect(copies.unavailable).toBe(false);
	});

	it("pins_the_uploader_to_the_org_so_a_foreign_chain_is_unreadable", async () => {
		const s = setup();
		const foreign = orgWorld().world;
		const stranger = foreign.addAgent();
		const ctx = contextFor(s.key, [s.world, foreign]);
		vi.spyOn(ctx.client, "escrowRows").mockResolvedValue({
			rows: [escrowRow(foreign, stranger)],
			complete: true,
		});
		const copies = await (await load(ctx)).copies(4);
		expect(copies.good).toEqual([]);
		expect(copies.bad).toEqual([unreadable(4)]);
	});

	describe("when the uploader's keys cannot be fetched just now", () => {
		const outages: [string, (id: string) => Response | undefined][] = [
			["429", () => jsonResponse({ error: "slow down" }, 429)],
			["500", () => jsonResponse({ error: "oops" }, 500)],
			["503", () => jsonResponse({ error: "busy" }, 503)],
		];

		it.each(outages)(
			"marks_the_copy_unavailable_and_names_nobody_on_%s",
			async (_status, answer) => {
				const s = setup();
				const ctx = contextFor(s.key, [s.world], answer);
				vi.spyOn(ctx.client, "escrowRows").mockResolvedValue({
					rows: [escrowRow(s.world, s.uploader)],
					complete: true,
				});
				const copies = await (await load(ctx)).copies(4);
				expect(copies).toEqual({
					good: [],
					bad: [],
					empty: false,
					unavailable: true,
				});
			},
		);

		it("marks_the_copy_unavailable_on_a_network_failure", async () => {
			const s = setup();
			s.escrowRows.mockResolvedValue({
				rows: [escrowRow(s.world, s.uploader)],
				complete: true,
			});
			vi.spyOn(s.ctx.client, "agentKeys").mockRejectedValue(
				new ReaderNetworkError("down"),
			);
			const copies = await (await load(s.ctx)).copies(4);
			expect(copies.unavailable).toBe(true);
			expect(copies.bad).toEqual([]);
		});

		it("still_reads_the_epoch_from_a_copy_whose_uploader_is_reachable", async () => {
			const s = setup();
			const down = s.world.addAgent();
			const ctx = contextFor(s.key, [s.world], (id) =>
				id === down.id ? jsonResponse({ error: "busy" }, 503) : undefined,
			);
			vi.spyOn(ctx.client, "escrowRows").mockResolvedValue({
				rows: [
					escrowRow(s.world, s.uploader),
					escrowRow(s.world, down, { fp: new Uint8Array(16).fill(8) }),
				],
				complete: true,
			});
			const copies = await (await load(ctx)).copies(4);
			expect(copies.good).toHaveLength(1);
			expect(copies.unavailable).toBe(true);
			expect(copies.bad).toEqual([]);
		});

		it("is_not_remembered_by_a_later_book", async () => {
			const s = setup();
			const rows = [escrowRow(s.world, s.uploader)];
			s.escrowRows.mockResolvedValue({ rows, complete: true });
			vi.spyOn(s.ctx.client, "agentKeys").mockRejectedValueOnce(
				new ReaderNetworkError("down"),
			);
			expect((await (await load(s.ctx)).copies(4)).unavailable).toBe(true);
			expect((await (await load(s.ctx)).copies(4)).good).toHaveLength(1);
		});
	});

	it("rethrows_a_failure_that_is_not_a_key_read", async () => {
		const s = setup();
		s.escrowRows.mockResolvedValue({
			rows: [escrowRow(s.world, s.uploader)],
			complete: true,
		});
		vi.spyOn(s.ctx.client, "agentKeys").mockRejectedValue(
			new TypeError("no binding"),
		);
		await expect((await load(s.ctx)).copies(4)).rejects.toBeInstanceOf(
			TypeError,
		);
	});
});

describe("EscrowBook when a page or row cap ends the load early", () => {
	it("is_unreadable_for_the_last_epoch_it_reached_and_every_epoch_after", async () => {
		const s = setup();
		s.escrowRows.mockResolvedValue({
			rows: [
				escrowRow(s.world, s.uploader, { epoch: 3 }),
				escrowRow(s.world, s.uploader, { epoch: 4 }),
			],
			complete: false,
		});
		const book = await load(s.ctx);
		expect((await book.copies(3)).good).toHaveLength(1);
		expect((await book.copies(4)).bad).toEqual([unreadable(4)]);
		expect((await book.copies(4)).good).toEqual([]);
		expect((await book.copies(5)).bad).toEqual([unreadable(5)]);
		expect((await book.copies(2)).empty).toBe(true);
	});

	it("is_unreadable_everywhere_when_no_row_was_read", async () => {
		const s = setup();
		s.escrowRows.mockResolvedValue({ rows: [], complete: false });
		const copies = await (await load(s.ctx)).copies(0);
		expect(copies.bad).toEqual([unreadable(0)]);
		expect(copies.empty).toBe(false);
	});

	it("is_what_the_client_reports_for_a_server_that_repeats_its_cursor", async () => {
		const { world, key, uploader } = setup();
		const row = escrowRow(world, uploader, { epoch: 1 });
		const ctx = contextFor(key, [world], (id) =>
			id === ""
				? jsonResponse({ rows: [row], next_cursor: "again" })
				: undefined,
		);
		const book = await load(ctx);
		expect((await book.copies(1)).bad).toEqual([unreadable(1)]);
		expect((await book.copies(0)).empty).toBe(true);
	});
});
