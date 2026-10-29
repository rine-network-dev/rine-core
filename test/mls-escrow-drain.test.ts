/**
 * The escrow drain, driven against the REAL native core.
 *
 * Only the branch escrow key read is mocked: the group, its exports and the
 * pending store are all real, so a test here fails when the drain seals after
 * saving, loses a file on a network error, or signs under a stale key
 * generation.
 */
import { hexToBytes } from "@noble/curves/utils.js";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	key: undefined as unknown,
	error: undefined as unknown,
	cached: true,
}));

vi.mock("../src/mls-escrow-key.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../src/mls-escrow-key.js")>()),
	resolveEscrowKey: vi.fn(async () => {
		if (state.error) throw state.error;
		return state.key;
	}),
	cachedEscrowKey: vi.fn(() => (state.cached ? state.key : undefined)),
}));

import type { EscrowExport, MlsGroup } from "@rine-network/mls";
import {
	type VerifiedEscrowKey,
	verifyEscrowUploaderSig,
} from "../src/crypto/escrow.js";
import { fromBase64Url, loadAgentKeys, saveAgentKeys, toBase64Url } from "../src/crypto/keys.js";
import { generateAgentKeys, generateEncryptionKeyPair, generatePqKeyPair } from "./helpers/keys.js";
import {
	mlsGroupIdBytes,
	mlsStoreRoot,
	openMlsClient,
} from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import { noteUnreported } from "../src/mls-escrow-handoff.js";
import { resetProcessGates } from "../src/process-gate.js";
import { BranchRevokedError } from "../src/mls-escrow-key.js";
import { EscrowDeferral, reportDrain, reportOf } from "../src/mls-escrow-report.js";
import { drainEscrow } from "../src/mls-escrow-drain.js";
import { uploadPendingEscrow } from "../src/mls-escrow-upload.js";
import { settleAfterJoin, settleEscrow } from "../src/mls-escrow-settle.js";
import { readHead } from "../src/mls-escrow-head.js";
import { readGap } from "../src/mls-escrow-markers.js";
import { listSnapshots } from "../src/mls-escrow-snapshots.js";
import {
	type PendingEscrow,
	groupPendingDir,
	listPending,
	writePending,
} from "../src/mls-escrow-pending.js";

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const PEER = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const ORG_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";

let dir: string;
let put: ReturnType<typeof vi.fn>;
let actor: { configDir: string; agentId: string; client: never };

/** A real `VerifiedEscrowKey` with a fixed org and branch. */
function escrowKey(): VerifiedEscrowKey {
	return {
		orgId: ORG_ID,
		branch: "main",
		x25519: generateEncryptionKeyPair().publicKey,
		mlKem: generatePqKeyPair().publicKey,
	};
}

/**
 * A group at epoch 1 as a restarted process finds it: AGENT founded it and admitted
 * PEER, and the saved snapshot still holds the escrow exports of both epochs.
 */
function groupAtEpochOne(): MlsGroup {
	const pkg = openMlsClient(dir, PEER).generateKeyPackage();
	openMlsClient(dir, AGENT)
		.createGroupWithMembers(mlsGroupIdBytes(GROUP_ID), [pkg])
		.save();
	return openMlsClient(dir, AGENT).loadGroup(mlsGroupIdBytes(GROUP_ID));
}

/** A fingerprint no marker is filed under, so a read sees only fork-less markers. */
const NO_FORK_FP = new Uint8Array(16);

/** The recorded reason of the fork a marker at `epoch` is named for. */
function gapOfMarkedFork(epoch: number) {
	const name = fs
		.readdirSync(groupPendingDir(dir, AGENT, GROUP_ID))
		.find((file) => file.startsWith(`${epoch}-`));
	const fork = name?.slice(`${epoch}-`.length, -".gap".length);
	return readGap(
		dir,
		AGENT,
		GROUP_ID,
		epoch,
		fork === undefined ? NO_FORK_FP : hexToBytes(fork),
	);
}

/** A group with no exports left in its snapshot. */
function quietGroup(): MlsGroup {
	const group = openMlsClient(dir, AGENT).createGroup(
		mlsGroupIdBytes(GROUP_ID),
	);
	group.save();
	return openMlsClient(dir, AGENT).loadGroup(mlsGroupIdBytes(GROUP_ID));
}

/** A proxy whose `save` throws once — the crash between seal and save. */
function crashOnce(group: MlsGroup): MlsGroup {
	let crashed = false;
	return new Proxy(group, {
		get(target, prop, receiver) {
			if (prop === "save" && !crashed) {
				return () => {
					crashed = true;
					throw new Error("crash");
				};
			}
			const value = Reflect.get(target, prop, receiver);
			return typeof value === "function" ? value.bind(target) : value;
		},
	});
}

/** The export the group currently holds, read without saving. */
function peek(group: MlsGroup): EscrowExport {
	const [first] = group.takeEscrowExports().exports;
	if (!first) throw new Error("no escrow export");
	return first;
}

/** The pending file for one epoch. */
function pendingAt(epoch: number): PendingEscrow {
	const found = listPending(dir, AGENT).find((p) => p.epoch === epoch);
	if (!found) throw new Error(`no pending file for epoch ${epoch}`);
	return found;
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-drain-"));
	saveAgentKeys(dir, AGENT, generateAgentKeys());
	saveAgentKeys(dir, PEER, generateAgentKeys());
	put = vi.fn(async () => undefined);
	actor = { configDir: dir, agentId: AGENT, client: { put } as never };
	state.key = escrowKey();
	state.error = undefined;
	state.cached = true;
	resetProcessGates();
});

afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("drainEscrow", () => {
	it("test_drain_when_process_dies_between_seal_and_save_reyields_and_uploads_exactly_once", async () => {
		const group = groupAtEpochOne();
		await expect(
			drainEscrow(actor, GROUP_ID, crashOnce(group)),
		).rejects.toThrow("crash");

		const pending = listPending(dir, AGENT);
		expect(pending.length).toBeGreaterThan(0);
		expect(put).not.toHaveBeenCalled();

		const fresh = openMlsClient(dir, AGENT).loadGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		const outcome = await drainEscrow(actor, GROUP_ID, fresh);

		// Nothing was re-sealed (the files survived the crash) and every slot
		// was uploaded exactly once, with the bytes the first drain wrote.
		expect(outcome.sealed).toBe(0);
		expect(outcome.uploaded).toBe(pending.length);
		expect(put).toHaveBeenCalledTimes(pending.length);
		for (const p of pending) {
			const call = put.mock.calls.find(
				([path]) => path === `/groups/${GROUP_ID}/mls/escrow/${p.epoch}`,
			);
			expect(call).toBeDefined();
			expect(call![2]).toEqual({ "X-Rine-Agent": AGENT });
			expect((call![1] as { sealed: string }).sealed).toBe(
				toBase64Url(p.sealed),
			);
		}
		expect(listPending(dir, AGENT)).toEqual([]);

		await drainEscrow(actor, GROUP_ID, fresh);
		expect(put).toHaveBeenCalledTimes(pending.length);
	});

	it("test_drain_when_escrow_key_unavailable_saves_without_taking_and_defers", async () => {
		const group = groupAtEpochOne();
		state.error = new Error("branch revoked");

		const outcome = await drainEscrow(actor, GROUP_ID, group);

		expect(outcome.deferred?.message).toBe("branch revoked");
		expect(outcome.sealed).toBe(0);
		expect(listPending(dir, AGENT)).toEqual([]);

		state.error = undefined;
		const fresh = openMlsClient(dir, AGENT).loadGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		const later = await drainEscrow(actor, GROUP_ID, fresh);
		expect(later.sealed).toBeGreaterThan(0);
		expect(later.uploaded).toBe(later.sealed);
		expect(later.failures).toEqual([]);
	});

	it("test_drain_when_the_branch_is_revoked_then_the_deferral_names_it_and_no_export_is_discarded", async () => {
		const group = groupAtEpochOne();
		state.error = new BranchRevokedError();

		const outcome = await drainEscrow(actor, GROUP_ID, group);

		expect(reportOf(outcome).deferral).toBe(EscrowDeferral.BranchRevoked);
		expect(reportOf(outcome).queued).toBeGreaterThan(0);
		expect(reportOf(outcome).dropped).toBe(0);

		state.error = undefined;
		const fresh = openMlsClient(dir, AGENT).loadGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		const later = await drainEscrow(actor, GROUP_ID, fresh);
		expect(later.sealed).toBe(reportOf(outcome).queued);
	});

	it("test_drain_when_upload_fails_keeps_pending_file_and_next_drain_uploads_it", async () => {
		put.mockRejectedValue(new RineApiError(503, "unavailable"));
		const group = groupAtEpochOne();

		const outcome = await drainEscrow(actor, GROUP_ID, group);

		expect(outcome.uploaded).toBe(0);
		// A 5xx means the server is down: the rest of the group is not tried.
		expect(outcome.failures).toHaveLength(1);
		expect(put).toHaveBeenCalledTimes(1);
		expect(listPending(dir, AGENT)).toHaveLength(2);

		put.mockResolvedValue(undefined);
		const fresh = openMlsClient(dir, AGENT).loadGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		const next = await drainEscrow(actor, GROUP_ID, fresh);
		expect(next.failures).toEqual([]);
		expect(next.uploaded).toBeGreaterThan(0);
		expect(listPending(dir, AGENT)).toEqual([]);
	});

	it("test_drain_when_file_was_sealed_under_older_key_gen_signs_with_current_key_gen", async () => {
		const group = quietGroup();
		const export_ = peek(group);
		writePending(dir, AGENT, {
			groupId: GROUP_ID,
			epoch: export_.epoch,
			fp: export_.fp,
			sealed: new Uint8Array([1, 2, 3, 4]),
		});
		const keys = loadAgentKeys(dir, AGENT);
		saveAgentKeys(dir, AGENT, { ...keys, keyGen: 1 });

		await drainEscrow(actor, GROUP_ID, group);

		const [, body] = put.mock.calls[0]!;
		const upload = body as {
			fp: string;
			sealed: string;
			key_gen: number;
			sig: string;
		};
		expect(upload.key_gen).toBe(1);
		expect(
			verifyEscrowUploaderSig(
				loadAgentKeys(dir, AGENT).signing.publicKey,
				state.key as VerifiedEscrowKey,
				{
					groupId: GROUP_ID,
					epoch: export_.epoch,
					fp: fromBase64Url(upload.fp),
				},
				{ agentId: AGENT, keyGen: 1 },
				fromBase64Url(upload.sealed),
				fromBase64Url(upload.sig),
			),
		).toBe(true);
	});

	it("test_drain_when_the_slot_already_holds_this_agents_row_then_the_file_is_done", async () => {
		put.mockRejectedValue(
			new RineApiError(409, "slot taken", undefined, "escrow_slot_taken"),
		);
		const group = groupAtEpochOne();

		const outcome = await drainEscrow(actor, GROUP_ID, group);

		expect(outcome.failures).toEqual([]);
		expect(outcome.uploaded).toBe(2);
		expect(listPending(dir, AGENT)).toEqual([]);
	});

	it.each([
		[409, "escrow_fork_limit", "refused"],
		[403, "escrow_no_seat", "refused"],
		[404, "group_not_found", "refused"],
		[410, "branch_revoked", "branch_revoked"],
		[403, "agent_revoked", "refused"],
	])(
		"test_drain_when_the_server_refuses_for_good_%i_%s_then_the_epochs_are_filed_as_lost_and_the_files_deleted",
		async (status, code, loss) => {
			put.mockRejectedValue(
				new RineApiError(status, "refused", undefined, code),
			);
			const group = groupAtEpochOne();

			const outcome = await drainEscrow(actor, GROUP_ID, group);

			expect(outcome.failures).toHaveLength(2);
			expect(listPending(dir, AGENT)).toEqual([]);
			expect(outcome.gaps).toEqual([
				{ epoch: 0, reason: loss },
				{ epoch: 1, reason: loss },
			]);
			expect(gapOfMarkedFork(0)).toBe(loss);
			expect(gapOfMarkedFork(1)).toBe(loss);
			expect(
				fs.readdirSync(join(mlsStoreRoot(dir, AGENT), "escrow-pending", GROUP_ID)).sort(),
			).toEqual([
				expect.stringMatching(/^0-[0-9a-f]{32}\.gap$/),
				expect.stringMatching(/^1-[0-9a-f]{32}\.gap$/),
			]);
			put.mockClear();
			await drainEscrow(
				actor,
				GROUP_ID,
				openMlsClient(dir, AGENT).loadGroup(mlsGroupIdBytes(GROUP_ID)),
			);
			expect(put).not.toHaveBeenCalled();
		},
	);

	it.each([[403], [404]])(
		"test_drain_when_the_server_refuses_%i_without_a_code_then_the_file_stays_on_a_retry_schedule",
		async (status) => {
			put.mockRejectedValue(new RineApiError(status, "refused"));
			const group = groupAtEpochOne();

			const outcome = await drainEscrow(actor, GROUP_ID, group);

			expect(outcome.failures).toHaveLength(2);
			expect(listPending(dir, AGENT).map((p) => p.epoch)).toEqual([0, 1]);
			const sidecars = fs
				.readdirSync(join(mlsStoreRoot(dir, AGENT), "escrow-pending", GROUP_ID))
				.filter((name) => name.endsWith(".attempts"));
			expect(sidecars).toHaveLength(2);
			put.mockClear();
			await drainEscrow(
				actor,
				GROUP_ID,
				openMlsClient(dir, AGENT).loadGroup(mlsGroupIdBytes(GROUP_ID)),
			);
			expect(put).not.toHaveBeenCalled();
		},
	);

	it("test_drain_when_the_server_keeps_refusing_without_a_code_then_the_sixteenth_try_files_the_epochs_as_lost_and_deletes_the_files", async () => {
		put.mockRejectedValue(new RineApiError(403, "refused"));
		await drainEscrow(actor, GROUP_ID, groupAtEpochOne());
		for (let attempt = 2; attempt <= 15; attempt++) {
			await uploadPendingEscrow(actor, GROUP_ID);
			expect(listPending(dir, AGENT)).toHaveLength(2);
		}

		const outcome = await uploadPendingEscrow(actor, GROUP_ID);

		expect(listPending(dir, AGENT)).toEqual([]);
		expect(outcome.gaps).toEqual([
			{ epoch: 0, reason: "refused" },
			{ epoch: 1, reason: "refused" },
		]);
		expect(gapOfMarkedFork(0)).toBe("refused");
		expect(gapOfMarkedFork(1)).toBe("refused");
	});

	it("test_drain_head_records_newest_epoch", async () => {
		put.mockRejectedValue(new RineApiError(503, "unavailable"));
		const group = groupAtEpochOne();

		await drainEscrow(actor, GROUP_ID, group);

		const head = readHead(dir, AGENT, GROUP_ID);
		expect(head?.epoch).toBe(1);
		expect(head?.fp).toEqual(pendingAt(1).fp);
	});

	it("test_drain_when_a_background_sweep_lost_epochs_then_a_dropped_outcome_leaves_them_for_a_reported_one", async () => {
		const carried = [
			{ epoch: 7, reason: "refused" as const },
			{ epoch: 8, reason: "branch_revoked" as const },
		];
		noteUnreported(dir, AGENT, carried.map((gap) => ({ groupId: GROUP_ID, gap })));

		const dropped = await drainEscrow(actor, GROUP_ID, groupAtEpochOne());
		const fresh = openMlsClient(dir, AGENT).loadGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		const outcome = await drainEscrow(actor, GROUP_ID, fresh);
		const report = reportDrain(actor, GROUP_ID, outcome);

		expect(dropped.gaps).toEqual([]);
		expect(report.gaps.slice(0, 2)).toEqual(carried);
		expect(reportDrain(actor, GROUP_ID, outcome).gaps).toEqual([]);
	});

	it("test_report_drain_when_a_sweep_lost_epochs_of_another_group_then_this_group_does_not_report_them", async () => {
		const other = "d4e5f6a7-b8c9-0123-def0-234567890123";
		noteUnreported(dir, AGENT, [
			{ groupId: other, gap: { epoch: 7, reason: "refused" } },
		]);

		const report = reportDrain(actor, GROUP_ID, await drainEscrow(actor, GROUP_ID, groupAtEpochOne()));

		expect(report.gaps).toEqual([]);
		expect(reportDrain(actor, other, { gaps: [] }).gaps).toEqual([
			{ epoch: 7, reason: "refused" },
		]);
	});
});

/** A proxy that records every export the drain takes, to inspect them afterwards. */
function recordingTakes(group: MlsGroup, seen: EscrowExport[]): MlsGroup {
	return new Proxy(group, {
		get(target, prop, receiver) {
			if (prop === "takeEscrowExports") {
				return () => {
					const take = target.takeEscrowExports();
					seen.push(...take.exports);
					return take;
				};
			}
			const value = Reflect.get(target, prop, receiver);
			return typeof value === "function" ? value.bind(target) : value;
		},
	});
}

const isZeroed = (export_: EscrowExport) =>
	export_.plaintext.every((byte) => byte === 0);

describe("drainEscrow zeroing", () => {
	it("test_drain_when_the_exports_are_sealed_then_every_plaintext_is_zeroed", async () => {
		const seen: EscrowExport[] = [];
		await drainEscrow(actor, GROUP_ID, recordingTakes(groupAtEpochOne(), seen));

		expect(seen.length).toBeGreaterThan(1);
		expect(seen.every(isZeroed)).toBe(true);
		expect(listPending(dir, AGENT)).toHaveLength(0);
	});

	it("test_drain_when_sealing_throws_then_every_plaintext_is_still_zeroed", async () => {
		state.key = { ...escrowKey(), x25519: new Uint8Array(3) };
		const seen: EscrowExport[] = [];
		await expect(
			drainEscrow(actor, GROUP_ID, recordingTakes(groupAtEpochOne(), seen)),
		).rejects.toThrow();

		expect(seen.length).toBeGreaterThan(1);
		expect(seen.every(isZeroed)).toBe(true);
	});
});

describe("settleEscrow", () => {
	it("test_settle_when_the_key_is_cached_then_the_exports_are_sealed_locally_and_nothing_is_uploaded", () => {
		groupAtEpochOne();

		const report = settleEscrow(actor, GROUP_ID);

		expect(put).not.toHaveBeenCalled();
		expect(listPending(dir, AGENT).map((p) => p.epoch)).toEqual([0, 1]);
		const reloaded = openMlsClient(dir, AGENT).loadGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		expect(reloaded.takeEscrowExports().exports).toEqual([]);
		expect(report).toEqual({
			gaps: [],
			queued: 0,
			dropped: 0,
			backlogged: 0,
		});
	});

	it("test_settle_when_no_key_is_cached_then_the_snapshot_is_parked_in_the_backlog_and_nothing_is_lost", () => {
		groupAtEpochOne();
		state.cached = false;

		const report = settleEscrow(actor, GROUP_ID);

		expect(put).not.toHaveBeenCalled();
		expect(listPending(dir, AGENT)).toEqual([]);
		const parked = join(
			mlsStoreRoot(dir, AGENT),
			"escrow-backlog",
			GROUP_ID,
			"1.snapshot",
		);
		expect(fs.statSync(parked).mode & 0o777).toBe(0o600);
		expect(report).toMatchObject({ backlogged: 1 });
		expect(report.queued).toBeGreaterThan(0);
	});

	it("test_settle_when_the_group_holds_no_exports_then_nothing_is_parked", async () => {
		await drainEscrow(actor, GROUP_ID, groupAtEpochOne());
		state.cached = false;

		const report = settleEscrow(actor, GROUP_ID);

		expect(report).toEqual({
			gaps: [],
			queued: 0,
			dropped: 0,
			backlogged: 0,
			deferral: EscrowDeferral.KeyUnavailable,
		});
		expect(
			fs.existsSync(join(mlsStoreRoot(dir, AGENT), "escrow-backlog")),
		).toBe(false);
	});

	it("test_settle_when_the_key_is_cached_then_the_head_is_not_recorded", () => {
		groupAtEpochOne();

		settleEscrow(actor, GROUP_ID);

		expect(readHead(dir, AGENT, GROUP_ID)).toBeUndefined();
	});

	it("test_settle_when_no_key_is_cached_then_the_report_names_the_key_as_the_deferral", () => {
		groupAtEpochOne();
		state.cached = false;

		const report = settleEscrow(actor, GROUP_ID);

		expect(report.deferral).toBe(EscrowDeferral.KeyUnavailable);
		expect(report.backlogged).toBe(1);
	});

	it("test_settle_when_parking_fails_then_it_does_not_throw_and_the_report_shows_work_left", () => {
		groupAtEpochOne();
		state.cached = false;
		// A regular file where the backlog root must be a directory: the group
		// dir cannot be created, so the park fails.
		fs.writeFileSync(join(mlsStoreRoot(dir, AGENT), "escrow-backlog"), "");

		const report = settleEscrow(actor, GROUP_ID);

		expect(report.queued).toBeGreaterThan(0);
		expect(report.backlogged).toBe(0);
	});

	it("test_settle_when_the_forks_cannot_be_read_then_the_snapshot_is_still_parked", () => {
		const group = groupAtEpochOne();
		state.cached = false;
		const prototype = Object.getPrototypeOf(group) as MlsGroup;
		const unreadable = vi
			.spyOn(prototype, "queuedEscrowFingerprints")
			.mockImplementation(() => {
				throw new Error("fork read failed");
			});

		const report = settleEscrow(actor, GROUP_ID);
		const reads = unreadable.mock.calls.length;
		unreadable.mockRestore();

		expect(reads).toBe(1);
		expect(report.backlogged).toBe(1);
		expect(listSnapshots(dir, AGENT)).toHaveLength(1);
	});

	it("test_settle_when_two_states_are_parked_at_the_same_epoch_then_both_are_kept", () => {
		groupAtEpochOne();
		state.cached = false;
		settleEscrow(actor, GROUP_ID);

		// Replace the stored state with a different epoch-1 state: a resync and a
		// rejoin can land on the same epoch number.
		fs.rmSync(join(mlsStoreRoot(dir, AGENT), "groups"), {
			recursive: true,
			force: true,
		});
		const pkg = openMlsClient(dir, PEER).generateKeyPackage();
		openMlsClient(dir, AGENT)
			.createGroupWithMembers(mlsGroupIdBytes(GROUP_ID), [pkg])
			.save();
		settleEscrow(actor, GROUP_ID);

		expect(listSnapshots(dir, AGENT)).toHaveLength(2);
	});

	it("test_settle_when_the_server_is_down_then_it_still_returns_because_it_never_calls_it", () => {
		groupAtEpochOne();
		put.mockRejectedValue(new RineApiError(503, "unavailable"));
		(actor.client as unknown as { get: unknown }).get = vi.fn(() => {
			throw new Error("settle must not touch the network");
		});

		expect(() => settleEscrow(actor, GROUP_ID)).not.toThrow();
		expect(put).not.toHaveBeenCalled();
	});
});

describe("settleAfterJoin", () => {
	it("test_settle_after_join_when_both_halves_report_then_the_settle_comes_first_and_the_counts_sum", async () => {
		// The settle parks the stored snapshot (no cached key) and the drain of
		// the joined group defers on a revoked branch, so each half carries its
		// own deferral and its own queue.
		const joined = groupAtEpochOne();
		const backlog = joined.escrowBacklog();
		state.cached = false;
		state.error = new BranchRevokedError();

		const report = await settleAfterJoin(actor, GROUP_ID, joined);

		expect(backlog.queued).toBeGreaterThan(0);
		expect(report).toEqual({
			gaps: [],
			deferral: EscrowDeferral.KeyUnavailable,
			queued: 2 * backlog.queued,
			dropped: 2 * backlog.dropped,
			backlogged: 1,
		});
	});
});
