/**
 * The cross-group sweep, the start-up sweep and the leave settle, against the
 * REAL native core. Only the branch escrow key read and the key-package top-up
 * are mocked.
 *
 * A pending file outlives the group state it was sealed from. These tests fail
 * when a drain sweeps other groups, when the sweep ignores its once-per-interval
 * gate, when the heartbeat or a client start-up forgets it, when a final refusal
 * is retried for ever, or when a leave waits on the network.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	key: undefined as unknown,
	error: undefined as unknown,
	cached: true,
}));

// Self-contained on purpose: `importActual` of the real module pulls in the
// `crypto/index` import cycle, after which the sweep module would resolve the
// REAL key read and the heartbeat tests would exercise nothing.
vi.mock("../src/mls-escrow-key.js", () => ({
	ESCROW_KEY_REVOKED: "branch revoked",
	BranchRevokedError: class BranchRevokedError extends Error {},
	dropEscrowKeys: vi.fn(),
	forgetEscrowKey: vi.fn(),
	cachedEscrowKey: vi.fn(() => (state.cached ? state.key : undefined)),
	resolveEscrowKey: vi.fn(async () => {
		if (state.error) throw state.error;
		return state.key;
	}),
}));
vi.mock("../src/mls-keypackages.js", () => ({
	ensureMlsKeyPackages: vi.fn(async () => undefined),
}));

import { ACTING_AGENT_HEADER } from "../src/actor.js";
import type { VerifiedEscrowKey } from "../src/crypto/escrow.js";
import { saveAgentKeys } from "../src/crypto/keys.js";
import { generateAgentKeys, generateEncryptionKeyPair, generatePqKeyPair } from "./helpers/keys.js";
import { mlsGroupIdBytes, mlsStoreRoot, openMlsClient } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import { deleteGroupMember } from "../src/group-removal-ops.js";
import { drainEscrow } from "../src/mls-escrow-drain.js";
import { EscrowLoss, writeGap } from "../src/mls-escrow-gap.js";
import { readGap } from "../src/mls-escrow-markers.js";
import { MAX_ATTEMPTS, noteFailure, readAttempts } from "../src/mls-escrow-retry.js";
import { startupEscrowSweep, sweepPendingEscrow } from "../src/mls-escrow-sweep.js";
import { BranchRevokedError, resolveEscrowKey } from "../src/mls-escrow-key.js";
import { listPending, writePending } from "../src/mls-escrow-pending.js";
import { listSnapshots } from "../src/mls-escrow-snapshots.js";
import { mlsHeartbeat, resetMlsHeartbeatGate } from "../src/mls-heartbeat.js";
import { MLS_HEARTBEAT_MIN_INTERVAL_MS } from "../src/mls-heartbeat-interval.js";

/** A fingerprint no marker is filed under, so a read sees only fork-less markers. */
const NO_FORK_FP = new Uint8Array(16);

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const AGENT_B = "a2b3c4d5-e6f7-8901-abcd-ef1234567890";
const PEER = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const GONE_GROUP = "e5f6a7b8-c9d0-1234-ef12-345678901234";
const OTHER_GONE_GROUP = "f6a7b8c9-d0e1-2345-f123-456789012345";
const ORG_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";

/** A fixed clock for the sweep, in unix seconds. */
const NOW_S = 1_000_000;
const INTERVAL_S = MLS_HEARTBEAT_MIN_INTERVAL_MS / 1000;

let dir: string;
let calls: string[];
let put: ReturnType<typeof vi.fn>;
let del: ReturnType<typeof vi.fn>;
let actor: { configDir: string; agentId: string; client: never };

function escrowKey(): VerifiedEscrowKey {
	return {
		orgId: ORG_ID,
		branch: "main",
		x25519: generateEncryptionKeyPair().publicKey,
		mlKem: generatePqKeyPair().publicKey,
	};
}

/** The saved snapshot of a group AGENT founded and admitted PEER to: it still holds both epochs' exports. */
function snapshotWithExports(): void {
	const pkg = openMlsClient(dir, PEER).generateKeyPackage();
	openMlsClient(dir, AGENT)
		.createGroupWithMembers(mlsGroupIdBytes(GROUP_ID), [pkg])
		.save();
}

/** A sealed file for a group this agent holds no state for. */
/** The fork fingerprint the gone-group file is sealed under, as its marker names it. */
const GONE_FP_HEX = "07".repeat(16);
const GONE_FP = new Uint8Array(16).fill(7);

/** Whether a backlog dir entry is a snapshot, not its sidecar. */
function isSnapshotName(name: string): boolean {
	return name.endsWith(".snapshot");
}

function goneGroupFile(groupId = GONE_GROUP): void {
	writePending(dir, AGENT, {
		groupId,
		epoch: 3,
		fp: new Uint8Array(16).fill(7),
		sealed: new Uint8Array([1, 2, 3]),
	});
}

/** Escrow PUTs by group, in call order. */
function putGroups(): string[] {
	return put.mock.calls.map(([path]) => (path as string).split("/")[2] as string);
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-sweep-"));
	saveAgentKeys(dir, AGENT, generateAgentKeys());
	saveAgentKeys(dir, PEER, generateAgentKeys());
	calls = [];
	put = vi.fn(async (path: string) => void calls.push(`put ${path}`));
	del = vi.fn(async (path: string) => void calls.push(`delete ${path}`));
	actor = { configDir: dir, agentId: AGENT, client: { put, delete: del } as never };
	state.key = escrowKey();
	state.error = undefined;
	state.cached = true;
	resetMlsHeartbeatGate();
	vi.mocked(resolveEscrowKey).mockClear();
});

afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("a drain does not sweep", () => {
	it("test_drain_when_another_group_has_pending_then_it_uploads_only_its_own_group", async () => {
		goneGroupFile();
		snapshotWithExports();

		await drainEscrow(
			actor,
			GROUP_ID,
			openMlsClient(dir, AGENT).loadGroup(mlsGroupIdBytes(GROUP_ID)),
		);

		expect(putGroups().every((g) => g === GROUP_ID)).toBe(true);
		expect(putGroups()).not.toHaveLength(0);
		expect(listPending(dir, AGENT, GONE_GROUP)).toHaveLength(1);
	});
});

describe("the cross-group sweep", () => {
	it("test_sweep_when_a_group_is_not_held_then_its_file_is_uploaded_and_deleted", async () => {
		goneGroupFile();

		await sweepPendingEscrow(actor, NOW_S);

		expect(putGroups()).toEqual([GONE_GROUP]);
		expect(listPending(dir, AGENT)).toEqual([]);
	});

	it("test_sweep_when_run_twice_inside_the_interval_then_the_second_pass_makes_no_call", async () => {
		goneGroupFile();
		await sweepPendingEscrow(actor, NOW_S);
		goneGroupFile(OTHER_GONE_GROUP);
		put.mockClear();

		await sweepPendingEscrow(actor, NOW_S + INTERVAL_S - 1);
		expect(put).not.toHaveBeenCalled();

		await sweepPendingEscrow(actor, NOW_S + INTERVAL_S);
		expect(putGroups()).toEqual([OTHER_GONE_GROUP]);
	});

	it("test_sweep_when_the_pass_failed_then_it_is_not_repeated_inside_the_interval", async () => {
		goneGroupFile();
		put.mockRejectedValue(new Error("network down"));
		await sweepPendingEscrow(actor, NOW_S);
		put.mockClear();

		await sweepPendingEscrow(actor, NOW_S + 1);

		expect(put).not.toHaveBeenCalled();
	});

	it.each([429, 500, 503])(
		"test_sweep_when_the_server_answers_%i_then_the_rest_of_the_files_wait",
		async (status) => {
			goneGroupFile();
			goneGroupFile(OTHER_GONE_GROUP);
			put.mockRejectedValue(new RineApiError(status, "unavailable"));

			await sweepPendingEscrow(actor, NOW_S);

			expect(put).toHaveBeenCalledTimes(1);
			expect(listPending(dir, AGENT)).toHaveLength(2);
		},
	);

	it("test_sweep_when_a_group_dir_is_not_a_uuid_then_it_is_skipped_and_the_pass_completes", async () => {
		goneGroupFile();
		const stray = join(mlsStoreRoot(dir, AGENT), "escrow-pending", "not-a-group");
		fs.mkdirSync(stray, { recursive: true });
		fs.writeFileSync(join(stray, `3-${"07".repeat(16)}.bin`), "x");

		await sweepPendingEscrow(actor, NOW_S);

		expect(putGroups()).toEqual([GONE_GROUP]);
		expect(listPending(dir, AGENT)).toEqual([]);
	});

	it("test_sweep_when_the_server_names_a_terminal_code_then_the_epoch_is_filed_as_lost_and_the_file_deleted", async () => {
		goneGroupFile();
		put.mockRejectedValue(
			new RineApiError(403, "no seat", undefined, "escrow_no_seat"),
		);

		const outcome = await sweepPendingEscrow(actor, NOW_S);

		const groupDir = join(mlsStoreRoot(dir, AGENT), "escrow-pending", GONE_GROUP);
		expect(fs.readdirSync(groupDir)).toEqual([`3-${GONE_FP_HEX}.gap`]);
		expect(readGap(dir, AGENT, GONE_GROUP, 3, GONE_FP)).toBe(EscrowLoss.Refused);
		expect(outcome.gaps).toEqual([{ epoch: 3, reason: EscrowLoss.Refused }]);
		expect(outcome.failures).toHaveLength(1);
		put.mockClear();
		await sweepPendingEscrow(actor, NOW_S + 10 * INTERVAL_S);
		expect(put).not.toHaveBeenCalled();
	});

	it("test_sweep_when_the_server_refuses_without_a_code_then_the_file_stays_with_an_attempt_record", async () => {
		goneGroupFile();
		put.mockRejectedValue(new RineApiError(404, "not found"));

		await sweepPendingEscrow(actor, NOW_S);

		const [file] = listPending(dir, AGENT, GONE_GROUP);
		expect(file).toBeDefined();
		const path = join(
			mlsStoreRoot(dir, AGENT),
			"escrow-pending",
			GONE_GROUP,
			`3-${"07".repeat(16)}.bin`,
		);
		expect(readAttempts(path)).toEqual({
			attempts: 1,
			nextTry: NOW_S + INTERVAL_S,
			last: "404",
		});
	});

	it("test_sweep_when_the_server_answers_backoff_then_the_groups_remaining_files_are_not_tried", async () => {
		writePending(dir, AGENT, {
			groupId: GONE_GROUP,
			epoch: 3,
			fp: new Uint8Array(16).fill(7),
			sealed: new Uint8Array([1, 2, 3]),
		});
		writePending(dir, AGENT, {
			groupId: GONE_GROUP,
			epoch: 4,
			fp: new Uint8Array(16).fill(8),
			sealed: new Uint8Array([4, 5, 6]),
		});
		put.mockRejectedValue(new RineApiError(503, "unavailable"));

		await sweepPendingEscrow(actor, NOW_S);

		expect(put).toHaveBeenCalledTimes(1);
		expect(listPending(dir, AGENT, GONE_GROUP)).toHaveLength(2);
	});

	it("test_sweep_when_a_terminal_code_comes_with_a_server_error_status_then_the_file_is_kept_and_no_gap_is_filed", async () => {
		goneGroupFile();
		put.mockRejectedValue(new RineApiError(500, "x", undefined, "escrow_no_seat"));

		await sweepPendingEscrow(actor, NOW_S);

		const groupDir = join(mlsStoreRoot(dir, AGENT), "escrow-pending", GONE_GROUP);
		expect(listPending(dir, AGENT, GONE_GROUP)).toHaveLength(1);
				// A 5xx is the server, not this file: the pass backs off and counts no attempt.
		expect(readAttempts(join(groupDir, `3-${"07".repeat(16)}.bin`))).toBeUndefined();
		expect(readGap(dir, AGENT, GONE_GROUP, 3, NO_FORK_FP)).toBeUndefined();
	});

	it("test_sweep_when_the_gap_marker_cannot_be_written_then_it_does_not_throw_and_keeps_the_file", async () => {
		goneGroupFile();
		put.mockRejectedValue(
			new RineApiError(403, "no seat", undefined, "escrow_no_seat"),
		);
		const groupDir = join(mlsStoreRoot(dir, AGENT), "escrow-pending", GONE_GROUP);
		fs.chmodSync(groupDir, 0o500);
		try {
			await expect(sweepPendingEscrow(actor, NOW_S)).resolves.toBeDefined();
			expect(listPending(dir, AGENT, GONE_GROUP)).toHaveLength(1);
		} finally {
			fs.chmodSync(groupDir, 0o700);
		}
	});
});

describe("the backlog", () => {
	it("test_sweep_when_a_leave_parked_a_snapshot_then_the_snapshot_is_sealed_uploaded_and_deleted", async () => {
		snapshotWithExports();
		state.cached = false;
		await deleteGroupMember(actor.client, dir, GROUP_ID, AGENT, undefined, {
			[ACTING_AGENT_HEADER]: AGENT,
		});
		const backlogDir = join(mlsStoreRoot(dir, AGENT), "escrow-backlog", GROUP_ID);
		expect(fs.readdirSync(backlogDir).filter(isSnapshotName)).toHaveLength(1);
		put.mockClear();

		await sweepPendingEscrow(actor, NOW_S);

		expect(putGroups().length).toBeGreaterThan(0);
		expect(putGroups().every((g) => g === GROUP_ID)).toBe(true);
		expect(listPending(dir, AGENT)).toEqual([]);
		expect(fs.existsSync(backlogDir) ? fs.readdirSync(backlogDir) : []).toEqual([]);
	});

	it("test_sweep_when_the_key_cannot_be_read_then_the_parked_snapshot_stays", async () => {
		snapshotWithExports();
		state.cached = false;
		await deleteGroupMember(actor.client, dir, GROUP_ID, AGENT, undefined, {
			[ACTING_AGENT_HEADER]: AGENT,
		});
		state.error = new Error("escrow key unreachable");
		put.mockClear();

		const outcome = await sweepPendingEscrow(actor, NOW_S);

		expect(outcome.deferred).toBeDefined();
		expect(put).not.toHaveBeenCalled();
		const backlogDir = join(mlsStoreRoot(dir, AGENT), "escrow-backlog", GROUP_ID);
		expect(fs.readdirSync(backlogDir).filter(isSnapshotName)).toHaveLength(1);
	});

	it.skipIf(process.getuid?.() === 0)(
		"test_backlog_when_a_snapshot_cannot_be_reopened_for_a_local_io_reason_then_no_attempt_is_counted",
		async () => {
			snapshotWithExports();
			state.cached = false;
			await deleteGroupMember(actor.client, dir, GROUP_ID, AGENT, undefined, {
				[ACTING_AGENT_HEADER]: AGENT,
			});
			const [snapshot] = listSnapshots(dir, AGENT);
			expect(snapshot).toBeDefined();
			const snapshotPath = snapshot!.path;
			fs.chmodSync(snapshotPath, 0);
			try {
				await sweepPendingEscrow(actor, NOW_S);

				expect(listSnapshots(dir, AGENT).map((s) => s.path)).toEqual([snapshotPath]);
				expect(readAttempts(snapshotPath)?.attempts ?? 0).toBe(0);
			} finally {
				fs.chmodSync(snapshotPath, 0o600);
			}
		},
	);
});

describe("the heartbeat and the start-up sweep", () => {
	it("test_heartbeat_when_a_file_is_pending_for_an_unheld_group_then_uploads_it", async () => {
		goneGroupFile();

		await mlsHeartbeat({ ...actor }, "gated");

		expect(putGroups()).toEqual([GONE_GROUP]);
		expect(listPending(dir, AGENT)).toEqual([]);
	});

	it("test_heartbeat_when_nothing_is_pending_then_it_asks_for_no_key", async () => {
		await mlsHeartbeat({ ...actor }, "gated");

		expect(resolveEscrowKey).not.toHaveBeenCalled();
		expect(put).not.toHaveBeenCalled();
	});

	it("test_heartbeat_when_the_only_leftovers_are_empty_dirs_sidecars_and_gap_markers_then_it_asks_for_no_key", async () => {
		const pendingRoot = join(mlsStoreRoot(dir, AGENT), "escrow-pending");
		const groupDir = join(pendingRoot, GONE_GROUP);
		fs.mkdirSync(groupDir, { recursive: true });
		fs.writeFileSync(join(groupDir, `3-${"07".repeat(16)}.attempts`), "x");
		fs.writeFileSync(join(groupDir, "3.gap"), "x");
		fs.mkdirSync(join(pendingRoot, OTHER_GONE_GROUP), { recursive: true });
		fs.mkdirSync(join(mlsStoreRoot(dir, AGENT), "escrow-backlog", GONE_GROUP), {
			recursive: true,
		});

		await mlsHeartbeat({ ...actor }, "gated");

		expect(resolveEscrowKey).not.toHaveBeenCalled();
		expect(put).not.toHaveBeenCalled();
	});

	it("test_heartbeat_when_the_escrow_key_is_unavailable_then_the_file_stays_and_nothing_throws", async () => {
		goneGroupFile();
		state.error = new Error("escrow key unreachable");

		await expect(mlsHeartbeat({ ...actor }, "gated")).resolves.toBeUndefined();

		expect(listPending(dir, AGENT)).toHaveLength(1);
	});

	it("test_startup_when_a_previous_process_left_a_pending_file_then_it_is_uploaded", async () => {
		goneGroupFile();

		await startupEscrowSweep(actor.client as never, dir);

		expect(putGroups()).toEqual([GONE_GROUP]);
		expect(listPending(dir, AGENT)).toEqual([]);
	});

	it("test_startup_when_the_config_dir_holds_no_escrow_work_then_it_asks_for_no_key", async () => {
		await startupEscrowSweep(actor.client as never, dir);

		expect(resolveEscrowKey).not.toHaveBeenCalled();
		expect(put).not.toHaveBeenCalled();
	});

	it("test_startup_when_the_sweep_already_ran_inside_the_interval_then_it_makes_no_call", async () => {
		goneGroupFile();
		await sweepPendingEscrow(actor, Date.now() / 1000);
		goneGroupFile(OTHER_GONE_GROUP);
		put.mockClear();

		await startupEscrowSweep(actor.client as never, dir);

		expect(put).not.toHaveBeenCalled();
	});

	it("test_startup_when_an_agent_is_named_then_only_that_agents_files_are_swept", async () => {
		saveAgentKeys(dir, AGENT_B, generateAgentKeys());
		goneGroupFile();
		writePending(dir, AGENT_B, {
			groupId: OTHER_GONE_GROUP,
			epoch: 3,
			fp: new Uint8Array(16).fill(9),
			sealed: new Uint8Array([7, 8, 9]),
		});

		await startupEscrowSweep(actor.client as never, dir, AGENT);

		expect(putGroups()).toEqual([GONE_GROUP]);
		expect(put.mock.calls[0]?.[2]).toEqual({ [ACTING_AGENT_HEADER]: AGENT });
		expect(listPending(dir, AGENT)).toEqual([]);
		expect(listPending(dir, AGENT_B, OTHER_GONE_GROUP)).toHaveLength(1);
	});

	it("test_startup_when_no_agent_is_named_then_every_local_agent_is_swept", async () => {
		saveAgentKeys(dir, AGENT_B, generateAgentKeys());
		goneGroupFile();
		writePending(dir, AGENT_B, {
			groupId: OTHER_GONE_GROUP,
			epoch: 3,
			fp: new Uint8Array(16).fill(9),
			sealed: new Uint8Array([7, 8, 9]),
		});

		await startupEscrowSweep(actor.client as never, dir);

		expect(putGroups().sort()).toEqual([GONE_GROUP, OTHER_GONE_GROUP].sort());
		expect(listPending(dir, AGENT)).toEqual([]);
		expect(listPending(dir, AGENT_B)).toEqual([]);
	});

	it("test_startup_when_a_dead_process_left_scratch_then_only_the_stale_scratch_is_cleared", async () => {
		const groupDir = join(mlsStoreRoot(dir, AGENT), "escrow-backlog", GROUP_ID);
		fs.mkdirSync(groupDir, { recursive: true });
		const stale = join(groupDir, ".open-dead");
		const fresh = join(groupDir, ".open-live");
		fs.mkdirSync(stale);
		fs.mkdirSync(fresh);
		const longAgo = new Date(Date.now() - 2 * 3600 * 1000);
		fs.utimesSync(stale, longAgo, longAgo);

		await startupEscrowSweep(actor.client as never, dir, AGENT);

		expect(fs.existsSync(stale)).toBe(false);
		expect(fs.existsSync(fresh)).toBe(true);
	});
});

describe("a leave settles the escrow locally", () => {
	it("test_leave_when_the_key_is_cached_then_the_exports_are_sealed_on_disk_and_only_the_delete_goes_out", async () => {
		snapshotWithExports();

		await deleteGroupMember(actor.client, dir, GROUP_ID, AGENT, undefined, {
			[ACTING_AGENT_HEADER]: AGENT,
		});

		expect(calls).toEqual([`delete /groups/${GROUP_ID}/members/${AGENT}`]);
		expect(listPending(dir, AGENT, GROUP_ID).map((p) => p.epoch)).toEqual([0, 1]);
	});

	it("test_leave_when_no_key_is_cached_and_the_server_is_down_then_the_leave_still_completes_and_the_snapshot_is_parked", async () => {
		snapshotWithExports();
		state.cached = false;
		put.mockRejectedValue(new RineApiError(503, "unavailable"));

		await deleteGroupMember(actor.client, dir, GROUP_ID, AGENT, undefined, {
			[ACTING_AGENT_HEADER]: AGENT,
		});

		expect(put).not.toHaveBeenCalled();
		expect(calls).toEqual([`delete /groups/${GROUP_ID}/members/${AGENT}`]);
		expect(
			fs.existsSync(
				join(mlsStoreRoot(dir, AGENT), "escrow-backlog", GROUP_ID, "1.snapshot"),
			),
		).toBe(true);
	});

	it("test_kick_when_the_acting_agent_is_not_the_target_then_no_escrow_is_settled", async () => {
		snapshotWithExports();

		await deleteGroupMember(actor.client, dir, GROUP_ID, PEER, undefined, {
			[ACTING_AGENT_HEADER]: AGENT,
		});

		expect(calls).toEqual([`delete /groups/${GROUP_ID}/members/${PEER}`]);
		expect(listPending(dir, AGENT)).toEqual([]);
	});
});

/** Park the snapshot a leave sets aside (the key is uncached, so the settle cannot seal it). */
async function parkSnapshotByLeaving(): Promise<void> {
	snapshotWithExports();
	state.cached = false;
	await deleteGroupMember(actor.client, dir, GROUP_ID, AGENT, undefined, {
		[ACTING_AGENT_HEADER]: AGENT,
	});
	state.cached = true;
}

function pendingFilePath(): string {
	return join(
		mlsStoreRoot(dir, AGENT),
		"escrow-pending",
		GONE_GROUP,
		`3-${"07".repeat(16)}.bin`,
	);
}

/** A clock far enough apart that every pass is past the gate and every retry is due. */
function passClock(pass: number): number {
	return NOW_S + pass * 2 * 24 * 60 * 60;
}

describe("giving up for good", () => {
	it("test_sweep_when_the_branch_is_revoked_then_every_snapshot_and_file_is_filed_as_lost_and_deleted", async () => {
		await parkSnapshotByLeaving();
		goneGroupFile();
		state.error = new BranchRevokedError();
		put.mockClear();

		const outcome = await sweepPendingEscrow(actor, NOW_S);

		expect(put).not.toHaveBeenCalled();
		expect(outcome.deferred).toBeUndefined();
		expect(listSnapshots(dir, AGENT)).toEqual([]);
		expect(listPending(dir, AGENT)).toEqual([]);
		expect(outcome.gaps.map((g) => g.reason)).toEqual([
			EscrowLoss.BranchRevoked,
			EscrowLoss.BranchRevoked,
			EscrowLoss.BranchRevoked,
		]);
		for (const epoch of [0, 1]) {
			const groupDir = join(mlsStoreRoot(dir, AGENT), "escrow-pending", GROUP_ID);
			const name = fs.readdirSync(groupDir).find((entry) => entry.startsWith(`${epoch}-`))!;
			const fp = Buffer.from(name.slice(name.indexOf("-") + 1, -".gap".length), "hex");
			expect(readGap(dir, AGENT, GROUP_ID, epoch, fp)).toBe(EscrowLoss.BranchRevoked);
		}
		expect(readGap(dir, AGENT, GONE_GROUP, 3, GONE_FP)).toBe(EscrowLoss.BranchRevoked);
	});

	it("test_sweep_when_a_snapshot_cannot_be_read_then_it_is_kept_until_the_sixteenth_failure_and_then_filed_as_lost", async () => {
		await parkSnapshotByLeaving();
		const [snapshot] = listSnapshots(dir, AGENT);
		expect(snapshot).toBeDefined();
		fs.writeFileSync(snapshot!.path, "not a group state");

		for (let pass = 0; pass < MAX_ATTEMPTS - 1; pass++) {
			const outcome = await sweepPendingEscrow(actor, passClock(pass));
			expect(outcome.gaps).toEqual([]);
			expect(listSnapshots(dir, AGENT)).toHaveLength(1);
			expect(readGap(dir, AGENT, GROUP_ID, snapshot!.epoch, NO_FORK_FP)).toBeUndefined();
		}

		const last = await sweepPendingEscrow(actor, passClock(MAX_ATTEMPTS));

		expect(listSnapshots(dir, AGENT)).toEqual([]);
		expect(last.gaps.map(({ epoch, reason }) => ({ epoch, reason }))).toEqual([
			{ epoch: 0, reason: EscrowLoss.Unreadable },
			{ epoch: snapshot!.epoch, reason: EscrowLoss.Unreadable },
		]);
		for (const gap of last.gaps) {
			expect(gap.fp).toBeInstanceOf(Uint8Array);
			expect(readGap(dir, AGENT, GROUP_ID, gap.epoch, gap.fp!)).toBe(EscrowLoss.Unreadable);
			expect(readGap(dir, AGENT, GROUP_ID, gap.epoch, NO_FORK_FP)).toBeUndefined();
		}
	});

	it("test_sweep_when_sealing_a_readable_snapshot_keeps_failing_then_it_is_never_filed_as_lost", async () => {
		await parkSnapshotByLeaving();
		const [snapshot] = listSnapshots(dir, AGENT);
		state.key = {};

		for (let pass = 0; pass <= MAX_ATTEMPTS; pass++) {
			const outcome = await sweepPendingEscrow(actor, passClock(pass));
			expect(outcome.failures.length).toBeGreaterThan(0);
			expect(outcome.gaps).toEqual([]);
		}

		expect(listSnapshots(dir, AGENT)).toHaveLength(1);
		expect(readGap(dir, AGENT, GROUP_ID, snapshot!.epoch, NO_FORK_FP)).toBeUndefined();
	});

	it("test_sweep_when_a_file_used_its_sixteenth_attempt_in_an_earlier_pass_then_the_next_sweep_files_the_gap_and_deletes_it_without_uploading", async () => {
		goneGroupFile();
		for (let i = 0; i < MAX_ATTEMPTS; i++) noteFailure(pendingFilePath(), "403", NOW_S);

		const outcome = await sweepPendingEscrow(actor, NOW_S + 1);

		expect(put).not.toHaveBeenCalled();
		expect(listPending(dir, AGENT)).toEqual([]);
		expect(outcome.gaps).toEqual([{ epoch: 3, reason: EscrowLoss.Refused }]);
		expect(readGap(dir, AGENT, GONE_GROUP, 3, GONE_FP)).toBe(EscrowLoss.Refused);
	});

	it("test_sweep_when_a_crash_left_both_the_marker_and_the_file_then_the_next_sweep_completes_the_give_up", async () => {
		goneGroupFile();
		writeGap(dir, AGENT, GONE_GROUP, { epoch: 3, reason: EscrowLoss.Refused });
		put.mockRejectedValue(
			new RineApiError(403, "no seat", undefined, "escrow_no_seat"),
		);

		await sweepPendingEscrow(actor, NOW_S);

		expect(listPending(dir, AGENT)).toEqual([]);
		expect(readGap(dir, AGENT, GONE_GROUP, 3, NO_FORK_FP)).toBe(EscrowLoss.Refused);
	});

	it("test_sweep_when_the_marker_cannot_be_written_then_the_file_is_not_deleted_and_the_failure_is_reported", async () => {
		goneGroupFile();
		const groupDir = join(mlsStoreRoot(dir, AGENT), "escrow-pending", GONE_GROUP);
		put.mockRejectedValue(
			new RineApiError(403, "no seat", undefined, "escrow_no_seat"),
		);
		fs.chmodSync(groupDir, 0o500);
		try {
			const outcome = await sweepPendingEscrow(actor, NOW_S);

			expect(listPending(dir, AGENT, GONE_GROUP)).toHaveLength(1);
			expect(outcome.gaps).toEqual([]);
			expect(outcome.failures).toHaveLength(2);
		} finally {
			fs.chmodSync(groupDir, 0o700);
		}
	});
});
