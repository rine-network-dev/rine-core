/**
 * The revocation flow end to end: a 401 naming a revoked agent or branch on the
 * upload, a revoked principal from the key read, the handoff of the epochs a
 * sweep gave up, and the marker a stored escrow clears.
 *
 * Only the branch escrow key read and the key-package top-up are mocked; the
 * pending store, the gap markers and the parked snapshots are real.
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
import {
	PrincipalRevokedError,
	RineApiError,
	RevokedScope,
} from "../src/errors.js";
import { deleteGroupMember } from "../src/group-removal-ops.js";
import { EscrowLoss, writeGap } from "../src/mls-escrow-gap.js";
import { readGap } from "../src/mls-escrow-markers.js";
import { takeUnreported } from "../src/mls-escrow-handoff.js";
import { resetProcessGates } from "../src/process-gate.js";
import { forgetEscrowKey } from "../src/mls-escrow-key.js";
import { listPending, writePending } from "../src/mls-escrow-pending.js";
import { EscrowDeferral, deferralFor } from "../src/mls-escrow-report.js";
import { listSnapshots } from "../src/mls-escrow-snapshots.js";
import {
	startupEscrowSweep,
	sweepPendingEscrow,
} from "../src/mls-escrow-sweep.js";

/** A fingerprint no marker is filed under, so a read sees only fork-less markers. */
const NO_FORK_FP = new Uint8Array(16);

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const PEER = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const GONE_GROUP = "e5f6a7b8-c9d0-1234-ef12-345678901234";
const ORG_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";

const NOW_S = 1_000_000;
const FP = new Uint8Array(16).fill(7);
const OTHER_FP = new Uint8Array(16).fill(8);

let dir: string;
let put: ReturnType<typeof vi.fn>;
let actor: { configDir: string; agentId: string; client: never };

function escrowKey(): VerifiedEscrowKey {
	return {
		orgId: ORG_ID,
		branch: "main",
		x25519: generateEncryptionKeyPair().publicKey,
		mlKem: generatePqKeyPair().publicKey,
	};
}

/** A sealed file for a group this agent holds no state for. */
function goneGroupFile(): void {
	writePending(dir, AGENT, {
		groupId: GONE_GROUP,
		epoch: 3,
		fp: FP,
		sealed: new Uint8Array([1, 2, 3]),
	});
}

/** The saved snapshot of a group AGENT founded and admitted PEER to. */
function snapshotWithExports(): void {
	const pkg = openMlsClient(dir, PEER).generateKeyPackage();
	openMlsClient(dir, AGENT)
		.createGroupWithMembers(mlsGroupIdBytes(GROUP_ID), [pkg])
		.save();
}

/** Park the snapshot a leave sets aside (the key is uncached, so the settle cannot seal it). */
async function parkSnapshotByLeaving(): Promise<void> {
	snapshotWithExports();
	state.cached = false;
	await deleteGroupMember(actor.client, dir, GROUP_ID, AGENT, undefined, {
		[ACTING_AGENT_HEADER]: AGENT,
	});
	state.cached = true;
}

/** The marker path of one fork at one epoch. */
function markerPath(epoch: number, fp: Uint8Array): string {
	return join(
		mlsStoreRoot(dir, AGENT),
		"escrow-pending",
		GONE_GROUP,
		`${epoch}-${Buffer.from(fp).toString("hex")}.gap`,
	);
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-revoked-flow-"));
	saveAgentKeys(dir, AGENT, generateAgentKeys());
	saveAgentKeys(dir, PEER, generateAgentKeys());
	put = vi.fn(async () => undefined);
	actor = {
		configDir: dir,
		agentId: AGENT,
		client: { put, delete: vi.fn(async () => undefined) } as never,
	};
	state.key = escrowKey();
	state.error = undefined;
	state.cached = true;
	resetProcessGates();
	vi.mocked(forgetEscrowKey).mockClear();
});

afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("a revoked principal on the upload", () => {
	it("test_sweep_when_the_upload_answers_a_revoked_agent_then_the_file_is_given_up_as_agent_revoked", async () => {
		goneGroupFile();
		put.mockRejectedValue(
			new PrincipalRevokedError(RevokedScope.Agent, "agent revoked", undefined, "agent_revoked"),
		);

		const outcome = await sweepPendingEscrow(actor, NOW_S);

		expect(listPending(dir, AGENT)).toEqual([]);
		expect(readGap(dir, AGENT, GONE_GROUP, 3, FP)).toBe(EscrowLoss.AgentRevoked);
		expect(outcome.gaps).toEqual([{ epoch: 3, reason: EscrowLoss.AgentRevoked }]);
	});

	it("test_sweep_when_the_upload_answers_a_revoked_branch_then_the_file_is_given_up_and_the_key_dropped", async () => {
		goneGroupFile();
		put.mockRejectedValue(
			new PrincipalRevokedError(RevokedScope.Branch, "branch revoked", undefined, "branch_revoked"),
		);

		await sweepPendingEscrow(actor, NOW_S);

		expect(listPending(dir, AGENT)).toEqual([]);
		expect(readGap(dir, AGENT, GONE_GROUP, 3, FP)).toBe(EscrowLoss.BranchRevoked);
		expect(forgetEscrowKey).toHaveBeenCalled();
	});

	it("test_sweep_when_the_escrow_upload_answers_422_agent_revoked_then_the_loss_is_agent_revoked", async () => {
		goneGroupFile();
		put.mockRejectedValue(
			new RineApiError(422, "agent revoked", undefined, "agent_revoked"),
		);

		await sweepPendingEscrow(actor, NOW_S);

		expect(listPending(dir, AGENT)).toEqual([]);
		expect(readGap(dir, AGENT, GONE_GROUP, 3, FP)).toBe(EscrowLoss.AgentRevoked);
		expect(forgetEscrowKey).not.toHaveBeenCalled();
	});
});

describe("a revoked principal from the key read", () => {
	it("test_sweep_when_the_key_read_names_a_revoked_agent_then_every_file_and_snapshot_is_given_up", async () => {
		await parkSnapshotByLeaving();
		goneGroupFile();
		state.error = new PrincipalRevokedError(RevokedScope.Agent, "agent revoked");
		put.mockClear();

		const outcome = await sweepPendingEscrow(actor, NOW_S);

		expect(put).not.toHaveBeenCalled();
		expect(outcome.deferred).toBeUndefined();
		expect(listSnapshots(dir, AGENT)).toEqual([]);
		expect(listPending(dir, AGENT)).toEqual([]);
		expect(outcome.gaps.map((g) => g.reason)).toEqual([
			EscrowLoss.AgentRevoked,
			EscrowLoss.AgentRevoked,
			EscrowLoss.AgentRevoked,
		]);
		expect(readGap(dir, AGENT, GONE_GROUP, 3, FP)).toBe(EscrowLoss.AgentRevoked);
	});

	it("test_sweep_when_the_key_read_answers_a_plain_401_then_the_files_stay_and_the_outcome_defers", async () => {
		goneGroupFile();
		state.error = new RineApiError(401, "unauthorized");

		const outcome = await sweepPendingEscrow(actor, NOW_S);

		expect(outcome.deferred).toBeDefined();
		expect(listPending(dir, AGENT)).toHaveLength(1);
		expect(readGap(dir, AGENT, GONE_GROUP, 3, NO_FORK_FP)).toBeUndefined();
	});
});

describe("a revocation that may not cover the swept agent", () => {
	it("test_sweep_when_the_revoked_principal_may_act_for_other_agents_then_the_files_stay_and_the_outcome_defers", async () => {
		goneGroupFile();
		state.error = new PrincipalRevokedError(RevokedScope.Branch, "branch revoked");

		const outcome = await sweepPendingEscrow(actor, NOW_S, false);

		expect(outcome.deferred).toBeDefined();
		expect(listPending(dir, AGENT)).toHaveLength(1);
		expect(readGap(dir, AGENT, GONE_GROUP, 3, NO_FORK_FP)).toBeUndefined();
	});

	it("test_startup_sweep_when_it_covers_every_local_agent_then_a_revoked_principal_gives_up_nothing", async () => {
		goneGroupFile();
		state.error = new PrincipalRevokedError(RevokedScope.Branch, "branch revoked");

		await startupEscrowSweep(actor.client, dir);

		expect(listPending(dir, AGENT)).toHaveLength(1);
		expect(readGap(dir, AGENT, GONE_GROUP, 3, NO_FORK_FP)).toBeUndefined();
	});

	it("test_startup_sweep_when_it_covers_one_agent_then_a_revoked_principal_gives_up_its_files", async () => {
		goneGroupFile();
		state.error = new PrincipalRevokedError(RevokedScope.Agent, "agent revoked");

		await startupEscrowSweep(actor.client, dir, AGENT);

		expect(listPending(dir, AGENT)).toEqual([]);
		expect(readGap(dir, AGENT, GONE_GROUP, 3, FP)).toBe(EscrowLoss.AgentRevoked);
	});
});

describe("the handoff of a sweep's losses", () => {
	it("test_sweep_when_a_pass_gave_files_up_then_the_gaps_are_reported_once_and_then_cleared", async () => {
		goneGroupFile();
		put.mockRejectedValue(
			new RineApiError(403, "no seat", undefined, "escrow_no_seat"),
		);

		const outcome = await sweepPendingEscrow(actor, NOW_S);

		expect(takeUnreported(dir, AGENT, GONE_GROUP)).toEqual(outcome.gaps);
		expect(takeUnreported(dir, AGENT, GONE_GROUP)).toEqual([]);
	});

	it("test_sweep_when_files_of_two_groups_were_given_up_then_each_group_takes_only_its_own_gaps", async () => {
		const second = "f6a7b8c9-d0e1-2345-f123-456789012345";
		goneGroupFile();
		writePending(dir, AGENT, { groupId: second, epoch: 9, fp: FP, sealed: new Uint8Array([1]) });
		state.error = new PrincipalRevokedError(RevokedScope.Agent, "agent revoked");

		await sweepPendingEscrow(actor, NOW_S);

		expect(takeUnreported(dir, AGENT, GONE_GROUP)).toEqual([
			{ epoch: 3, reason: EscrowLoss.AgentRevoked },
		]);
		expect(takeUnreported(dir, AGENT, second)).toEqual([
			{ epoch: 9, reason: EscrowLoss.AgentRevoked },
		]);
	});

	it("test_sweep_when_a_pass_gave_files_up_then_the_loss_is_logged_with_its_group", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		goneGroupFile();
		state.error = new PrincipalRevokedError(RevokedScope.Agent, "agent revoked");

		await sweepPendingEscrow(actor, NOW_S);

		expect(warn).toHaveBeenCalledTimes(1);
		expect(warn.mock.calls[0]?.[0]).toContain(GONE_GROUP);
		expect(warn.mock.calls[0]?.[0]).toContain("3 (agent_revoked)");
		warn.mockRestore();
	});

	it("test_sweep_when_a_pass_runs_inside_the_interval_then_it_notes_nothing", async () => {
		goneGroupFile();
		await sweepPendingEscrow(actor, NOW_S);
		takeUnreported(dir, AGENT, GONE_GROUP);
		goneGroupFile();

		await sweepPendingEscrow(actor, NOW_S + 1);

		expect(takeUnreported(dir, AGENT, GONE_GROUP)).toEqual([]);
	});
});

describe("deferralFor", () => {
	it("test_deferral_for_when_the_branch_is_revoked_then_it_names_the_branch", () => {
		expect(
			deferralFor(new PrincipalRevokedError(RevokedScope.Branch, "branch revoked")),
		).toBe(EscrowDeferral.BranchRevoked);
	});

	it("test_deferral_for_when_the_agent_is_revoked_then_it_names_the_agent", () => {
		expect(
			deferralFor(new PrincipalRevokedError(RevokedScope.Agent, "agent revoked")),
		).toBe(EscrowDeferral.AgentRevoked);
	});

	it("test_deferral_for_when_the_error_names_no_revocation_then_the_key_is_unavailable", () => {
		expect(deferralFor(new Error("escrow key unreachable"))).toBe(
			EscrowDeferral.KeyUnavailable,
		);
	});
});

describe("markStored clears the fork's marker", () => {
	it("test_sweep_when_the_slot_is_already_stored_then_the_forks_marker_is_cleared_and_another_forks_stays", async () => {
		goneGroupFile();
		writeGap(dir, AGENT, GONE_GROUP, { epoch: 3, reason: EscrowLoss.Refused }, FP);
		writeGap(dir, AGENT, GONE_GROUP, { epoch: 3, reason: EscrowLoss.Refused }, OTHER_FP);
		put.mockRejectedValue(
			new RineApiError(409, "slot taken", undefined, "escrow_slot_taken"),
		);

		await sweepPendingEscrow(actor, NOW_S);

		expect(fs.existsSync(markerPath(3, FP))).toBe(false);
		expect(fs.existsSync(markerPath(3, OTHER_FP))).toBe(true);
	});

	it("test_sweep_when_the_upload_succeeds_then_the_forks_marker_is_cleared_and_another_forks_stays", async () => {
		goneGroupFile();
		writeGap(dir, AGENT, GONE_GROUP, { epoch: 3, reason: EscrowLoss.Refused }, FP);
		writeGap(dir, AGENT, GONE_GROUP, { epoch: 3, reason: EscrowLoss.Refused }, OTHER_FP);

		await sweepPendingEscrow(actor, NOW_S);

		expect(fs.existsSync(markerPath(3, FP))).toBe(false);
		expect(fs.existsSync(markerPath(3, OTHER_FP))).toBe(true);
	});
});
