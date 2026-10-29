/**
 * The send-side escrow helpers, driven against the REAL native core.
 *
 * Only the branch escrow key read is mocked: the group, its exports and the
 * pending store are all real, so a test here fails when the sender reads a
 * stale fp, sends without an escrow, or retries more than once.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	key: undefined as unknown,
	error: undefined as unknown,
}));

vi.mock("../src/mls-escrow-key.js", () => ({
	BranchRevokedError: class BranchRevokedError extends Error {},
	resolveEscrowKey: vi.fn(async () => {
		if (state.error) throw state.error;
		return state.key;
	}),
}));

vi.mock("../src/mls-orphans.js", () => ({
	reclaimOrphanLeaves: vi.fn(async () => undefined),
}));

import { EscrowGapReason, type MlsGroup } from "@rine-network/mls";
import type { VerifiedEscrowKey } from "../src/crypto/escrow.js";
import { saveAgentKeys, toBase64Url } from "../src/crypto/keys.js";
import { generateAgentKeys, generateEncryptionKeyPair, generatePqKeyPair } from "./helpers/keys.js";
import { mlsGroupIdBytes, mlsStoreRoot, openMlsClient } from "../src/crypto/mls.js";
import { EscrowGapError, RineApiError } from "../src/errors.js";
import { writeGap } from "../src/mls-escrow-gap.js";
import { resetProcessGates } from "../src/process-gate.js";
import { reclaimOrphanLeaves } from "../src/mls-orphans.js";
import {
	EscrowUnavailableError,
	postWithEscrowRetry,
	prepareEscrowForSend,
} from "../src/mls-escrow-send.js";
import { readHead, writeHead } from "../src/mls-escrow-head.js";
import { listPending } from "../src/mls-escrow-pending.js";

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
 * A group at epoch 1 as a restarted process finds it: AGENT founded it and
 * admitted PEER, and the saved snapshot still holds the escrow exports of both
 * epochs.
 */
function groupAtEpochOne(): MlsGroup {
	const pkg = openMlsClient(dir, PEER).generateKeyPackage();
	openMlsClient(dir, AGENT)
		.createGroupWithMembers(mlsGroupIdBytes(GROUP_ID), [pkg])
		.save();
	return openMlsClient(dir, AGENT).loadGroup(mlsGroupIdBytes(GROUP_ID));
}

/** The head record path, so a test can delete it. */
function headPath(): string {
	return join(mlsStoreRoot(dir, AGENT), "escrow-head", `${GROUP_ID}.json`);
}

/** The server's 409 for a send whose escrow is not uploaded. */
function escrowMissing(): RineApiError {
	return new RineApiError(409, "escrow missing", undefined, "escrow_missing");
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-send-"));
	saveAgentKeys(dir, AGENT, generateAgentKeys());
	saveAgentKeys(dir, PEER, generateAgentKeys());
	put = vi.fn(async () => undefined);
	actor = { configDir: dir, agentId: AGENT, client: { put } as never };
	state.key = escrowKey();
	state.error = undefined;
	resetProcessGates();
	vi.mocked(reclaimOrphanLeaves).mockClear();
});

afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("prepareEscrowForSend", () => {
	it("test_prepare_escrow_for_send_when_drained_returns_fp_of_current_epoch", async () => {
		groupAtEpochOne();

		const fp = await prepareEscrowForSend(actor, GROUP_ID);

		const head = readHead(dir, AGENT, GROUP_ID);
		expect(head?.epoch).toBe(1);
		expect(fp).toBe(toBase64Url(head!.fp));
		expect(put).toHaveBeenCalledWith(
			`/groups/${GROUP_ID}/mls/escrow/1`,
			expect.anything(),
			{ "X-Rine-Agent": AGENT },
		);
	});

	it("test_prepare_escrow_for_send_when_escrow_key_unavailable_throws_escrow_unavailable_with_cause", async () => {
		groupAtEpochOne();
		const deferral = new Error("branch revoked");
		state.error = deferral;

		const err = await prepareEscrowForSend(actor, GROUP_ID).catch((e) => e);

		expect(err).toBeInstanceOf(EscrowUnavailableError);
		expect((err as EscrowUnavailableError).cause).toBe(deferral);
		expect(put).not.toHaveBeenCalled();
	});

	it("test_prepare_escrow_for_send_when_the_head_is_current_and_the_key_read_fails_then_it_still_returns_the_fp", async () => {
		groupAtEpochOne();
		const fp = await prepareEscrowForSend(actor, GROUP_ID);
		state.error = new Error("escrow key read failed");

		expect(await prepareEscrowForSend(actor, GROUP_ID)).toBe(fp);
	});

	it("test_prepare_escrow_for_send_when_head_is_behind_the_group_throws", async () => {
		groupAtEpochOne();
		// Drain once so the exports are consumed and the head is written, then
		// lose the head: the group is at epoch 1 and nothing remembers its fp.
		await prepareEscrowForSend(actor, GROUP_ID);
		fs.rmSync(headPath());

		const err = await prepareEscrowForSend(actor, GROUP_ID).catch((e) => e);

		expect(err).toBeInstanceOf(EscrowUnavailableError);
	});

	it("test_prepare_escrow_for_send_when_the_epoch_has_a_gap_then_it_throws_a_typed_gap_error", async () => {
		groupAtEpochOne();
		await prepareEscrowForSend(actor, GROUP_ID);
		fs.rmSync(headPath());
		writeGap(dir, AGENT, GROUP_ID, { epoch: 1, reason: EscrowGapReason.QueueOverflow });

		const err = await prepareEscrowForSend(actor, GROUP_ID).catch((e) => e);

		expect(err).toBeInstanceOf(EscrowGapError);
		expect(err).toMatchObject({ groupId: GROUP_ID, epoch: 1, reason: EscrowGapReason.QueueOverflow });
		expect(reclaimOrphanLeaves).not.toHaveBeenCalled();
	});

	it("test_prepare_escrow_for_send_when_only_another_fork_has_a_gap_then_the_send_is_retryable", async () => {
		const group = groupAtEpochOne();
		await prepareEscrowForSend(actor, GROUP_ID);
		fs.rmSync(headPath());
		const other = group.epochFingerprint().map((byte) => byte ^ 0xff);
		writeGap(dir, AGENT, GROUP_ID, { epoch: 1, reason: EscrowGapReason.Malformed }, other);

		const err = await prepareEscrowForSend(actor, GROUP_ID).catch((e) => e);

		expect(err).toBeInstanceOf(EscrowUnavailableError);
	});

	it("test_prepare_escrow_for_send_when_the_live_fork_has_a_gap_then_it_throws_a_typed_gap_error", async () => {
		const group = groupAtEpochOne();
		await prepareEscrowForSend(actor, GROUP_ID);
		fs.rmSync(headPath());
		writeGap(
			dir,
			AGENT,
			GROUP_ID,
			{ epoch: 1, reason: EscrowGapReason.Malformed },
			group.epochFingerprint(),
		);

		const err = await prepareEscrowForSend(actor, GROUP_ID).catch((e) => e);

		expect(err).toMatchObject({ groupId: GROUP_ID, epoch: 1, reason: EscrowGapReason.Malformed });
	});

	it("test_prepare_escrow_for_send_when_the_head_names_another_fork_of_the_epoch_then_it_does_not_vouch", async () => {
		const group = groupAtEpochOne();
		await prepareEscrowForSend(actor, GROUP_ID);
		const other = group.epochFingerprint().map((byte) => byte ^ 0xff);
		writeHead(dir, AGENT, GROUP_ID, { epoch: 1, fp: other });

		const err = await prepareEscrowForSend(actor, GROUP_ID).catch((e) => e);

		expect(err).toBeInstanceOf(EscrowUnavailableError);
		expect((err as Error).message).toContain("epoch 1 on another fork");
	});

	it("test_prepare_escrow_for_send_when_the_head_names_another_fork_and_a_fork_less_marker_exists_then_it_throws_a_typed_gap_error", async () => {
		const group = groupAtEpochOne();
		await prepareEscrowForSend(actor, GROUP_ID);
		const other = group.epochFingerprint().map((byte) => byte ^ 0xff);
		writeHead(dir, AGENT, GROUP_ID, { epoch: 1, fp: other });
		writeGap(dir, AGENT, GROUP_ID, { epoch: 1, reason: EscrowGapReason.Malformed });

		const err = await prepareEscrowForSend(actor, GROUP_ID).catch((e) => e);

		expect(err).toMatchObject({ groupId: GROUP_ID, epoch: 1, reason: EscrowGapReason.Malformed });
	});

	it("test_prepare_escrow_for_send_when_the_gap_is_too_many_leaves_then_it_reclaims_once_and_reports_the_gap", async () => {
		groupAtEpochOne();
		await prepareEscrowForSend(actor, GROUP_ID);
		fs.rmSync(headPath());
		writeGap(dir, AGENT, GROUP_ID, { epoch: 1, reason: EscrowGapReason.TooManyLeaves });

		const first = await prepareEscrowForSend(actor, GROUP_ID).catch((e) => e);
		const second = await prepareEscrowForSend(actor, GROUP_ID).catch((e) => e);

		expect(first).toBeInstanceOf(EscrowGapError);
		expect(second).toBeInstanceOf(EscrowGapError);
		expect(reclaimOrphanLeaves).toHaveBeenCalledTimes(1);
	});

	it("test_prepare_escrow_for_send_when_the_reclaim_clears_the_gap_then_the_send_proceeds", async () => {
		const group = groupAtEpochOne();
		await prepareEscrowForSend(actor, GROUP_ID);
		fs.rmSync(headPath());
		writeGap(dir, AGENT, GROUP_ID, { epoch: 1, reason: EscrowGapReason.TooManyLeaves });
		vi.mocked(reclaimOrphanLeaves).mockImplementationOnce(async () => {
			// The reclamation's commit drains an epoch whose head is current.
			writeHead(dir, AGENT, GROUP_ID, { epoch: 1, fp: group.epochFingerprint() });
			return undefined as never;
		});

		await expect(prepareEscrowForSend(actor, GROUP_ID)).resolves.toBeTypeOf("string");
		expect(reclaimOrphanLeaves).toHaveBeenCalledTimes(1);
	});
});

describe("postWithEscrowRetry", () => {
	it("test_post_with_escrow_retry_when_409_escrow_missing_uploads_pending_and_reposts_the_same_fp", async () => {
		groupAtEpochOne();
		put.mockRejectedValueOnce(new RineApiError(500, "unavailable"));
		const fp = await prepareEscrowForSend(actor, GROUP_ID);
		// The 5xx stopped the group's pass, so both epochs' files are still pending.
		expect(listPending(dir, AGENT, GROUP_ID)).toHaveLength(2);
		const post = vi
			.fn<(fp: string) => Promise<string>>()
			.mockRejectedValueOnce(escrowMissing())
			.mockResolvedValueOnce("sent");

		const result = await postWithEscrowRetry(actor, GROUP_ID, fp, post);

		expect(result).toBe("sent");
		expect(post.mock.calls.map((call) => call[0])).toEqual([fp, fp]);
		expect(listPending(dir, AGENT, GROUP_ID)).toEqual([]);
	});

	it("test_post_with_escrow_retry_when_409_escrow_missing_twice_surfaces_the_second_error_and_posts_exactly_twice", async () => {
		groupAtEpochOne();
		const second = escrowMissing();
		const post = vi
			.fn<(fp: string) => Promise<string>>()
			.mockRejectedValueOnce(escrowMissing())
			.mockRejectedValueOnce(second);

		const err = await postWithEscrowRetry(actor, GROUP_ID, "stale", post).catch(
			(e) => e,
		);

		expect(err).toBe(second);
		expect(post).toHaveBeenCalledTimes(2);
	});

	it("test_post_with_escrow_retry_when_other_error_does_not_retry", async () => {
		groupAtEpochOne();
		const failure = new RineApiError(500, "unavailable");
		const post = vi
			.fn<(fp: string) => Promise<string>>()
			.mockRejectedValueOnce(failure);

		const err = await postWithEscrowRetry(actor, GROUP_ID, "stale", post).catch(
			(e) => e,
		);

		expect(err).toBe(failure);
		expect(post).toHaveBeenCalledTimes(1);
	});
});
