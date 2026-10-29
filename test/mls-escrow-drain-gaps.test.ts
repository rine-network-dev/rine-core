/**
 * The escrow drain when an installed epoch cannot be escrowed, driven against
 * the REAL native core: only the branch escrow key read is mocked.
 *
 * An epoch the core reports as a gap leaves a marker beside the pending files
 * and never fails the drain for the epochs that can be sealed.
 */
import { AllowedIdentities, EscrowGapReason, type MlsGroup } from "@rine-network/mls";
import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	key: undefined as unknown,
	error: undefined as unknown,
}));

vi.mock("../src/mls-escrow-key.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../src/mls-escrow-key.js")>()),
	resolveEscrowKey: vi.fn(async () => {
		if (state.error) throw state.error;
		return state.key;
	}),
}));

import type { VerifiedEscrowKey } from "../src/crypto/escrow.js";
import { loadAgentKeys, saveAgentKeys } from "../src/crypto/keys.js";
import { generateAgentKeys, generateEncryptionKeyPair, generatePqKeyPair } from "./helpers/keys.js";
import { mlsGroupIdBytes, mlsStoreRoot, openMlsClient } from "../src/crypto/mls.js";
import { drainEscrow } from "../src/mls-escrow-drain.js";
import { type DrainGap } from "../src/mls-escrow-gap.js";
import { readHead } from "../src/mls-escrow-head.js";
import { readGap } from "../src/mls-escrow-markers.js";
import { BranchRevokedError } from "../src/mls-escrow-key.js";
import { listPending } from "../src/mls-escrow-pending.js";
import { EscrowDeferral, reportOf } from "../src/mls-escrow-report.js";

/** A fingerprint no marker is filed under, so a read sees only fork-less markers. */
const NO_FORK_FP = new Uint8Array(16);

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const ORG_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";

/** The core's escrow limits (rine-mls-core `MAX_LEAVES`, the vendored queue cap). */
const MAX_LEAVES = 1000;
const QUEUE_CAP = 32;
/** Growing a tree past 1000 leaves takes some seconds of real key generation. */
const LARGE_TREE_TIMEOUT_MS = 120_000;
/**
 * Sealing a full queue mints QUEUE_CAP real epochs: about 2.6 s alone, which crosses vitest's
 * 5 s default in the parallel suite. The margin is for load, not for a slower drain.
 */
const FULL_QUEUE_TIMEOUT_MS = 30_000;

let dir: string;
let allowed: AllowedIdentities;
let put: ReturnType<typeof vi.fn>;
let actor: { configDir: string; agentId: string; client: never };

/** Register one more agent that the group may admit, returning its key package. */
function peerKeyPackage(): Uint8Array {
	const id = randomUUID();
	saveAgentKeys(dir, id, generateAgentKeys());
	const { mls, keyGen } = loadAgentKeys(dir, id);
	allowed.insert(Buffer.from(id), mls.publicKey, keyGen);
	return openMlsClient(dir, id, { allowed }).generateKeyPackage();
}

function newGroup(): MlsGroup {
	return openMlsClient(dir, AGENT, { allowed }).createGroup(mlsGroupIdBytes(GROUP_ID));
}

/** Install `count` more epochs, one new member each, without draining. */
function installEpochs(group: MlsGroup, count: number): void {
	for (let n = 0; n < count; n++) group.addMember(peerKeyPackage());
}

function reload(group: MlsGroup): MlsGroup {
	group.save();
	return openMlsClient(dir, AGENT, { allowed }).loadGroup(mlsGroupIdBytes(GROUP_ID));
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-gaps-"));
	saveAgentKeys(dir, AGENT, generateAgentKeys());
	allowed = new AllowedIdentities();
	const { mls, keyGen } = loadAgentKeys(dir, AGENT);
	allowed.insert(Buffer.from(AGENT), mls.publicKey, keyGen);
	put = vi.fn(async () => undefined);
	actor = { configDir: dir, agentId: AGENT, client: { put } as never };
	state.key = {
		orgId: ORG_ID,
		branch: "main",
		x25519: generateEncryptionKeyPair().publicKey,
		mlKem: generatePqKeyPair().publicKey,
	} satisfies VerifiedEscrowKey;
	state.error = undefined;
});

afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("drainEscrow gaps", () => {
	it("test_drain_when_more_epochs_wait_than_the_cap_files_a_marker_for_each_dropped_epoch_and_seals_the_rest", async () => {
		const extra = 3;
		const group = newGroup();
		installEpochs(group, QUEUE_CAP + extra);

		const outcome = await drainEscrow(actor, GROUP_ID, group);

		// Creation installs epochs 0 and 1; the oldest `extra + 2` were dropped.
		const dropped = Array.from({ length: extra + 2 }, (_, epoch) => epoch);
		expect(outcome.gaps.map((g) => g.epoch).sort((a, b) => a - b)).toEqual(dropped);
		for (const epoch of dropped) {
			expect(readGap(dir, AGENT, GROUP_ID, epoch, NO_FORK_FP)).toBe(EscrowGapReason.QueueOverflow);
		}
		expect(outcome.deferred).toBeUndefined();
		expect(outcome.sealed).toBe(QUEUE_CAP);
		expect(outcome.uploaded).toBe(QUEUE_CAP);
		expect(outcome.failures).toEqual([]);
		expect(listPending(dir, AGENT)).toEqual([]);
	}, FULL_QUEUE_TIMEOUT_MS);

	it("test_drain_when_the_tree_holds_over_1000_occupied_leaves_files_a_marker_and_seals_the_rest", async () => {
		const group = newGroup();
		let leaves = 1;
		const gaps: DrainGap[] = [];
		const epochsOver: number[] = [];
		let sealed = 0;
		// One drain per commit: the native queue holds 32 epochs, which a tree this
		// size outgrows if the drain waits for the end.
		while (leaves < MAX_LEAVES + 2) {
			const batch = Math.min(QUEUE_CAP, MAX_LEAVES + 2 - leaves);
			group.addMembers(Array.from({ length: batch }, peerKeyPackage));
			leaves += batch;
			if (leaves > MAX_LEAVES) epochsOver.push(group.epoch());
			const outcome = await drainEscrow(actor, GROUP_ID, group);
			gaps.push(...outcome.gaps);
			sealed += outcome.sealed;
			expect(outcome.failures).toEqual([]);
			// Every call above is synchronous or resolves on a microtask, so without a
			// turn of the event loop the worker would hold it for the whole tree and
			// miss vitest's 60 s RPC deadline on a loaded box.
			await new Promise((resolve) => setImmediate(resolve));
		}
		expect(epochsOver).toHaveLength(1);

		expect(gaps).toEqual([
			{
				epoch: epochsOver[0],
				reason: EscrowGapReason.TooManyLeaves,
				fp: expect.any(Uint8Array),
			},
		]);
		expect(readGap(dir, AGENT, GROUP_ID, epochsOver[0]!, gaps[0]!.fp!)).toBe(
			EscrowGapReason.TooManyLeaves,
		);
		expect(readGap(dir, AGENT, GROUP_ID, epochsOver[0]!, NO_FORK_FP)).toBeUndefined();
		expect(sealed).toBeGreaterThan(0);
	}, LARGE_TREE_TIMEOUT_MS);

	it("test_drain_when_the_member_is_seated_on_another_fork_at_a_lower_epoch_then_the_head_follows", async () => {
		const stateDir = mlsStoreRoot(dir, AGENT);
		const early = newGroup();
		early.save();
		const earlyState = fs.mkdtempSync(join(tmpdir(), "rine-escrow-early-"));
		fs.cpSync(stateDir, earlyState, { recursive: true });
		installEpochs(early, 4);
		await drainEscrow(actor, GROUP_ID, early);
		expect(readHead(dir, AGENT, GROUP_ID)?.epoch).toBe(early.epoch());

		// A resync or reseat puts the member back on a lower epoch of another fork.
		fs.cpSync(earlyState, stateDir, { recursive: true, force: true });
		fs.rmSync(earlyState, { recursive: true, force: true });
		const seated = reload(openMlsClient(dir, AGENT, { allowed }).loadGroup(mlsGroupIdBytes(GROUP_ID)));
		await drainEscrow(actor, GROUP_ID, seated);

		expect(seated.epoch()).toBeLessThan(early.epoch());
		expect(readHead(dir, AGENT, GROUP_ID)).toEqual({
			epoch: seated.epoch(),
			fp: seated.epochFingerprint(),
		});
	});

	it("test_drain_when_the_key_is_unavailable_reports_the_backlog_and_a_later_drain_files_the_gaps", async () => {
		const group = newGroup();
		installEpochs(group, QUEUE_CAP + 1);
		state.error = new Error("no escrow key");

		const deferred = await drainEscrow(actor, GROUP_ID, group);

		expect(deferred.deferred?.message).toBe("no escrow key");
		expect(deferred.backlog).toEqual({ queued: QUEUE_CAP, dropped: 3 });
		expect(deferred.gaps).toEqual([]);

		state.error = undefined;
		const later = await drainEscrow(actor, GROUP_ID, openMlsClient(dir, AGENT, { allowed }).loadGroup(mlsGroupIdBytes(GROUP_ID)));
		expect(later.gaps).toHaveLength(3);
		expect(later.backlog).toBeUndefined();
	});

	it("test_drain_when_the_branch_is_revoked_keeps_every_export_queued_and_reports_the_deferral", async () => {
		const group = newGroup();
		installEpochs(group, 2);
		state.error = new BranchRevokedError();

		const outcome = await drainEscrow(actor, GROUP_ID, group);

		expect(outcome.deferred).toBeInstanceOf(BranchRevokedError);
		expect(reportOf(outcome)).toEqual({
			gaps: [],
			deferral: EscrowDeferral.BranchRevoked,
			queued: 4,
			dropped: 0,
			backlogged: 0,
		});
		expect(readGap(dir, AGENT, GROUP_ID, 0, NO_FORK_FP)).toBeUndefined();
		expect(listPending(dir, AGENT)).toEqual([]);

		// Saved with the exports still in it: a later drain, once the branch's key
		// is readable again, seals every one of them.
		state.error = undefined;
		const fresh = openMlsClient(dir, AGENT, { allowed }).loadGroup(mlsGroupIdBytes(GROUP_ID));
		expect(fresh.escrowBacklog()).toEqual({ queued: 4, dropped: 0 });
		const later = await drainEscrow(actor, GROUP_ID, fresh);
		expect(later.sealed).toBe(4);
		expect(later.gaps).toEqual([]);
	});
});
