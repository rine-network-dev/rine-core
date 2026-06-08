import * as fs from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	generateAgentKeys,
	saveAgentKeys,
} from "../src/crypto/keys.js";
import { saveMlsState } from "../src/crypto/mls-state.js";

// ── Mock ts-mls decode (used by processMlsWelcomes) ────────────────────────

const MOCK_KP_REF = new Uint8Array([7, 8, 9]);
const MOCK_KP_REF_HEX = Buffer.from(MOCK_KP_REF).toString("hex");

vi.mock("ts-mls", () => {
	// Defined INSIDE the factory: vi.mock is hoisted above top-level declarations.
	class MockMlsError extends Error {
		constructor(message?: string) {
			super(message);
			this.name = "MlsError";
		}
	}
	return {
		decode: vi.fn(() => ({
			wireformat: 3, // mls_welcome
			welcome: {
				cipherSuite: 1,
				secrets: [{ newMember: MOCK_KP_REF }],
				encryptedGroupInfo: new Uint8Array([0]),
			},
		})),
		mlsMessageDecoder: {},
		wireformats: { mls_welcome: 3 },
		MlsError: MockMlsError,
	};
});

// ── Mock mls-state (partial — keep real save/load, mock key package fns) ────

vi.mock("../src/crypto/mls-state.js", async () => {
	const actual = await vi.importActual("../src/crypto/mls-state.js");
	return {
		...actual,
		listPrivateKeyPackages: vi.fn(() => [
			{
				ref: MOCK_KP_REF_HEX,
				publicBlob: new Uint8Array([1, 2, 3]),
				privateBlob: new Uint8Array([4, 5, 6]),
			},
		]),
		deletePrivateKeyPackage: vi.fn(),
		savePrivateKeyPackages: vi.fn(),
	};
});

// ── Mock MLS crypto stubs ────────────────────────────────────────────────────

vi.mock("../src/crypto/mls.js", () => ({
	generateMlsKeyPackage: vi.fn(async () => ({
		publicBlob: new Uint8Array([1, 2, 3]),
		privateBlob: new Uint8Array([4, 5, 6]),
		keyPackageRef: new Uint8Array([7, 8, 9]),
	})),
	createMlsGroup: vi.fn(async () => ({
		stateBlob: new Uint8Array([10, 20]),
		groupInfo: new Uint8Array([30, 40]),
		commitBlob: new Uint8Array([50, 60]),
		epoch: 1,
	})),
	addMemberToMlsGroup: vi.fn(async () => ({
		commitBlob: new Uint8Array([70, 80]),
		welcomeBlob: new Uint8Array([90, 100]),
		updatedState: new Uint8Array([110, 120]),
		groupInfo: new Uint8Array([130, 140]),
		epoch: 2,
	})),
	// groupId here is the MLS-INTERNAL group id (decoded from the ratchet tree).
	// It deliberately differs from the rine group UUID on the welcome delivery
	// below — processMlsWelcomes must key state by the rine UUID, not this value.
	processMlsWelcome: vi.fn(async () => ({
		stateBlob: new Uint8Array([1, 2]),
		groupId: "mls-internal-id-not-a-rine-uuid",
		epoch: 0,
		cipherSuite: 1,
	})),
	processMlsCommit: vi.fn(async () => ({
		updatedState: new Uint8Array([3, 4]),
		epoch: 1,
	})),
	removeMemberFromMlsGroup: vi.fn(async () => ({
		commitBlob: new Uint8Array([5, 6]),
		updatedState: new Uint8Array([7, 8]),
		groupInfo: new Uint8Array([15, 16]),
		epoch: 1,
	})),
	externalJoinMlsGroup: vi.fn(async () => ({
		commitBlob: new Uint8Array([21, 22]),
		stateBlob: new Uint8Array([23, 24]),
		groupInfo: new Uint8Array([25, 26]),
		epoch: 2,
	})),
	VERSION_MLS: 0x04,
}));

// ── Mock MLS API ─────────────────────────────────────────────────────────────

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual("../src/crypto/mls-api.js");
	return {
		...actual,
		uploadKeyPackages: vi.fn(async () => ({ stored: 10 })),
		claimKeyPackages: vi.fn(async () => ({
			packages: [Buffer.from(new Uint8Array([1, 2, 3])).toString("base64")],
			agent_id: "member-uuid",
		})),
		mlsInit: vi.fn(async () => ({
			mls_pending: true,
			members: [
				{ agent_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", has_key_package: true },
				{ agent_id: "b2c3d4e5-f6a7-8901-bcde-f12345678901", has_key_package: true },
			],
		})),
		mlsCommit: vi.fn(async () => ({ epoch: 0, delivered_to: 1 })),
		mlsAck: vi.fn(async () => ({ confirmed: true, acks: 1, needed: 1 })),
		mlsNack: vi.fn(async () => ({ quarantined: true })),
		fetchHandshakes: vi.fn(async () => ({
			handshakes: [
				{
					id: "h1",
					epoch: 1,
					blob: Buffer.from(new Uint8Array([1])).toString("base64"),
					created_at: "2026-01-01T00:00:00Z",
				},
			],
		})),
		fetchWelcomes: vi.fn(async () => ({
			welcomes: [
				{
					id: "w1",
					group_id: "e4f5a6b7-c8d9-0123-abcd-ef1234567890",
					blob: Buffer.from(new Uint8Array([1])).toString("base64"),
					created_at: "2026-01-01T00:00:00Z",
				},
			],
		})),
		fetchGroupInfo: vi.fn(async () => ({
			group_info: Buffer.from(new Uint8Array([1, 2])).toString("base64"),
			epoch: 1,
		})),
	};
});

// ── Import ops (AFTER mocks) ────────────────────────────────────────────────

import {
	publishMlsKeyPackages,
	initMlsGroup,
	addMlsGroupMember,
	removeMlsGroupMember,
	externalJoinMlsGroup,
	processMlsWelcomes,
	syncMlsGroup,
} from "../src/mls-ops.js";
import {
	uploadKeyPackages,
	claimKeyPackages,
	mlsInit,
	mlsCommit,
	mlsAck,
	mlsNack,
	fetchHandshakes,
	fetchWelcomes,
	fetchGroupInfo,
} from "../src/crypto/mls-api.js";
import { MlsError } from "ts-mls";
import {
	generateMlsKeyPackage,
	createMlsGroup,
	addMemberToMlsGroup,
	removeMemberFromMlsGroup,
	externalJoinMlsGroup as cryptoExternalJoin,
	processMlsWelcome,
	processMlsCommit,
} from "../src/crypto/mls.js";
import { loadMlsState } from "../src/crypto/mls-state.js";
import { RineApiError } from "../src/errors.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

const SELF_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const MEMBER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-mlsops-test-"));
}

function setupAgent(dir: string, agentId: string) {
	const keys = generateAgentKeys();
	saveAgentKeys(dir, agentId, keys);
	return keys;
}

function makeMockClient() {
	return {
		get: vi.fn().mockResolvedValue({}),
		post: vi.fn().mockResolvedValue({}),
	};
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("publishMlsKeyPackages", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, SELF_ID);
		vi.clearAllMocks();
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("generates and uploads the requested number of key packages", async () => {
		const client = makeMockClient();
		const result = await publishMlsKeyPackages(dir, SELF_ID, client as never, 5);
		expect(result).toEqual({ stored: 10 });
		expect(generateMlsKeyPackage).toHaveBeenCalledTimes(5);
		expect(uploadKeyPackages).toHaveBeenCalledTimes(1);
		const call = vi.mocked(uploadKeyPackages).mock.calls[0]!;
		expect(call[1]).toBe(SELF_ID);
		expect(call[2]).toHaveLength(5);
	});

	it("defaults to 10 key packages", async () => {
		const client = makeMockClient();
		await publishMlsKeyPackages(dir, SELF_ID, client as never);
		expect(generateMlsKeyPackage).toHaveBeenCalledTimes(10);
		const call = vi.mocked(uploadKeyPackages).mock.calls[0]!;
		expect(call[2]).toHaveLength(10);
	});
});

describe("initMlsGroup", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, SELF_ID);
		vi.clearAllMocks();
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("initializes group with all eligible members", async () => {
		const client = makeMockClient();
		const result = await initMlsGroup(dir, SELF_ID, GROUP_ID, client as never);

		// mlsInit called to get member list
		expect(mlsInit).toHaveBeenCalledWith(client, GROUP_ID, undefined);

		// createMlsGroup called with signing key
		expect(createMlsGroup).toHaveBeenCalledTimes(1);
		const createCall = vi.mocked(createMlsGroup).mock.calls[0]!;
		expect(createCall[0]).toBeInstanceOf(Uint8Array);

		// claimKeyPackages called for the eligible member (not self)
		expect(claimKeyPackages).toHaveBeenCalledTimes(1);
		expect(claimKeyPackages).toHaveBeenCalledWith(client, MEMBER_ID);

		// addMemberToMlsGroup called for eligible member
		expect(addMemberToMlsGroup).toHaveBeenCalledTimes(1);

		// mlsCommit called with welcomes and group_info
		expect(mlsCommit).toHaveBeenCalledTimes(1);
		const commitCall = vi.mocked(mlsCommit).mock.calls[0]!;
		expect(commitCall[1]).toBe(GROUP_ID);
		expect(commitCall[2].welcomes).toHaveLength(1);
		expect(commitCall[2].welcomes![0]!.agent_id).toBe(MEMBER_ID);
		expect(commitCall[2].group_info).toBeDefined();
		// One add after create(epoch 1) advances to the committed epoch 2.
		expect(commitCall[2].epoch).toBe(2);

		// State saved to disk
		const saved = loadMlsState(dir, SELF_ID, GROUP_ID);
		expect(saved).not.toBeNull();
		expect(saved!.metadata.groupId).toBe(GROUP_ID);
		expect(saved!.metadata.epoch).toBe(0);

		expect(result.epoch).toBe(0);
		expect(result.membersAdded).toBe(1);
	});
});

describe("addMlsGroupMember", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, SELF_ID);
		vi.clearAllMocks();
		// Pre-save MLS state
		saveMlsState(dir, SELF_ID, GROUP_ID, new Uint8Array([10, 20]), {
			groupId: GROUP_ID,
			epoch: 0,
			cipherSuite: 1,
		});
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("claims key package, adds member, commits, and updates state", async () => {
		const client = makeMockClient();
		const result = await addMlsGroupMember(
			dir, SELF_ID, GROUP_ID, MEMBER_ID, client as never,
		);

		expect(claimKeyPackages).toHaveBeenCalledWith(client, MEMBER_ID);
		expect(addMemberToMlsGroup).toHaveBeenCalledTimes(1);
		expect(mlsCommit).toHaveBeenCalledTimes(1);

		const commitCall = vi.mocked(mlsCommit).mock.calls[0]!;
		expect(commitCall[2].welcomes).toHaveLength(1);
		expect(commitCall[2].welcomes![0]!.agent_id).toBe(MEMBER_ID);
		// A fresh GroupInfo is published on the add commit so the next external
		// joiner self-joins against the new epoch.
		expect(commitCall[2].group_info).toBeDefined();
		// The add commit carries its committed epoch (crypto-owned).
		expect(commitCall[2].epoch).toBe(2);

		// State was updated on disk
		const saved = loadMlsState(dir, SELF_ID, GROUP_ID);
		expect(saved).not.toBeNull();
		expect(Buffer.from(saved!.stateBlob).equals(Buffer.from(new Uint8Array([110, 120])))).toBe(true);

		expect(result.epoch).toBe(0);
	});

	it("throws when no MLS state exists", async () => {
		const freshDir = makeTmpDir();
		setupAgent(freshDir, SELF_ID);
		const client = makeMockClient();

		await expect(
			addMlsGroupMember(freshDir, SELF_ID, GROUP_ID, MEMBER_ID, client as never),
		).rejects.toThrow(`No MLS state for group ${GROUP_ID}`);

		fs.rmSync(freshDir, { recursive: true, force: true });
	});
});

describe("removeMlsGroupMember", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, SELF_ID);
		vi.clearAllMocks();
		saveMlsState(dir, SELF_ID, GROUP_ID, new Uint8Array([10, 20]), {
			groupId: GROUP_ID,
			epoch: 0,
			cipherSuite: 1,
		});
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("removes member by leaf index, commits, and updates state", async () => {
		const client = makeMockClient();
		const result = await removeMlsGroupMember(
			dir, SELF_ID, GROUP_ID, 2, client as never,
		);

		expect(removeMemberFromMlsGroup).toHaveBeenCalledWith(
			new Uint8Array([10, 20]), 2,
		);
		expect(mlsCommit).toHaveBeenCalledTimes(1);
		// Remove also republishes a fresh GroupInfo for the next external joiner.
		expect(vi.mocked(mlsCommit).mock.calls[0]![2].group_info).toBeDefined();
		// The remove commit carries its committed epoch (crypto-owned).
		expect(vi.mocked(mlsCommit).mock.calls[0]![2].epoch).toBe(1);

		const saved = loadMlsState(dir, SELF_ID, GROUP_ID);
		expect(saved).not.toBeNull();
		expect(Buffer.from(saved!.stateBlob).equals(Buffer.from(new Uint8Array([7, 8])))).toBe(true);

		expect(result.epoch).toBe(0);
	});

	it("throws when no MLS state exists", async () => {
		const freshDir = makeTmpDir();
		setupAgent(freshDir, SELF_ID);
		const client = makeMockClient();

		await expect(
			removeMlsGroupMember(freshDir, SELF_ID, GROUP_ID, 2, client as never),
		).rejects.toThrow(`No MLS state for group ${GROUP_ID}`);

		fs.rmSync(freshDir, { recursive: true, force: true });
	});
});

describe("processMlsWelcomes", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, SELF_ID);
		vi.clearAllMocks();
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("fetches welcomes, processes each, and saves state", async () => {
		const client = makeMockClient();
		const result = await processMlsWelcomes(dir, SELF_ID, client as never);

		expect(fetchWelcomes).toHaveBeenCalledWith(client, SELF_ID);
		expect(processMlsWelcome).toHaveBeenCalledTimes(1);

		// Verify new 3-argument signature: welcomeBlob, publicBlob, privateBlob
		const welcomeCall = vi.mocked(processMlsWelcome).mock.calls[0]!;
		expect(welcomeCall).toHaveLength(3);
		expect(welcomeCall[1]).toEqual(new Uint8Array([1, 2, 3])); // publicBlob from stored pkg
		expect(welcomeCall[2]).toEqual(new Uint8Array([4, 5, 6])); // privateBlob from stored pkg

		// State MUST be keyed by the rine group UUID (welcome.group_id), NOT the
		// MLS-internal id returned by processMlsWelcome — otherwise
		// decryptGroupMessage(rineGroupId) / encryptMlsGroupMessage(rineGroupId)
		// would never find a joiner's state.
		const welcomeGroupId = "e4f5a6b7-c8d9-0123-abcd-ef1234567890";
		const saved = loadMlsState(dir, SELF_ID, welcomeGroupId);
		expect(saved).not.toBeNull();
		expect(saved!.metadata.groupId).toBe(welcomeGroupId);
		expect(saved!.metadata.epoch).toBe(0);
		expect(saved!.metadata.cipherSuite).toBe(1);
		// metadata.groupId is the rine UUID, never the MLS-internal id — proving
		// the welcome's group_id (not processMlsWelcome's groupId) keyed the state.

		expect(result.processed).toBe(1);
		expect(result.groupIds).toEqual(["e4f5a6b7-c8d9-0123-abcd-ef1234567890"]);
	});

	it("skips welcomes the server could not associate with a rine group", async () => {
		const client = makeMockClient();
		vi.mocked(fetchWelcomes).mockResolvedValueOnce({
			welcomes: [
				{
					id: "w-null",
					group_id: null,
					blob: Buffer.from(new Uint8Array([1])).toString("base64"),
					created_at: "2026-01-01T00:00:00Z",
				},
			],
		});
		const result = await processMlsWelcomes(dir, SELF_ID, client as never);
		expect(result.processed).toBe(0);
		expect(result.groupIds).toEqual([]);
		expect(processMlsWelcome).not.toHaveBeenCalled();
	});
});

describe("syncMlsGroup", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, SELF_ID);
		vi.clearAllMocks();
		// Pre-save MLS state at epoch 0
		saveMlsState(dir, SELF_ID, GROUP_ID, new Uint8Array([10, 20]), {
			groupId: GROUP_ID,
			epoch: 0,
			cipherSuite: 1,
		});
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("fetches handshakes since current epoch and applies commits", async () => {
		const client = makeMockClient();
		const result = await syncMlsGroup(dir, SELF_ID, GROUP_ID, client as never);

		expect(fetchHandshakes).toHaveBeenCalledWith(client, GROUP_ID, 0, undefined);
		expect(processMlsCommit).toHaveBeenCalledTimes(1);

		// State was updated on disk
		const saved = loadMlsState(dir, SELF_ID, GROUP_ID);
		expect(saved).not.toBeNull();
		expect(Buffer.from(saved!.stateBlob).equals(Buffer.from(new Uint8Array([3, 4])))).toBe(true);
		expect(saved!.metadata.epoch).toBe(1);

		expect(result.epoch).toBe(1);
		expect(result.processed).toBe(1);
	});

	it("throws when no MLS state exists", async () => {
		const freshDir = makeTmpDir();
		setupAgent(freshDir, SELF_ID);
		const client = makeMockClient();

		await expect(
			syncMlsGroup(freshDir, SELF_ID, GROUP_ID, client as never),
		).rejects.toThrow(`No MLS state for group ${GROUP_ID}`);

		fs.rmSync(freshDir, { recursive: true, force: true });
	});

	it("H4: emits an ACK after cleanly processing a commit", async () => {
		const client = makeMockClient();
		await syncMlsGroup(dir, SELF_ID, GROUP_ID, client as never);

		// The clean commit (handshake "h1") is ACKed, never NACKed.
		expect(mlsAck).toHaveBeenCalledTimes(1);
		const ackCall = vi.mocked(mlsAck).mock.calls[0]!;
		expect(ackCall[1]).toBe(GROUP_ID);
		expect(ackCall[2]).toEqual({ object_id: "h1" });
		expect(mlsNack).not.toHaveBeenCalled();
	});

	it("H4: emits a NACK and saves NO state when a commit cannot be processed", async () => {
		const client = makeMockClient();
		vi.mocked(processMlsCommit).mockRejectedValueOnce(
			new MlsError("cannot process commit"),
		);

		const result = await syncMlsGroup(dir, SELF_ID, GROUP_ID, client as never);

		// NACK emitted for the un-processable handshake; no ACK.
		expect(mlsNack).toHaveBeenCalledTimes(1);
		const nackCall = vi.mocked(mlsNack).mock.calls[0]!;
		expect(nackCall[1]).toBe(GROUP_ID);
		expect(nackCall[2].object_id).toBe("h1");
		expect(nackCall[2].epoch).toBe(1);
		expect(mlsAck).not.toHaveBeenCalled();

		// Aborted: no commit processed → epoch unchanged, no advance persisted.
		expect(result.processed).toBe(0);
		const saved = loadMlsState(dir, SELF_ID, GROUP_ID);
		expect(saved!.metadata.epoch).toBe(0);
		expect(
			Buffer.from(saved!.stateBlob).equals(Buffer.from(new Uint8Array([10, 20]))),
		).toBe(true);
	});

	it("H4 (MEDIUM-1): orphaned local epoch is discarded + re-bootstrapped, NOT NACK-looped", async () => {
		const client = makeMockClient();
		// Local state is ahead (epoch 2) of the server's confirmed epoch (1):
		// our own tentative self-join was rolled back, so our branch is orphaned.
		saveMlsState(dir, SELF_ID, GROUP_ID, new Uint8Array([99, 99]), {
			groupId: GROUP_ID,
			epoch: 2,
			cipherSuite: 1,
		});
		// The fetched handshake (epoch 1, since_epoch=2 still returns the mock's
		// h1) cannot apply to our orphaned branch → MlsError.
		vi.mocked(processMlsCommit).mockRejectedValueOnce(
			new MlsError("cannot process on orphaned branch"),
		);
		// Server's confirmed GroupInfo is at epoch 1 — BELOW our local epoch 2,
		// the orphan signal.
		vi.mocked(fetchGroupInfo).mockResolvedValueOnce({
			group_info: Buffer.from(new Uint8Array([1, 2])).toString("base64"),
			epoch: 1,
		});
		// The re-bootstrap external join then succeeds.
		vi.mocked(fetchGroupInfo).mockResolvedValueOnce({
			group_info: Buffer.from(new Uint8Array([1, 2])).toString("base64"),
			epoch: 1,
		});
		vi.mocked(mlsCommit).mockResolvedValueOnce({ epoch: 2, delivered_to: 1 });

		await syncMlsGroup(dir, SELF_ID, GROUP_ID, client as never);

		// CRUX: no NACK was emitted — the failure was our orphaned state, not a
		// garbage commit. (This is the per-member denial-of-participation fix.)
		expect(mlsNack).not.toHaveBeenCalled();
		expect(mlsAck).not.toHaveBeenCalled();
		// Re-bootstrapped: the external join posted a fresh commit and saveMlsState
		// overwrote the stale branch with the new epoch.
		expect(cryptoExternalJoin).toHaveBeenCalledTimes(1);
		const saved = loadMlsState(dir, SELF_ID, GROUP_ID);
		expect(saved).not.toBeNull();
	});

	it("H4: a mid-flight re-join failure leaves stale state intact (no permanent strand)", async () => {
		const client = makeMockClient();
		// Orphaned local branch at epoch 2 (our tentative self-join was rolled back).
		saveMlsState(dir, SELF_ID, GROUP_ID, new Uint8Array([99, 99]), {
			groupId: GROUP_ID,
			epoch: 2,
			cipherSuite: 1,
		});
		// The peer commit cannot apply to our orphaned branch → MlsError.
		vi.mocked(processMlsCommit).mockRejectedValueOnce(
			new MlsError("cannot process on orphaned branch"),
		);
		// Server confirmed epoch 1 < local 2 → orphan signal (reconcile fetch).
		vi.mocked(fetchGroupInfo).mockResolvedValueOnce({
			group_info: Buffer.from(new Uint8Array([1, 2])).toString("base64"),
			epoch: 1,
		});
		// The re-join's own GroupInfo fetch succeeds...
		vi.mocked(fetchGroupInfo).mockResolvedValueOnce({
			group_info: Buffer.from(new Uint8Array([1, 2])).toString("base64"),
			epoch: 1,
		});
		// ...but the re-join commit fails mid-flight (server unreachable). Pre-fix
		// this happened AFTER deleteMlsState → the agent was stranded stateless.
		vi.mocked(mlsCommit).mockRejectedValueOnce(new Error("server unreachable"));

		await expect(
			syncMlsGroup(dir, SELF_ID, GROUP_ID, client as never),
		).rejects.toThrow("server unreachable");

		// CRUX: the stale local state SURVIVES, so the next sync can retry the
		// re-join instead of throwing "No MLS state for group".
		const saved = loadMlsState(dir, SELF_ID, GROUP_ID);
		expect(saved).not.toBeNull();
		expect(saved!.metadata.epoch).toBe(2);
		expect(
			Buffer.from(saved!.stateBlob).equals(Buffer.from(new Uint8Array([99, 99]))),
		).toBe(true);
		// It was an orphan, not garbage — no NACK was emitted.
		expect(mlsNack).not.toHaveBeenCalled();
	});

	it("H4: emits neither ACK nor NACK on a transport error (rethrows)", async () => {
		const client = makeMockClient();
		// A non-MlsError (e.g. network) must NOT be a NACK — it should rethrow so
		// the next sync retries, with no ACK/NACK side-effect.
		vi.mocked(processMlsCommit).mockRejectedValueOnce(new Error("network down"));

		await expect(
			syncMlsGroup(dir, SELF_ID, GROUP_ID, client as never),
		).rejects.toThrow("network down");
		expect(mlsAck).not.toHaveBeenCalled();
		expect(mlsNack).not.toHaveBeenCalled();
	});
});

describe("externalJoinMlsGroup (orchestrator)", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, SELF_ID);
		vi.clearAllMocks();
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("fetches GroupInfo, external-joins, posts commit+group_info, saves state by rine UUID", async () => {
		const client = makeMockClient();
		const result = await externalJoinMlsGroup(dir, SELF_ID, GROUP_ID, client as never);

		expect(fetchGroupInfo).toHaveBeenCalledWith(client, GROUP_ID, undefined);
		expect(cryptoExternalJoin).toHaveBeenCalledTimes(1);

		// Posts the public external commit AND a fresh GroupInfo for the next joiner.
		const commitCall = vi.mocked(mlsCommit).mock.calls[0]!;
		expect(commitCall[1]).toBe(GROUP_ID);
		expect(commitCall[2].commit).toBeDefined();
		expect(commitCall[2].group_info).toBeDefined();
		expect(commitCall[2].epoch).toBe(2);

		// State keyed by the RINE group UUID so encrypt/decryptGroupMessage find it.
		const saved = loadMlsState(dir, SELF_ID, GROUP_ID);
		expect(saved).not.toBeNull();
		expect(saved!.metadata.groupId).toBe(GROUP_ID);
		expect(result.epoch).toBe(0); // server-reported epoch from mlsCommit mock
	});

	it("throws a clear error when no GroupInfo is published", async () => {
		vi.mocked(fetchGroupInfo).mockResolvedValue({ group_info: null, epoch: null });
		const client = makeMockClient();
		await expect(
			externalJoinMlsGroup(dir, SELF_ID, GROUP_ID, client as never),
		).rejects.toThrow("no published GroupInfo");
	});

	it("retries once on an epoch conflict, then resolves when the second commit succeeds", async () => {
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: Buffer.from(new Uint8Array([1, 2])).toString("base64"),
			epoch: 1,
		});
		vi.mocked(mlsCommit)
			.mockRejectedValueOnce(
				new RineApiError(409, "MLS epoch conflict", undefined, "epoch_conflict"),
			)
			.mockResolvedValueOnce({ epoch: 3, delivered_to: 1 });
		const client = makeMockClient();
		const result = await externalJoinMlsGroup(dir, SELF_ID, GROUP_ID, client as never);
		expect(result.epoch).toBe(3);
		// Two attempts => GroupInfo fetched twice (discard-and-rebuild).
		expect(fetchGroupInfo).toHaveBeenCalledTimes(2);
		expect(mlsCommit).toHaveBeenCalledTimes(2);
	});

	it("retries once on an epoch conflict, then surfaces a terminal error on a second conflict", async () => {
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: Buffer.from(new Uint8Array([1, 2])).toString("base64"),
			epoch: 1,
		});
		vi.mocked(mlsCommit).mockRejectedValue(
			new RineApiError(409, "MLS epoch conflict", undefined, "epoch_conflict"),
		);
		const client = makeMockClient();
		await expect(
			externalJoinMlsGroup(dir, SELF_ID, GROUP_ID, client as never),
		).rejects.toThrow("after one retry");
		expect(fetchGroupInfo).toHaveBeenCalledTimes(2);
	});

	it("H4: retries briefly on pending_confirmation, then joins once confirmed", async () => {
		vi.mocked(fetchGroupInfo)
			.mockRejectedValueOnce(
				new RineApiError(409, "pending", undefined, "pending_confirmation"),
			)
			.mockResolvedValue({
				group_info: Buffer.from(new Uint8Array([1, 2])).toString("base64"),
				epoch: 1,
			});
		vi.mocked(mlsCommit).mockResolvedValue({ epoch: 2, delivered_to: 1 });
		const client = makeMockClient();
		const result = await externalJoinMlsGroup(dir, SELF_ID, GROUP_ID, client as never);
		expect(result.epoch).toBe(2);
		// First attempt was pending → retried; pending_confirmation must NOT be
		// treated as an epoch conflict (that single retry stays available).
		expect(fetchGroupInfo).toHaveBeenCalledTimes(2);
	});

	it("does NOT retry on a non-conflict error (surfaces it immediately, no misleading wrapper)", async () => {
		// fetchGroupInfo returns no group_info → attempt() throws a plain Error.
		// This is not recoverable by retrying, so it must surface without a retry.
		vi.mocked(fetchGroupInfo).mockResolvedValue({ group_info: null, epoch: null });
		const client = makeMockClient();
		await expect(
			externalJoinMlsGroup(dir, SELF_ID, GROUP_ID, client as never),
		).rejects.toThrow("no published GroupInfo");
		// Exactly one attempt: GroupInfo fetched once, never retried.
		expect(fetchGroupInfo).toHaveBeenCalledTimes(1);
		expect(mlsCommit).not.toHaveBeenCalled();
	});
});
