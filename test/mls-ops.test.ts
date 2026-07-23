/**
 * The MLS orchestrators, driven against the REAL native core.
 *
 * Only the network is mocked: `crypto/mls-api.js` stands in for the server and
 * relays the genuine commit / welcome / GroupInfo blobs the core produces
 * between two real agents. Nothing about MLS itself is faked, so a test here
 * fails when the adapter mis-pairs a welcome, saves state the server rejected,
 * or loses an epoch.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/crypto/mls-api.js")
	>("../src/crypto/mls-api.js");
	return {
		...actual,
		uploadKeyPackages: vi.fn(async (_c: unknown, _a: unknown, p: string[]) => ({
			stored: p.length,
		})),
		claimKeyPackages: vi.fn(async () => ({ packages: [], agent_id: "" })),
		mlsFromBase64: vi.fn(actual.mlsFromBase64),
		mlsInit: vi.fn(async () => ({ mls_pending: true, members: [] })),
		mlsCommit: vi.fn(async () => ({ epoch: null, delivered_to: 1 })),
		mlsAck: vi.fn(async () => ({ confirmed: true, acks: 1, needed: 1 })),
		mlsNack: vi.fn(async () => ({ quarantined: true })),
		fetchHandshakes: vi.fn(async () => ({ handshakes: [] })),
		fetchWelcomes: vi.fn(async () => ({ welcomes: [] })),
		fetchGroupInfo: vi.fn(async () => ({ group_info: null, epoch: null })),
	};
});

import { generateAgentKeys, saveAgentKeys } from "../src/crypto/keys.js";
import {
	claimKeyPackages,
	fetchGroupInfo,
	fetchHandshakes,
	fetchWelcomes,
	mlsAck,
	mlsCommit,
	mlsFromBase64,
	mlsInit,
	mlsNack,
	mlsToBase64,
	uploadKeyPackages,
} from "../src/crypto/mls-api.js";
import type { MlsCommitBody } from "../src/crypto/mls-api.js";
import { loadMlsState } from "../src/crypto/mls-state.js";
import { mlsGroupIdBytes, openMlsClient } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import {
	MLS_KEY_PACKAGE_LOW_WATER,
	MLS_KEY_PACKAGE_TARGET,
	addMlsGroupMember,
	drainAndRepublishMlsKeyPackages,
	ensureMlsKeyPackages,
	externalJoinMlsGroup,
	initMlsGroup,
	processMlsWelcomes,
	publishMlsKeyPackages,
	removeMlsGroupMember,
	syncMlsGroup,
} from "../src/mls-ops.js";

const SELF_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const MEMBER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const THIRD_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

let dir: string;
/** Every commit body the code posted, in order. */
let posted: MlsCommitBody[];

const client = {} as never;

function agent(agentId: string) {
	saveAgentKeys(dir, agentId, generateAgentKeys());
}

/** One claimable key package for `agentId`, minted by that agent's own client. */
function offerKeyPackage(agentId: string): void {
	const pkg = openMlsClient(dir, agentId).generateKeyPackage();
	vi.mocked(claimKeyPackages).mockResolvedValue({
		packages: [mlsToBase64(pkg)],
		agent_id: agentId,
	});
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-mlsops-"));
	posted = [];
	vi.clearAllMocks();
	vi.mocked(uploadKeyPackages).mockImplementation(async (_c, _a, p) => ({
		stored: p.length,
	}));
	vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => {
		posted.push(body);
		return { epoch: body.epoch ?? null, delivered_to: 1 };
	});
	vi.mocked(mlsAck).mockResolvedValue({ confirmed: true, acks: 1, needed: 1 });
	vi.mocked(mlsNack).mockResolvedValue({ quarantined: true });
	vi.mocked(fetchHandshakes).mockResolvedValue({ handshakes: [] });
	vi.mocked(fetchWelcomes).mockResolvedValue({ welcomes: [] });
	vi.mocked(fetchGroupInfo).mockResolvedValue({
		group_info: null,
		epoch: null,
	});
	agent(SELF_ID);
	agent(MEMBER_ID);
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

/** Found GROUP_ID with SELF as creator and MEMBER welcomed into it. */
async function foundGroup(): Promise<void> {
	offerKeyPackage(MEMBER_ID);
	vi.mocked(mlsInit).mockResolvedValue({
		mls_pending: true,
		members: [
			{ agent_id: SELF_ID, has_key_package: true },
			{ agent_id: MEMBER_ID, has_key_package: true },
		],
	});
	await initMlsGroup(dir, SELF_ID, GROUP_ID, client);

	const welcome = posted[0]?.welcomes?.[0]?.welcome;
	if (!welcome) throw new Error("founding commit carried no welcome");
	vi.mocked(fetchWelcomes).mockResolvedValue({
		welcomes: [
			{
				id: "w1",
				group_id: GROUP_ID,
				blob: welcome,
				created_at: "2026-01-01T00:00:00Z",
			},
		],
	});
	await processMlsWelcomes(dir, MEMBER_ID, client);
	vi.mocked(fetchWelcomes).mockResolvedValue({ welcomes: [] });
}

/** Group state for SELF only, founded locally — no HTTP, so no replenishment. */
function seedGroupState(): void {
	openMlsClient(dir, SELF_ID).createGroup(mlsGroupIdBytes(GROUP_ID)).save();
}

/** SELF's current GroupInfo, as the server would publish it. */
function currentGroupInfo(): string {
	const group = openMlsClient(dir, SELF_ID).loadGroup(
		mlsGroupIdBytes(GROUP_ID),
	);
	return mlsToBase64(group.groupInfo());
}

// ── key packages ─────────────────────────────────────────────────────────────

describe("publishMlsKeyPackages", () => {
	it("uploads the batch it was asked for and keeps every private half", async () => {
		const result = await publishMlsKeyPackages(dir, SELF_ID, client, 5);
		expect(result).toEqual({ stored: 5 });
		expect(vi.mocked(uploadKeyPackages).mock.calls[0]![2]).toHaveLength(5);
		expect(openMlsClient(dir, SELF_ID).keyPackageCount()).toBe(5);
	});

	it("defaults to the core's target inventory", async () => {
		await publishMlsKeyPackages(dir, SELF_ID, client);
		expect(vi.mocked(uploadKeyPackages).mock.calls[0]![2]).toHaveLength(
			MLS_KEY_PACKAGE_TARGET,
		);
	});
});

describe("ensureMlsKeyPackages", () => {
	it("tops the inventory back up to the target when it is below the low-water mark", async () => {
		openMlsClient(dir, SELF_ID).generateKeyPackages(1);
		const status = await ensureMlsKeyPackages(dir, SELF_ID, client);
		expect(status.available).toBe(1);
		expect(status.published).toBe(MLS_KEY_PACKAGE_TARGET - 1);
		expect(status.capReached).toBe(false);
	});

	it("is a no-op when the inventory is full", async () => {
		openMlsClient(dir, SELF_ID).generateKeyPackages(MLS_KEY_PACKAGE_TARGET);
		const status = await ensureMlsKeyPackages(dir, SELF_ID, client);
		expect(status).toEqual({
			available: MLS_KEY_PACKAGE_TARGET,
			published: 0,
			capReached: false,
		});
		expect(uploadKeyPackages).not.toHaveBeenCalled();
	});

	it("is a no-op exactly at the low-water mark", async () => {
		openMlsClient(dir, SELF_ID).generateKeyPackages(MLS_KEY_PACKAGE_LOW_WATER);
		const status = await ensureMlsKeyPackages(dir, SELF_ID, client);
		expect(status.published).toBe(0);
		expect(uploadKeyPackages).not.toHaveBeenCalled();
	});

	it("treats the server inventory cap as a no-op success, not a failure", async () => {
		openMlsClient(dir, SELF_ID).generateKeyPackages(1);
		vi.mocked(uploadKeyPackages).mockRejectedValue(
			new RineApiError(409, "key package inventory full"),
		);
		const status = await ensureMlsKeyPackages(dir, SELF_ID, client);
		expect(status).toEqual({ available: 1, published: 0, capReached: true });
	});

	it("surfaces a genuine upload failure", async () => {
		openMlsClient(dir, SELF_ID).generateKeyPackages(1);
		vi.mocked(uploadKeyPackages).mockRejectedValue(
			new RineApiError(500, "boom"),
		);
		await expect(ensureMlsKeyPackages(dir, SELF_ID, client)).rejects.toThrow(
			"boom",
		);
	});
});

describe("drainAndRepublishMlsKeyPackages", () => {
	it("replaces the whole pool rather than adding to it (SPEC DEC-7)", async () => {
		const mls = openMlsClient(dir, SELF_ID);
		const before = mls
			.generateKeyPackages(4)
			.map((p) => Buffer.from(p).toString("base64"));

		const result = await drainAndRepublishMlsKeyPackages(dir, SELF_ID, client);
		expect(result.stored).toBe(MLS_KEY_PACKAGE_TARGET);
		expect(openMlsClient(dir, SELF_ID).keyPackageCount()).toBe(
			MLS_KEY_PACKAGE_TARGET,
		);

		const published = vi.mocked(uploadKeyPackages).mock.calls[0]![2];
		expect(published).toHaveLength(MLS_KEY_PACKAGE_TARGET);
		expect(published.some((p) => before.includes(p))).toBe(false);
	});
});

// ── founding and membership ──────────────────────────────────────────────────

describe("initMlsGroup", () => {
	it("admits every eligible member in the founding commit and saves only after the server accepts", async () => {
		await foundGroup();

		expect(mlsInit).toHaveBeenCalledWith(client, GROUP_ID, undefined);
		expect(claimKeyPackages).toHaveBeenCalledWith(client, MEMBER_ID);
		expect(claimKeyPackages).toHaveBeenCalledTimes(1); // never for self
		expect(posted).toHaveLength(1);

		const body = posted[0]!;
		expect(body.welcomes).toHaveLength(1);
		expect(body.welcomes![0]!.agent_id).toBe(MEMBER_ID);
		expect(body.group_info).toBeDefined();
		expect(body.epoch).toBe(1);
		expect(body.cipher_suite).toBe(0xf057);

		expect(loadMlsState(dir, SELF_ID, GROUP_ID)).toEqual({
			groupId: GROUP_ID,
			epoch: 1,
			cipherSuite: 0xf057,
		});
	});

	it("tops up the acting agent's own inventory before founding", async () => {
		await foundGroup();
		expect(uploadKeyPackages).toHaveBeenCalledWith(
			client,
			SELF_ID,
			expect.any(Array),
		);
	});
});

describe("addMlsGroupMember", () => {
	it("claims a key package, commits the add, and advances local state", async () => {
		await foundGroup();
		agent(THIRD_ID);
		offerKeyPackage(THIRD_ID);
		posted.length = 0;

		const { epoch } = await addMlsGroupMember(
			dir,
			SELF_ID,
			GROUP_ID,
			THIRD_ID,
			client,
		);

		expect(epoch).toBe(2);
		expect(posted[0]!.welcomes![0]!.agent_id).toBe(THIRD_ID);
		expect(loadMlsState(dir, SELF_ID, GROUP_ID)!.epoch).toBe(2);
	});

	it("throws when no MLS state exists", async () => {
		await expect(
			addMlsGroupMember(dir, SELF_ID, GROUP_ID, MEMBER_ID, client),
		).rejects.toThrow(`No MLS state for group ${GROUP_ID}`);
	});

	it("throws when the member published no key package", async () => {
		await foundGroup();
		vi.mocked(claimKeyPackages).mockResolvedValue({
			packages: [],
			agent_id: THIRD_ID,
		});
		await expect(
			addMlsGroupMember(dir, SELF_ID, GROUP_ID, THIRD_ID, client),
		).rejects.toThrow(`No key packages available for ${THIRD_ID}`);
	});

	it("tops up before the add, so a long-lived agent never runs itself out", async () => {
		seedGroupState();
		agent(THIRD_ID);
		offerKeyPackage(THIRD_ID);

		await addMlsGroupMember(dir, SELF_ID, GROUP_ID, THIRD_ID, client);
		expect(uploadKeyPackages).toHaveBeenCalledWith(
			client,
			SELF_ID,
			expect.any(Array),
		);
	});

	it("does not top up while the inventory is healthy", async () => {
		seedGroupState();
		agent(THIRD_ID);
		offerKeyPackage(THIRD_ID);
		openMlsClient(dir, SELF_ID).generateKeyPackages(MLS_KEY_PACKAGE_TARGET);
		vi.mocked(uploadKeyPackages).mockClear();

		await addMlsGroupMember(dir, SELF_ID, GROUP_ID, THIRD_ID, client);
		expect(uploadKeyPackages).not.toHaveBeenCalled();
	});

	it("still completes when the top-up fails (maintenance is best-effort)", async () => {
		await foundGroup();
		agent(THIRD_ID);
		offerKeyPackage(THIRD_ID);
		vi.mocked(uploadKeyPackages).mockRejectedValue(new Error("network down"));

		await expect(
			addMlsGroupMember(dir, SELF_ID, GROUP_ID, THIRD_ID, client),
		).resolves.toEqual({ epoch: 2 });
	});
});

describe("removeMlsGroupMember", () => {
	it("commits a remove by leaf index and advances local state", async () => {
		await foundGroup();
		posted.length = 0;

		const { epoch } = await removeMlsGroupMember(
			dir,
			SELF_ID,
			GROUP_ID,
			1,
			client,
		);

		expect(epoch).toBe(2);
		expect(posted[0]!.welcomes).toEqual([]);
		expect(loadMlsState(dir, SELF_ID, GROUP_ID)!.epoch).toBe(2);
	});

	it("throws when no MLS state exists", async () => {
		await expect(
			removeMlsGroupMember(dir, SELF_ID, GROUP_ID, 1, client),
		).rejects.toThrow(`No MLS state for group ${GROUP_ID}`);
	});
});

// ── welcomes ─────────────────────────────────────────────────────────────────

describe("processMlsWelcomes", () => {
	it("installs state keyed by the rine group UUID and replaces the key package it consumed", async () => {
		await foundGroup();

		expect(loadMlsState(dir, MEMBER_ID, GROUP_ID)).toEqual({
			groupId: GROUP_ID,
			epoch: 1,
			cipherSuite: 0xf057,
		});
		expect(uploadKeyPackages).toHaveBeenCalledWith(
			client,
			MEMBER_ID,
			expect.any(Array),
		);
	});

	it("skips welcomes the server could not associate with a rine group", async () => {
		vi.mocked(fetchWelcomes).mockResolvedValue({
			welcomes: [
				{
					id: "w1",
					group_id: null,
					blob: "AAAA",
					created_at: "2026-01-01T00:00:00Z",
				},
			],
		});
		const result = await processMlsWelcomes(dir, MEMBER_ID, client);
		expect(result).toEqual({ processed: 0, groupIds: [] });
	});

	it("does not top up when there was nothing to process", async () => {
		await processMlsWelcomes(dir, MEMBER_ID, client);
		expect(uploadKeyPackages).not.toHaveBeenCalled();
	});
});

// ── sync ─────────────────────────────────────────────────────────────────────

describe("syncMlsGroup", () => {
	/** SELF commits a remove of leaf 1; the returned blob is what MEMBER must apply. */
	function peerCommit(): string {
		const group = openMlsClient(dir, SELF_ID).loadGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		const bundle = group.removeMember(1);
		group.save();
		return mlsToBase64(bundle.commit);
	}

	/** SELF removes MEMBER, so MEMBER is genuinely out of the canonical tree. */
	function evictMember(): void {
		const group = openMlsClient(dir, SELF_ID).loadGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		group.removeMember(1);
		group.save();
	}

	function handshake(blob: string, epoch: number | null = 2) {
		return {
			handshakes: [
				{ id: "h1", epoch, blob, created_at: "2026-01-01T00:00:00Z" },
			],
		};
	}

	it("throws when no MLS state exists", async () => {
		await expect(syncMlsGroup(dir, SELF_ID, GROUP_ID, client)).rejects.toThrow(
			`No MLS state for group ${GROUP_ID}`,
		);
	});

	it("applies commits posted since the current epoch and ACKs each", async () => {
		await foundGroup();
		agent(THIRD_ID);
		offerKeyPackage(THIRD_ID);
		const group = openMlsClient(dir, SELF_ID).loadGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		const bundle = group.addMember(
			mlsFromBase64((await claimKeyPackages(client, THIRD_ID)).packages[0]!),
		);
		group.save();
		vi.mocked(fetchHandshakes).mockResolvedValue(
			handshake(mlsToBase64(bundle.commit)),
		);

		const result = await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client);

		expect(vi.mocked(fetchHandshakes).mock.calls[0]![2]).toBe(1); // since_epoch
		expect(result).toEqual({ epoch: 2, processed: 1, evicted: false });
		expect(mlsAck).toHaveBeenCalledWith(
			client,
			GROUP_ID,
			{ object_id: "h1" },
			undefined,
		);
		expect(loadMlsState(dir, MEMBER_ID, GROUP_ID)!.epoch).toBe(2);
	});

	it("reports eviction as the valid outcome of a valid commit, not an error", async () => {
		await foundGroup();
		vi.mocked(fetchHandshakes).mockResolvedValue(handshake(peerCommit()));

		const result = await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client);
		expect(result.processed).toBe(1);
		expect(result.evicted).toBe(true);
		expect(mlsAck).toHaveBeenCalledTimes(1);
	});

	it("NACKs an un-processable commit and saves nothing", async () => {
		await foundGroup();
		vi.mocked(fetchHandshakes).mockResolvedValue(
			handshake(Buffer.from("garbage").toString("base64")),
		);
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: currentGroupInfo(),
			epoch: 1,
		});

		const result = await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client);
		expect(result.processed).toBe(0);
		expect(mlsNack).toHaveBeenCalledTimes(1);
		expect(mlsAck).not.toHaveBeenCalled();
		expect(loadMlsState(dir, MEMBER_ID, GROUP_ID)!.epoch).toBe(1);
	});

	it("re-bootstraps an orphaned local epoch instead of NACK-looping it", async () => {
		await foundGroup();
		// MEMBER is no longer in the tree, but still holds epoch-1 local state whose
		// epoch is AHEAD of the server's confirmed epoch (0) — only a rolled-back own
		// commit produces that, so the state is orphaned rather than merely stale.
		evictMember();
		vi.mocked(fetchHandshakes).mockResolvedValue(
			handshake(Buffer.from("garbage").toString("base64")),
		);
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: currentGroupInfo(),
			epoch: 0,
		});
		posted.length = 0;

		const result = await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client);

		expect(mlsNack).not.toHaveBeenCalled();
		expect(posted).toHaveLength(1); // the external re-join commit
		expect(result.epoch).toBe(3);
		expect(loadMlsState(dir, MEMBER_ID, GROUP_ID)!.epoch).toBe(3);
	});

	it("leaves stale state intact when the re-bootstrap fails mid-flight", async () => {
		await foundGroup();
		vi.mocked(fetchHandshakes).mockResolvedValue(
			handshake(Buffer.from("garbage").toString("base64")),
		);
		// Orphaned, but there is no GroupInfo to re-join against.
		vi.mocked(fetchGroupInfo).mockResolvedValue({ group_info: null, epoch: 0 });

		await expect(
			syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client),
		).rejects.toThrow("no published GroupInfo");
		// Not stranded stateless: the next sync re-enters the same path.
		expect(loadMlsState(dir, MEMBER_ID, GROUP_ID)!.epoch).toBe(1);
	});

	it("emits neither ACK nor NACK on a transport error, and rethrows", async () => {
		await foundGroup();
		vi.mocked(fetchHandshakes).mockResolvedValue(handshake(peerCommit()));
		vi.mocked(mlsFromBase64).mockImplementationOnce(() => {
			throw new Error("socket hang up");
		});

		await expect(
			syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client),
		).rejects.toThrow("socket hang up");
		expect(mlsAck).not.toHaveBeenCalled();
		expect(mlsNack).not.toHaveBeenCalled();
	});
});

// ── external self-join ───────────────────────────────────────────────────────

describe("externalJoinMlsGroup", () => {
	function conflict() {
		return new RineApiError(409, "stale epoch", undefined, "epoch_conflict");
	}

	beforeEach(async () => {
		await foundGroup();
		agent(THIRD_ID);
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: currentGroupInfo(),
			epoch: 1,
		});
		posted.length = 0;
		vi.mocked(mlsCommit).mockClear();
	});

	it("joins by external commit and saves state keyed by the rine UUID", async () => {
		const { epoch } = await externalJoinMlsGroup(
			dir,
			THIRD_ID,
			GROUP_ID,
			client,
		);

		expect(epoch).toBe(2);
		expect(posted).toHaveLength(1);
		expect(posted[0]!.group_info).toBeDefined();
		expect(loadMlsState(dir, THIRD_ID, GROUP_ID)!.epoch).toBe(2);
	});

	it("throws a clear error when no GroupInfo is published", async () => {
		vi.mocked(fetchGroupInfo).mockResolvedValue({ group_info: null, epoch: 1 });
		await expect(
			externalJoinMlsGroup(dir, THIRD_ID, GROUP_ID, client),
		).rejects.toThrow("no published GroupInfo");
	});

	it("retries once on an epoch conflict and succeeds on the rebuild", async () => {
		vi.mocked(mlsCommit)
			.mockRejectedValueOnce(conflict())
			.mockImplementationOnce(async (_c, _g, body) => {
				posted.push(body);
				return { epoch: body.epoch ?? null, delivered_to: 1 };
			});

		const { epoch } = await externalJoinMlsGroup(
			dir,
			THIRD_ID,
			GROUP_ID,
			client,
		);
		expect(epoch).toBe(2);
		expect(mlsCommit).toHaveBeenCalledTimes(2);
	});

	it("surfaces a terminal error on a second epoch conflict rather than looping", async () => {
		vi.mocked(mlsCommit).mockRejectedValue(conflict());
		await expect(
			externalJoinMlsGroup(dir, THIRD_ID, GROUP_ID, client),
		).rejects.toThrow("after one retry");
		expect(mlsCommit).toHaveBeenCalledTimes(2);
	});

	it("retries briefly while the GroupInfo is pending confirmation, then joins", async () => {
		vi.mocked(mlsCommit)
			.mockRejectedValueOnce(
				new RineApiError(
					409,
					"awaiting ack",
					undefined,
					"pending_confirmation",
				),
			)
			.mockImplementationOnce(async (_c, _g, body) => {
				posted.push(body);
				return { epoch: body.epoch ?? null, delivered_to: 1 };
			});

		const { epoch } = await externalJoinMlsGroup(
			dir,
			THIRD_ID,
			GROUP_ID,
			client,
		);
		expect(epoch).toBe(2);
	});

	it("gives up with an actionable error when confirmation never arrives", async () => {
		vi.mocked(mlsCommit).mockRejectedValue(
			new RineApiError(409, "awaiting ack", undefined, "pending_confirmation"),
		);
		await expect(
			externalJoinMlsGroup(dir, THIRD_ID, GROUP_ID, client),
		).rejects.toThrow("still pending");
	});

	it("does not retry a non-conflict error, and does not wrap it misleadingly", async () => {
		vi.mocked(mlsCommit).mockRejectedValue(
			new RineApiError(403, "not a member", undefined, "forbidden"),
		);
		await expect(
			externalJoinMlsGroup(dir, THIRD_ID, GROUP_ID, client),
		).rejects.toThrow("not a member");
		expect(mlsCommit).toHaveBeenCalledTimes(1);
	});
});
