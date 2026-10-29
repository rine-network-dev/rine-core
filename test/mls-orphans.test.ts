/**
 * Leaf reclamation, driven against the REAL native core.
 *
 * Only the server is faked: `crypto/mls-api.js` stands in for the MLS routes and
 * a stub `HttpClient` answers the three reads the pass makes — who holds a
 * member row, which invitations are still live, and each of their signing keys.
 * Every leaf, commit and ratchet-tree fact is genuine, so a test here fails when
 * the orphan set is computed from the wrong population.
 *
 * The load-bearing one is `does not classify a live invitee as an orphan`: an
 * invitation takes its leaf the moment its Welcome is minted, so a pass that
 * reads members alone would evict every agent who has not accepted yet.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-escrow-key.js", async () =>
	(await import("./mls-escrow-harness.js")).escrowKeyModule(),
);

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/crypto/mls-api.js")
	>("../src/crypto/mls-api.js");
	return {
		...actual,
		uploadKeyPackages: vi.fn(async (_c: unknown, _a: unknown, p: string[]) => ({
			stored: p.length,
		})),
		claimKeyPackagesBatch: vi.fn(async () => ({ claims: [] })),
		mlsInit: vi.fn(async () => ({ mls_pending: true, members: [] })),
		mlsCommit: vi.fn(async () => ({ epoch: null, delivered_to: 1 })),
		mlsAck: vi.fn(async () => ({ confirmed: true, acks: 1, needed: 1 })),
		mlsNack: vi.fn(async () => ({ quarantined: true })),
		fetchHandshakes: vi.fn(async () => ({ handshakes: [] })),
		fetchGroupInfo: vi.fn(async () => ({ group_info: null, epoch: null })),
	};
});

import { ascii } from "../src/crypto/bytes.js";
import { RineApiError } from "../src/errors.js";
import { World } from "./crypto/world.js";
import {
	claimKeyPackagesBatch,
	mlsCommit,
	mlsToBase64,
} from "../src/crypto/mls-api.js";
import type { MlsCommitBody } from "../src/crypto/mls-api.js";
import {
	mlsGroupIdBytes,
	openMlsClient,
	openMlsGroup,
} from "../src/crypto/mls.js";
import {
	addMlsGroupMembers,
	isSeated,
	orphanLeaves,
	reclaimOrphanLeaves,
	resumeMlsGroupAdmission,
} from "../src/mls-ops.js";

const SELF_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

let dir: string;
let world: World;
/** Every commit body the server accepted, in order. */
let posted: MlsCommitBody[];
/** Agents holding a claimable KeyPackage. */
let pool: Set<string>;
/** What `GET /groups/{id}/requests?outstanding=live` reports. */
let invited: string[];
let pending: string[];
/**
 * Agents a member nominated: `pending` like a self-application, and carrying an
 * inviter. On a majority or unanimity group an invite files one of these rather
 * than minting a voucher, so a row's inviter no longer says which population it
 * belongs to.
 */
let nominated: string[];
let members: string[];
/** Agent ids `GET /agents/keys` pretends not to know — revoked, or org erased. */
let unreadable: Set<string>;
let client: never;
/** Every escrow upload the pass made, as the path it PUT. */
let uploads: string[];

/** An agent with keys on disk and one claimable KeyPackage. */
function agent(): string {
	const created = world.addAgent();
	world.save(dir, created);
	pool.add(created.id);
	return created.id;
}

/** An agent's MLS basic-credential identity — the ASCII bytes of its agent id. */
function identityOf(agentId: string): Uint8Array {
	return ascii(agentId);
}

/** The published keys `GET /agents/keys` would return for `ids`. */
function publishedKeys(ids: string[]) {
	const keys: Record<string, unknown> = {};
	for (const id of ids) {
		if (unreadable.has(id)) continue;
		const generations = world.agents.get(id);
		if (!generations?.length) continue;
		const newest = generations.reduce((a, b) => (b.gen > a.gen ? b : a));
		keys[id] = newest.response;
	}
	return keys;
}

/** Found the group locally and seat `ids` in its ratchet tree for real. */
async function seatAgents(ids: string[]): Promise<void> {
	openMlsClient(dir, SELF_ID).createGroup(mlsGroupIdBytes(GROUP_ID)).save();
	if (ids.length > 0) {
		await addMlsGroupMembers(dir, SELF_ID, GROUP_ID, ids, client);
	}
}

/** How many commits the server has taken so far. */
function commitCount(): number {
	return posted.length;
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-orphans-"));
	world = new World();
	posted = [];
	pool = new Set();
	invited = [];
	pending = [];
	nominated = [];
	members = [SELF_ID];
	unreadable = new Set();
	vi.clearAllMocks();
	world.save(dir, world.addAgent({ id: SELF_ID }));
	vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => {
		posted.push(body);
		return { epoch: body.epoch ?? null, delivered_to: 1 };
	});
	vi.mocked(claimKeyPackagesBatch).mockImplementation(async (_c, ids) => ({
		claims: ids.map((agent_id) => ({
			agent_id,
			packages: pool.has(agent_id)
				? [mlsToBase64(openMlsClient(dir, agent_id).generateKeyPackage())]
				: [],
		})),
	}));
	uploads = [];
	client = {
		put: vi.fn(async (path: string) => {
			uploads.push(path);
			return {};
		}),
		get: vi.fn(async (path: string, params?: Record<string, string>) => {
			if (path === "/agents/keys") {
				return { keys: publishedKeys(String(params?.ids).split(",")) };
			}
			if (path === `/groups/${GROUP_ID}/members`) {
				return { items: members.map((agent_id) => ({ agent_id })) };
			}
			if (path === `/groups/${GROUP_ID}/requests`) {
				// Three row kinds, because the server writes three: an invitation, a
				// stranger's self-application, and a member's nomination — which is
				// `pending` and carries an inviter, so the inviter alone does not say
				// which population a row belongs to.
				return {
					items: [
						...invited.map((agent_id) => ({
							agent_id,
							status: "invited",
							invited_by: SELF_ID,
						})),
						...pending.map((agent_id) => ({
							agent_id,
							status: "pending",
							invited_by: null,
						})),
						...nominated.map((agent_id) => ({
							agent_id,
							status: "pending",
							invited_by: SELF_ID,
						})),
					],
				};
			}
			throw new Error(`unexpected GET ${path}`);
		}),
	} as never;
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("orphanLeaves", () => {
	it("names the leaf of an agent no member row and no voucher accounts for", async () => {
		const gone = agent();
		await seatAgents([gone]);
		const group = openMlsGroup(dir, SELF_ID, GROUP_ID);

		const orphans = orphanLeaves(group, [identityOf(SELF_ID)]);

		expect(orphans.map((leaf) => leaf.index)).toEqual([
			group.memberIndex(identityOf(gone)),
		]);
	});

	it("never names this agent's own leaf, whatever the entitled set says", async () => {
		const other = agent();
		await seatAgents([other]);
		const group = openMlsGroup(dir, SELF_ID, GROUP_ID);

		// The degenerate input: nobody at all is entitled. An admin that
		// self-evicts can neither commit nor recover, so its own leaf is excluded
		// structurally rather than by trusting the membership read.
		const orphans = orphanLeaves(group, []);

		expect(orphans.map((leaf) => leaf.index)).toEqual([
			group.memberIndex(identityOf(other)),
		]);
	});
});

describe("reclaimOrphanLeaves", () => {
	it("does not classify a live invitee as an orphan", async () => {
		// An invitation takes its leaf the moment its Welcome is minted and the
		// invitee holds no member row until they join. Reading members alone here
		// would evict every agent who has not accepted yet.
		const invitee = agent();
		await seatAgents([invitee]);
		invited = [invitee];
		const before = commitCount();

		const result = await reclaimOrphanLeaves(dir, SELF_ID, GROUP_ID, client);

		expect(result).toMatchObject({ found: 0, reclaimed: 0, commits: 0 });
		expect(commitCount()).toBe(before);
		expect(
			isSeated(openMlsGroup(dir, SELF_ID, GROUP_ID), identityOf(invitee)),
		).toBe(true);
	});

	it("does not classify a pending self-applicant as an orphan", async () => {
		const applicant = agent();
		await seatAgents([applicant]);
		pending = [applicant];

		const result = await reclaimOrphanLeaves(dir, SELF_ID, GROUP_ID, client);

		expect(result).toMatchObject({ found: 0, reclaimed: 0 });
	});

	it("does not classify an agent a member nominated as an orphan", async () => {
		// The entitled set is the WIDER of the two voucher populations, so a
		// nomination is covered by the same read that covers an invitation.
		// Narrowing it to the rows a resume may admit would evict every agent the
		// electorate still owes an answer to.
		const nominee = agent();
		await seatAgents([nominee]);
		nominated = [nominee];

		const result = await reclaimOrphanLeaves(dir, SELF_ID, GROUP_ID, client);

		expect(result).toMatchObject({ found: 0, reclaimed: 0, commits: 0 });
		expect(
			isSeated(openMlsGroup(dir, SELF_ID, GROUP_ID), identityOf(nominee)),
		).toBe(true);
	});

	it("retires the leaf of a lapsed invitation the reaper already resolved", async () => {
		const noShow = agent();
		await seatAgents([noShow]);
		// The reaper freed the seat: no member row, no live voucher. The leaf is
		// what it left behind.
		const before = commitCount();

		const result = await reclaimOrphanLeaves(dir, SELF_ID, GROUP_ID, client);

		expect(result).toMatchObject({ found: 1, reclaimed: 1, commits: 1 });
		expect(commitCount()).toBe(before + 1);
		expect(uploads).toContain(
			`/groups/${GROUP_ID}/mls/escrow/${openMlsGroup(dir, SELF_ID, GROUP_ID).epoch()}`,
		);
		// The Remove commit carries no Welcome and declares the orphan's agent, so
		// the server can close that agent's seat span.
		expect(posted.at(-1)?.welcomes).toEqual([]);
		expect(posted.at(-1)?.removes).toEqual([noShow]);
		expect(
			isSeated(openMlsGroup(dir, SELF_ID, GROUP_ID), identityOf(noShow)),
		).toBe(false);
	});

	it("test_reclaim_when_a_revoked_leaf_is_removed_then_nobody_is_added_or_claimed", async () => {
		const revoked = agent();
		const bystander = agent();
		await seatAgents([revoked]);
		const treeBefore = openMlsGroup(dir, SELF_ID, GROUP_ID)
			.memberIdentities()
			.map((leaf) => new TextDecoder().decode(leaf.identity));
		unreadable.add(revoked);
		vi.mocked(claimKeyPackagesBatch).mockClear();
		const before = commitCount();

		const result = await reclaimOrphanLeaves(dir, SELF_ID, GROUP_ID, client);

		// The pass reaches no key package and no Welcome, so a joiner the revoked
		// seat was holding back is not admitted by it, even with a key on offer.
		expect(result).toMatchObject({ found: 1, reclaimed: 1 });
		expect(claimKeyPackagesBatch).not.toHaveBeenCalled();
		const reclaim = posted.slice(before);
		expect(reclaim).toHaveLength(1);
		expect(reclaim.every((body) => body.welcomes?.length === 0)).toBe(true);
		const treeAfter = openMlsGroup(dir, SELF_ID, GROUP_ID)
			.memberIdentities()
			.map((leaf) => new TextDecoder().decode(leaf.identity));
		expect(treeAfter).toEqual(treeBefore.filter((id) => id !== revoked));
		expect(treeAfter).not.toContain(bystander);
	});

	it("test_reclaim_when_every_commit_meets_an_epoch_conflict_then_one_retry_and_the_pass_stops", async () => {
		await seatAgents([agent(), agent()]);
		vi.mocked(mlsCommit).mockClear();
		vi.mocked(mlsCommit).mockRejectedValue(
			new RineApiError(409, "stale", undefined, "epoch_conflict"),
		);

		const result = await reclaimOrphanLeaves(dir, SELF_ID, GROUP_ID, client);

		// One resync and one retry for the first orphan; the second conflict ends
		// the pass, so the second orphan is never tried.
		expect(mlsCommit).toHaveBeenCalledTimes(2);
		expect(result).toMatchObject({ found: 2, reclaimed: 0, commits: 0 });
	});

	it("refuses to act when an entitled agent publishes no readable signing key", async () => {
		const revoked = agent();
		const noShow = agent();
		await seatAgents([revoked, noShow]);
		// An INVITATION, not a member row: `GET /groups/{id}/members` filters
		// revoked agents out, so a revoked member never reaches this pass at all,
		// while a voucher outlives the revocation of the agent it names. That
		// agent holds a leaf and publishes no key, so its leaf cannot be told
		// apart from the no-show's.
		invited = [revoked];
		unreadable.add(revoked);
		const before = commitCount();

		const result = await reclaimOrphanLeaves(dir, SELF_ID, GROUP_ID, client);

		expect(result).toMatchObject({ found: 0, reclaimed: 0, commits: 0 });
		expect(result.declined?.reason).toBe("identity_unknown");
		expect(result.declined?.detail).toContain(revoked);
		expect(commitCount()).toBe(before);
		const group = openMlsGroup(dir, SELF_ID, GROUP_ID);
		expect(isSeated(group, identityOf(revoked))).toBe(true);
		expect(isSeated(group, identityOf(noShow))).toBe(true);
	});

	it("test_reclaim_when_a_member_row_has_no_leaf_then_the_pass_declines_without_blaming_a_rotation", async () => {
		const unseated = agent();
		const noShow = agent();
		await seatAgents([noShow]);
		// A member row whose leaf the tree does not hold: the two have come apart,
		// so no leaf can be attributed to it. Subtracting by published key would
		// classify the seated no-show's leaf as an orphan and Remove it.
		members = [SELF_ID, unseated];
		const before = commitCount();

		const result = await reclaimOrphanLeaves(dir, SELF_ID, GROUP_ID, client);

		expect(result).toMatchObject({ found: 0, reclaimed: 0, commits: 0 });
		expect(result.declined?.reason).toBe("identity_unseated");
		expect(result.declined?.detail).toContain(unseated);
		expect(result.declined?.detail).not.toMatch(/rotat|group sync/);
		// Nothing was committed, so BOTH leaves are still there — including the
		// no-show's, which a pass that ran would legitimately have retired.
		expect(commitCount()).toBe(before);
		expect(
			isSeated(openMlsGroup(dir, SELF_ID, GROUP_ID), identityOf(noShow)),
		).toBe(true);
	});
});

describe("resumeMlsGroupAdmission", () => {
	it("retires nothing unless reclamation is asked for", async () => {
		const noShow = agent();
		await seatAgents([noShow]);
		const before = commitCount();

		const result = await resumeMlsGroupAdmission(
			dir,
			SELF_ID,
			GROUP_ID,
			client,
		);

		expect(result.reclamation).toBeUndefined();
		expect(commitCount()).toBe(before);
		expect(
			isSeated(openMlsGroup(dir, SELF_ID, GROUP_ID), identityOf(noShow)),
		).toBe(true);
	});

	it("seats nobody a member merely nominated, and retires no leaf on their account", async () => {
		// A nomination occupies a seat in the server's count and is entitled to
		// nothing else: it is a request the electorate has yet to answer, and the
		// vote seats the member, which is what grants the group's keys. So a pass
		// over a group holding one commits nothing at all — it neither Welcomes the
		// nominee nor treats the seat it is holding as abandoned.
		const nominee = agent();
		await seatAgents([]);
		nominated = [nominee];
		const before = commitCount();

		const result = await resumeMlsGroupAdmission(
			dir,
			SELF_ID,
			GROUP_ID,
			client,
			undefined,
			{ reclaim: true },
		);

		expect(result.added).toBe(0);
		expect(result.reclamation).toMatchObject({ found: 0, reclaimed: 0 });
		expect(commitCount()).toBe(before);
		expect(
			isSeated(openMlsGroup(dir, SELF_ID, GROUP_ID), identityOf(nominee)),
		).toBe(false);
	});

	it("seats the unseated first, then retires what nobody is entitled to", async () => {
		const noShow = agent();
		await seatAgents([noShow]);
		// One member the founding never reached, and one leaf nobody accounts for.
		const unseated = agent();
		members = [SELF_ID, unseated];

		const result = await resumeMlsGroupAdmission(
			dir,
			SELF_ID,
			GROUP_ID,
			client,
			undefined,
			{ reclaim: true },
		);

		expect(result.added).toBe(1);
		expect(result.reclamation).toMatchObject({
			found: 1,
			reclaimed: 1,
			commits: 1,
		});
		// The reclamation moved the epoch after the admission did, so the result
		// reports where the group actually stands.
		expect(result.epoch).toBe(result.reclamation?.epoch);
		const group = openMlsGroup(dir, SELF_ID, GROUP_ID);
		expect(isSeated(group, identityOf(unseated))).toBe(true);
		expect(isSeated(group, identityOf(noShow))).toBe(false);
	});
});
