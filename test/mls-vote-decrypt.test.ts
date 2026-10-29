/**
 * A **drained** key-package pool, all the way through to a real decrypt.
 *
 * This is the shape the fix shipped and the one no other suite reaches. Peers claim
 * one of an agent's published key packages per add, and every claim they turn
 * into a Welcome consumes the matching private half locally — so an agent that
 * only ever gets added, and never publishes again, ends at zero on BOTH sides.
 * At zero it is **un-addable**: no member can mint it a Welcome, so a carried
 * vote seats it on the roster with no leaf in the ratchet tree, and it reads
 * nothing the group says. Zero is an absorbing state precisely because the
 * repairs are all conditioned on events that can no longer happen to it.
 *
 * The chain each test drives, end to end, against the REAL native core:
 *
 *     drained to 0/0 -> a peer's admission is refused (no_key_package)
 *                    -> the agent's own next operation beats and refills
 *                    -> the peer's admission now mints a real Welcome
 *                    -> the welcomed member DECRYPTS REAL CIPHERTEXT
 *
 * Only `crypto/mls-api.js` is faked, and it is faked **statefully**: the pool is
 * a queue the mock pops from, so "drained" is representable at all and a claim
 * against an empty pool answers the way the server does — an empty `packages`
 * array, not an error. Every KeyPackage, Welcome, commit and ciphertext is
 * genuine.
 *
 * 🔴 The drain installs its Welcomes through `openMlsClient(...).joinFromWelcome`
 * rather than through `processMlsWelcomes`, and that is not a shortcut around
 * the unit under test — it is the only way to BUILD the precondition. Every
 * product path that consumes a private half now publishes a replacement, which
 * is the fix; driving the drain through the product would refill the pool as
 * fast as it emptied it and the wedged state would be unreachable. So the
 * install is fixture construction, standing in for the shipped build that
 * created these agents, and the assertions start where it ends.
 *
 * Deliberately NOT covered here: a LOCAL mirror that still reads full while the
 * server holds none (an upload that failed after the private halves were minted
 * over-counts). The beat cannot see that and is not what rescues it — the
 * additive top-up is, and that arm is gated with the top-up.
 *
 * No fixture, no golden value: the drain runs until the pool is empty and the
 * refilled count is compared against `MLS_KEY_PACKAGE_TARGET`, so a policy
 * change moves this file's expectations with it.
 */
import { randomUUID } from "node:crypto";
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
		uploadKeyPackages: vi.fn(),
		claimKeyPackages: vi.fn(),
		claimKeyPackagesBatch: vi.fn(),
		mlsInit: vi.fn(),
		mlsCommit: vi.fn(),
		mlsAck: vi.fn(async () => ({ confirmed: true, acks: 1, needed: 1 })),
		mlsNack: vi.fn(async () => ({ quarantined: true })),
		fetchHandshakes: vi.fn(async () => ({ handshakes: [] })),
		fetchWelcomes: vi.fn(),
		fetchGroupInfo: vi.fn(async () => ({ group_info: null, epoch: null })),
	};
});

import { World } from "./crypto/world.js";
import { encryptMlsGroupMessage } from "../src/message-mls.js";
import { decryptGroupMessage } from "../src/message-group.js";
import type { MlsCommitBody, MlsWelcomeEntry } from "../src/crypto/mls-api.js";
import {
	claimKeyPackages,
	claimKeyPackagesBatch,
	fetchWelcomes,
	mlsCommit,
	mlsFromBase64,
	mlsInit,
	uploadKeyPackages,
} from "../src/crypto/mls-api.js";
import { openMlsClient } from "../src/crypto/mls.js";
import { MLS_KEY_PACKAGE_TARGET } from "../src/mls-keypackages.js";
import {
	addMlsGroupMembers,
	initMlsGroup,
	processMlsWelcomes,
	publishMlsKeyPackages,
	syncMlsGroup,
} from "../src/mls-ops.js";
// Off the module rather than the barrel: it defeats a rate limit, so it is a
// test seam and not part of @rine-network/core's published surface.
import { resetMlsHeartbeatGate } from "../src/mls-heartbeat.js";

/** The admitter: founds groups and carries the vote that seats the drained agent. */
const ADMIN_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
/** The agent whose pool is drained to zero. */
const BOB_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
/** A second founding member, so the voted group has a history before Bob arrives. */
const CARL_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
/** The group a carried vote seats Bob into. */
const VOTED_GROUP_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";

let dir: string;
let world: World;
/** Unclaimed key packages the server holds, per agent, in publish order. */
let serverPool: Map<string, string[]>;
/** Welcomes the server holds for an agent, delivered once, per agent. */
let inbox: Map<string, MlsWelcomeEntry[]>;
/** Every commit body the server accepted, in order. */
let posted: MlsCommitBody[];
/** Whom `POST /groups/{id}/mls/init` reports as this group's founding roster. */
let foundingRoster: string[];
let welcomeSeq: number;
let client: never;

function pool(agentId: string): string[] {
	const held = serverPool.get(agentId) ?? [];
	serverPool.set(agentId, held);
	return held;
}

function held(agentId: string): number {
	return pool(agentId).length;
}

/** The private halves this agent still holds, read from the real core. */
function localCount(agentId: string): number {
	return openMlsClient(dir, agentId).keyPackageCount();
}

/** Deliver an agent's Welcomes and clear them, as a one-shot fetch does. */
function takeInbox(agentId: string): MlsWelcomeEntry[] {
	const waiting = inbox.get(agentId) ?? [];
	inbox.set(agentId, []);
	return waiting;
}

function headers(agentId: string): Record<string, string> {
	return { "X-Rine-Agent": agentId };
}

/** The published keys `GET /agents/keys` would return for `ids`. */
function publishedKeys(ids: string[]) {
	const map: Record<string, unknown> = {};
	for (const id of ids) {
		if (!id) continue;
		const generations = world.agents.get(id);
		if (!generations?.length) continue;
		const newest = generations.reduce((a, b) => (b.gen > a.gen ? b : a));
		map[id] = newest.response;
	}
	return map;
}

/**
 * The key server the decrypt path verifies an envelope against. Its non-`/keys`
 * answers are empty because recovery is not this file's subject: a decrypt that
 * needs it has already failed the thing being asserted.
 */
function keyServer() {
	const base = world.client();
	return {
		get: vi.fn(async (path: string, params?: Record<string, string>) =>
			path.includes("/keys")
				? base.get(path, params)
				: { welcomes: [], handshakes: [] },
		),
		post: vi.fn(),
	} as never;
}

beforeEach(async () => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-vote-decrypt-"));
	world = new World();
	serverPool = new Map();
	inbox = new Map();
	posted = [];
	foundingRoster = [];
	welcomeSeq = 0;
	vi.clearAllMocks();
	// Per process by design, so a test inheriting the previous test's stamp
	// would measure the gate rather than the beat.
	resetMlsHeartbeatGate();
	for (const id of [ADMIN_ID, BOB_ID, CARL_ID]) {
		world.save(dir, world.addAgent({ id }));
	}

	// A pool that is a queue, not a boolean: an upload lengthens it, a claim pops
	// from it, and an empty one answers `packages: []` exactly as the server does.
	vi.mocked(uploadKeyPackages).mockImplementation(async (_c, agentId, pkgs) => {
		pool(agentId).push(...pkgs);
		return { stored: pkgs.length };
	});
	vi.mocked(claimKeyPackages).mockImplementation(async (_c, agentId, count) => ({
		agent_id: agentId,
		packages: pool(agentId).splice(0, count ?? 1),
	}));
	vi.mocked(claimKeyPackagesBatch).mockImplementation(
		async (_c, ids, perAgent) => ({
			claims: ids.map((agent_id) => ({
				agent_id,
				packages: pool(agent_id).splice(0, perAgent ?? 1),
			})),
		}),
	);
	vi.mocked(mlsInit).mockImplementation(async () => ({
		mls_pending: true,
		members: foundingRoster.map((agent_id) => ({
			agent_id,
			has_key_package: held(agent_id) > 0,
		})),
	}));
	// Accept every commit and spool the Welcomes it carried, so a Welcome exists
	// only because an admission really minted one.
	vi.mocked(mlsCommit).mockImplementation(async (_c, groupId, body) => {
		posted.push(body);
		for (const entry of body.welcomes ?? []) {
			const waiting = inbox.get(entry.agent_id) ?? [];
			waiting.push({
				id: `w${(welcomeSeq += 1)}`,
				group_id: groupId,
				blob: entry.welcome,
				created_at: "2026-01-01T00:00:00Z",
			});
			inbox.set(entry.agent_id, waiting);
		}
		return { epoch: body.epoch ?? null, delivered_to: 1 };
	});
	vi.mocked(fetchWelcomes).mockImplementation(async (_c, agentId) => ({
		welcomes: takeInbox(agentId),
	}));

	client = {
		get: vi.fn(async (path: string, params?: Record<string, string>) => {
			if (path === "/agents/keys") {
				return { keys: publishedKeys(String(params?.ids ?? "").split(",")) };
			}
			if (/^\/groups\/[^/]+$/.test(path)) return { member_count: 2 };
			if (/^\/groups\/[^/]+\/members$/.test(path)) {
				return { items: [{ agent_id: ADMIN_ID }] };
			}
			if (/^\/groups\/[^/]+\/requests$/.test(path)) return { items: [] };
			throw new Error(`unexpected GET ${path}`);
		}),
	} as never;

	// Carl is the healthy peer every assertion is read against: he is seated
	// wherever Bob is dropped, so an admission that seats nobody at all cannot
	// be mistaken for the drained agent's own refusal.
	await publishMlsKeyPackages(dir, CARL_ID, client);
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

/**
 * Spend exactly one of `memberId`'s published key packages: a peer founds a
 * group naming them, and they install the Welcome it minted.
 *
 * Installed through the core rather than `processMlsWelcomes` — see this file's
 * header. Returns the group id, which the member now genuinely holds state for.
 */
async function spendOneKeyPackage(memberId: string): Promise<string> {
	const groupId = randomUUID();
	foundingRoster = [memberId];
	await initMlsGroup(dir, ADMIN_ID, groupId, client, headers(ADMIN_ID));
	const [welcome] = takeInbox(memberId);
	if (!welcome) throw new Error(`no Welcome minted for ${memberId}`);
	openMlsClient(dir, memberId)
		.joinFromWelcome(mlsFromBase64(welcome.blob))
		.save();
	return groupId;
}

/**
 * Drain Bob to zero on both sides. Returns a group he genuinely holds state
 * for, so a test can drive his own next operation against something real.
 */
async function drainBob(): Promise<string> {
	await publishMlsKeyPackages(dir, BOB_ID, client);
	expect(held(BOB_ID)).toBe(MLS_KEY_PACKAGE_TARGET);

	const bobsGroups: string[] = [];
	// Derived from the pool, never from a literal round count: the policy owns
	// how many packages a publish mints.
	while (held(BOB_ID) > 0) bobsGroups.push(await spendOneKeyPackage(BOB_ID));

	// The absorbing state, asserted on both sides. Either half alone is a
	// different population with a different repair.
	expect(held(BOB_ID)).toBe(0);
	expect(localCount(BOB_ID)).toBe(0);
	return bobsGroups[0] as string;
}

/** Admit Bob to the voted group as the admitter carrying the vote. */
async function admitBob() {
	return await addMlsGroupMembers(
		dir,
		ADMIN_ID,
		VOTED_GROUP_ID,
		[BOB_ID],
		client,
		headers(ADMIN_ID),
	);
}

describe("a drained key-package pool", () => {
	it("leaves the agent un-addable until its own next read refills the pool, and the vote then seats a member that decrypts", async () => {
		const bobsFirstGroup = await drainBob();
		foundingRoster = [CARL_ID];
		await initMlsGroup(dir, ADMIN_ID, VOTED_GROUP_ID, client, headers(ADMIN_ID));

		// The drained-pool signature: the carried vote arrives, and the admission cannot
		// mint a Welcome. Nothing here fails loudly — the agent is simply skipped,
		// which is how it ends up on a roster holding no leaf.
		const refused = await admitBob();
		expect(refused.outcomes[0]?.reason).toBe("no_key_package");
		expect(refused.added).toBe(0);
		expect(inbox.get(BOB_ID) ?? []).toHaveLength(0);

		// Bob's own next operation. A plain read posts no commit and spends
		// nothing, so nothing about it prompts a top-up — which is exactly why the
		// beat has to ride on it rather than on the paths that spend.
		await syncMlsGroup(dir, BOB_ID, bobsFirstGroup, client, headers(BOB_ID));
		expect(held(BOB_ID)).toBe(MLS_KEY_PACKAGE_TARGET);
		expect(localCount(BOB_ID)).toBe(MLS_KEY_PACKAGE_TARGET);

		// The same vote, re-run: now it has a key package to spend.
		const seated = await admitBob();
		expect(seated.outcomes[0]?.reason).toBeUndefined();
		expect(seated.added).toBe(1);

		const installed = await processMlsWelcomes(dir, BOB_ID, client);
		expect(installed.groupIds).toContain(VOTED_GROUP_ID);

		// The only assertion that proves the seat is real. A roster row, an
		// outcome and an epoch are all things the shipped defect also produced.
		const enc = await encryptMlsGroupMessage(dir, ADMIN_ID, VOTED_GROUP_ID, {
			carried: "the vote",
		});
		const dec = await decryptGroupMessage(
			dir,
			BOB_ID,
			VOTED_GROUP_ID,
			enc.encrypted_payload,
			keyServer(),
			ADMIN_ID,
		);
		expect(JSON.parse(dec.plaintext)).toEqual({ carried: "the vote" });
		expect(dec.verified).toBe(true);
	});

	it("is dropped from a founding roster without a word, until its own next read refills the pool", async () => {
		const bobsFirstGroup = await drainBob();

		// The founding entry point, which fails differently from an add: the
		// server reports `has_key_package: false` and the founder simply founds
		// without him. The group exists, the other member is seated, and nothing
		// anywhere says Bob is missing — this is the "silently" in the defect.
		foundingRoster = [BOB_ID, CARL_ID];
		const partial = await initMlsGroup(
			dir,
			ADMIN_ID,
			randomUUID(),
			client,
			headers(ADMIN_ID),
		);
		expect(partial.outcomes[0]?.agentId).toBe(BOB_ID);
		expect(partial.outcomes[0]?.reason).toBe("no_key_package");
		expect(partial.added).toBe(1);
		expect(inbox.get(BOB_ID) ?? []).toHaveLength(0);
		expect(inbox.get(CARL_ID) ?? []).toHaveLength(1);

		await syncMlsGroup(dir, BOB_ID, bobsFirstGroup, client, headers(BOB_ID));

		const refounded = randomUUID();
		foundingRoster = [BOB_ID, CARL_ID];
		const whole = await initMlsGroup(
			dir,
			ADMIN_ID,
			refounded,
			client,
			headers(ADMIN_ID),
		);
		expect(whole.outcomes[0]?.reason).toBeUndefined();
		expect(whole.added).toBe(2);
		const installed = await processMlsWelcomes(dir, BOB_ID, client);
		expect(installed.groupIds).toContain(refounded);
	});
});
