/**
 * The group-substitution guard, driven against the REAL native core.
 *
 * The adversary here is the server itself, and it is played by a second real
 * MLS client: it founds its own group under the victim's rine group UUID, seals
 * a real Welcome to the victim's own published KeyPackage, and serves it from
 * `GET /agents/{id}/mls/welcomes` — exactly the shape of the attack, with real
 * crypto on both sides. Only the HTTP surface is faked.
 *
 * The two tests that matter most are the two directions: a substituted Welcome
 * must be refused, and an honest one must still install. A guard that refuses
 * an honest Welcome is worse for every honest user than the attack it prevents.
 * The sharpest case of the second direction is the removed-then-re-invited
 * member, who holds live local state and whose new Welcome is the only way back
 * in.
 */
import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-escrow-key.js", () => escrowKeyModule());

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
		mlsCommit: vi.fn(async () => ({ epoch: null, delivered_to: 1 })),
	};
});

import { World } from "./crypto/world.js";
import { escrowKeyModule, withPeerReads } from "./mls-escrow-harness.js";
import {
	mintHonestWelcome,
	spooledWelcomes,
	welcomeQueue,
} from "./mls-welcome-harness.js";
import type { MlsCommitBody } from "../src/crypto/mls-api.js";
import {
	claimKeyPackagesBatch,
	mlsCommit,
	mlsToBase64,
} from "../src/crypto/mls-api.js";
import {
	loadMlsGroup,
	mlsGroupIdBytes,
	openMlsClient,
} from "../src/crypto/mls.js";
import {
	addMlsGroupMembers,
	processMlsWelcomes,
	removeMlsGroupMember,
} from "../src/mls-ops.js";
import {
	isMlsWelcomeRefusedError,
	refusalIsRetryable,
} from "../src/mls-welcome-guard.js";

const VICTIM = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
/** The group id an honest second Welcome in the same batch is minted for. */
const OTHER_GROUP_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";

let dir: string;
let world: World;
/** Every commit body the fake server accepted, in order. */
let posted: MlsCommitBody[];
/** Agent ids `GET /groups/{id}/members` reports, per group. */
let members: Map<string, string[]>;
/** What `GET /agents/{id}/mls/welcomes` hands the victim. */
let inbox: ReturnType<typeof welcomeQueue>;
/**
 * How many roster reads still answer before the roster stops answering. The
 * welcome pass reads the roster once to admit the group's peers, then the guard
 * reads it again, so 1 lets the admission through and fails the guard's own
 * read, as it does for a non-member.
 */
let rosterReadsLeft: number;
let client: never;

/** An agent with keys on disk, minted by the world so its chain verifies. */
function agent(): string {
	const agentId = randomUUID();
	world.save(dir, world.addAgent({ id: agentId }));
	return agentId;
}

/**
 * The group roster `GET /groups/{id}/members` reports, and the read the
 * admission path and the guard both make. An unreadable roster throws, as it
 * does for an org holding no member row.
 */
function roster(groupId: string): string[] {
	if (rosterReadsLeft <= 0) throw new Error("403 Membership required");
	rosterReadsLeft -= 1;
	return members.get(groupId) ?? [];
}

/**
 * An honest founder seats the victim in `groupId` and returns the Welcome the
 * commit minted for it — the bytes the server would file under that group.
 */
async function honestWelcome(groupId: string): Promise<string> {
	const founder = agent();
	members.set(groupId, [founder, VICTIM]);
	return mintHonestWelcome({
		founderDir: dir,
		founder,
		victim: VICTIM,
		groupId,
		client,
		posted,
	});
}

/**
 * The server founds its OWN group under `groupId` and seals a Welcome to the
 * victim's published KeyPackage. Real MLS, real Welcome, chosen group id.
 */
function substitutedWelcome(groupId: string): string {
	const impostor = agent();
	const keyPackage = openMlsClient(dir, VICTIM).generateKeyPackage();
	const group = openMlsClient(dir, impostor).createGroupWithMembers(
		mlsGroupIdBytes(groupId),
		[keyPackage],
	);
	const welcome = group.lastCommit()?.welcomes[0];
	if (!welcome) throw new Error("the impostor's group minted no welcome");
	group.save();
	return mlsToBase64(welcome);
}

/**
 * The founder evicts the victim with a real Remove commit, then re-invites it.
 *
 * This is the flow the guard used to wedge: the victim still holds live state
 * for the group, and this second Welcome is the only way back into it.
 */
async function reinvitationWelcome(groupId: string): Promise<string> {
	const founder = members.get(groupId)?.[0];
	if (!founder) throw new Error(`no founder recorded for group ${groupId}`);
	await removeMlsGroupMember(dir, founder, groupId, VICTIM, client);
	await addMlsGroupMembers(dir, founder, groupId, [VICTIM], client);
	const welcome = posted.at(-1)?.welcomes?.[0]?.welcome;
	if (!welcome) throw new Error("the re-invitation minted no welcome");
	return welcome;
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-welcome-guard-"));
	world = new World();
	posted = [];
	members = new Map();
	rosterReadsLeft = Number.POSITIVE_INFINITY;
	vi.clearAllMocks();
	world.save(dir, world.addAgent({ id: VICTIM }));
	vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => {
		posted.push(body);
		return { epoch: body.epoch ?? null, delivered_to: 1 };
	});
	vi.mocked(claimKeyPackagesBatch).mockImplementation(async (_c, ids) => ({
		claims: ids.map((agent_id) => ({
			agent_id,
			packages: [
				mlsToBase64(openMlsClient(dir, agent_id).generateKeyPackage()),
			],
		})),
	}));
	// The escrow and admission reads the orchestrators now make are answered by
	// the harness; the inbox keeps the welcome queue and the requests read, and
	// every other path is a test bug.
	inbox = welcomeQueue(VICTIM);
	const fakeClient = { get: inbox.get };
	client = withPeerReads(world, fakeClient, roster) as never;
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("processMlsWelcomes", () => {
	it("installs a welcome minted by a member of the group it names", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);

		const result = await processMlsWelcomes(dir, VICTIM, client);

		expect(result.groupIds).toEqual([GROUP_ID]);
		expect(loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)).not.toBeNull();
	});

	it("refuses a welcome from a group the roster names nobody in", async () => {
		// The rine roster is honest and says the group holds a founder and the
		// victim. The tree this welcome seats the victim in holds the server's own
		// identity instead, so nothing in it corroborates the roster.
		await honestWelcome(GROUP_ID);
		inbox.deliver(substitutedWelcome(GROUP_ID), GROUP_ID);

		const refusal = await processMlsWelcomes(dir, VICTIM, client).catch(
			(err: unknown) => err,
		);

		expect(isMlsWelcomeRefusedError(refusal)).toBe(true);
		expect((refusal as { reason: string }).reason).toBe("roster_uncorroborated");
		expect((refusal as Error).message).not.toMatch(/rotat|group sync/);
		expect(loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)).toBeNull();
	});

	it("refuses a welcome the roster contradicts while state is held", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		const substituted = substitutedWelcome(GROUP_ID);
		await processMlsWelcomes(dir, VICTIM, client);
		const epoch = loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)?.epoch();
		inbox.deliver(substituted, GROUP_ID);

		await expect(processMlsWelcomes(dir, VICTIM, client)).rejects.toSatisfy(
			(err: unknown) =>
				isMlsWelcomeRefusedError(err) &&
				(err as { reason: string }).reason === "roster_uncorroborated",
		);
		// The state that was already there is what a substitution destroys, so the
		// assertion is on the state and not merely on the refusal.
		const held = loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID);
		expect(held?.epoch()).toBe(epoch);
		expect(held?.memberIdentities().length).toBe(2);
	});

	it("refuses a welcome it cannot corroborate while state is held", async () => {
		// The same unreadable roster that ACCEPTS for an agent holding nothing
		// REFUSES here: with state to lose, corroboration has to be positive.
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		const substituted = substitutedWelcome(GROUP_ID);
		await processMlsWelcomes(dir, VICTIM, client);
		const epoch = loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)?.epoch();
		inbox.deliver(substituted, GROUP_ID);
		rosterReadsLeft = 1;

		await expect(processMlsWelcomes(dir, VICTIM, client)).rejects.toSatisfy(
			(err: unknown) =>
				isMlsWelcomeRefusedError(err) &&
				(err as { reason: string }).reason === "state_would_be_overwritten",
		);
		expect(loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)?.epoch()).toBe(
			epoch,
		);
	});

	it("installs the welcome a removed and re-invited member is sent", async () => {
		// The case the guard used to wedge permanently. The victim holds live
		// state — and holds it as ACTIVE, because eviction is not persisted, so a
		// reloaded handle says nothing useful about whether its leaf survives. The
		// roster is what settles it, and here the roster corroborates.
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		await processMlsWelcomes(dir, VICTIM, client);
		const first = loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID);
		expect(first?.isActive()).toBe(true);
		const firstEpoch = first?.epoch() ?? 0;
		inbox.deliver(await reinvitationWelcome(GROUP_ID), GROUP_ID);

		const result = await processMlsWelcomes(dir, VICTIM, client);

		expect(result.groupIds).toEqual([GROUP_ID]);
		// The new state really replaced the old: the epoch moved and the victim
		// can read the group again.
		const held = loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID);
		expect(held?.epoch()).toBeGreaterThan(firstEpoch);
		expect(held?.memberIdentities().length).toBe(2);
		expect(spooledWelcomes(dir, VICTIM)).toBe(0);
	});

	it("keeps a welcome whose refusal a later attempt can clear", async () => {
		// A refused Welcome that is dropped is dropped forever: the fetch marks it
		// consumed, so there is no second read and no peer can produce it again.
		// The first attempt refuses with an unreadable roster; the second, once the
		// roster answers, installs the SAME bytes.
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		const reinvitation = await reinvitationWelcome(GROUP_ID);
		await processMlsWelcomes(dir, VICTIM, client);
		const firstEpoch =
			loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)?.epoch() ?? 0;
		inbox.deliver(reinvitation, GROUP_ID);
		rosterReadsLeft = 1;

		await expect(processMlsWelcomes(dir, VICTIM, client)).rejects.toSatisfy(
			isMlsWelcomeRefusedError,
		);
		expect(spooledWelcomes(dir, VICTIM)).toBe(1);

		// The fetch is empty now — the server already handed the bytes over — so
		// the install can only come off the spool.
		rosterReadsLeft = Number.POSITIVE_INFINITY;
		const result = await processMlsWelcomes(dir, VICTIM, client);

		expect(result.groupIds).toEqual([GROUP_ID]);
		expect(
			loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)?.epoch(),
		).toBeGreaterThan(firstEpoch);
		expect(spooledWelcomes(dir, VICTIM)).toBe(0);
	});

	it("retries a retained refusal quietly instead of raising it again", async () => {
		// A retained refusal must not fail every later call. It was reported once,
		// when its bytes arrived; after that it is a quiet retry, or one unusable
		// Welcome would break every future join on this agent.
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		const substituted = substitutedWelcome(GROUP_ID);
		await processMlsWelcomes(dir, VICTIM, client);
		inbox.deliver(substituted, GROUP_ID);
		await expect(processMlsWelcomes(dir, VICTIM, client)).rejects.toSatisfy(
			isMlsWelcomeRefusedError,
		);

		const result = await processMlsWelcomes(dir, VICTIM, client);

		expect(result.groupIds).toEqual([]);
		expect(spooledWelcomes(dir, VICTIM)).toBe(1);
	});

	it("discards a welcome filed under a group it does not join", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), OTHER_GROUP_ID);

		await expect(processMlsWelcomes(dir, VICTIM, client)).rejects.toSatisfy(
			(err: unknown) =>
				isMlsWelcomeRefusedError(err) &&
				(err as { reason: string }).reason === "group_id_mismatch",
		);
		// Deterministic, so it is the one refusal that keeps nothing: the welcome
		// joins a group it was not filed under, on every attempt.
		expect(spooledWelcomes(dir, VICTIM)).toBe(0);
	});

	it("installs the honest welcomes in a batch that also carries a refused one", async () => {
		// The fetch is destructive, so a refusal that abandoned the batch would
		// lose every welcome behind it — permanently, since no peer can mint
		// another without noticing the first went unused.
		await honestWelcome(GROUP_ID);
		inbox.deliver(substitutedWelcome(GROUP_ID), GROUP_ID);
		inbox.deliver(await honestWelcome(OTHER_GROUP_ID), OTHER_GROUP_ID);

		await expect(processMlsWelcomes(dir, VICTIM, client)).rejects.toSatisfy(
			isMlsWelcomeRefusedError,
		);
		expect(
			loadMlsGroup(openMlsClient(dir, VICTIM), OTHER_GROUP_ID),
		).not.toBeNull();
	});

	it("installs a welcome whose roster it cannot read, and says so by doing it", async () => {
		// An agent that has been invited and has not accepted yet reads 403 from
		// every group-scoped route, so an unreadable roster has to accept. This is
		// the residual: a server that refuses the roster read defeats the
		// corroboration check, which is why no surface may call the attack closed.
		inbox.deliver(substitutedWelcome(GROUP_ID), GROUP_ID);
		rosterReadsLeft = 1;

		const result = await processMlsWelcomes(dir, VICTIM, client);

		expect(result.groupIds).toEqual([GROUP_ID]);
	});

	it("raises the refusal for the group the caller named, not the first one", async () => {
		// The server chooses the delivery ids and the queue used to be ordered by
		// them, so a decoy that sorted first made the caller's own group's refusal
		// a log line and the join fell through to the external-join fallback for a
		// group it had just refused to trust. The decoy is first here by both
		// orderings — it is written first AND named first.
		await honestWelcome(GROUP_ID);
		await honestWelcome(OTHER_GROUP_ID);
		inbox.deliver(substitutedWelcome(GROUP_ID), GROUP_ID, "aaaa-decoy");
		inbox.deliver(
			substitutedWelcome(OTHER_GROUP_ID),
			OTHER_GROUP_ID,
			"zzzz-real",
		);

		await expect(
			processMlsWelcomes(dir, VICTIM, client, { forGroup: OTHER_GROUP_ID }),
		).rejects.toSatisfy(
			(err: unknown) =>
				isMlsWelcomeRefusedError(err) && err.groupId === OTHER_GROUP_ID,
		);
	});

	it("raises a retained refusal again for the group the caller named", async () => {
		// Quiet on a pass that is not about this group — that is what keeps one
		// unusable Welcome from failing every future call. Loud for a caller that
		// is establishing this very group: it asked, and a refusal is the answer.
		await honestWelcome(GROUP_ID);
		inbox.deliver(substitutedWelcome(GROUP_ID), GROUP_ID);
		await expect(processMlsWelcomes(dir, VICTIM, client)).rejects.toSatisfy(
			isMlsWelcomeRefusedError,
		);
		expect((await processMlsWelcomes(dir, VICTIM, client)).groupIds).toEqual(
			[],
		);

		await expect(
			processMlsWelcomes(dir, VICTIM, client, { forGroup: GROUP_ID }),
		).rejects.toSatisfy(
			(err: unknown) =>
				isMlsWelcomeRefusedError(err) && err.groupId === GROUP_ID,
		);
	});

	it("does not raise a refusal for a group the caller did not name", async () => {
		// The twin of the case above, and the one the TypeScript read path was
		// missing: a substituted Welcome for one group must not fail a legitimate
		// install of another.
		await honestWelcome(GROUP_ID);
		inbox.deliver(substitutedWelcome(GROUP_ID), GROUP_ID);
		inbox.deliver(await honestWelcome(OTHER_GROUP_ID), OTHER_GROUP_ID);

		const result = await processMlsWelcomes(dir, VICTIM, client, {
			forGroup: OTHER_GROUP_ID,
		});

		expect(result.groupIds).toEqual([OTHER_GROUP_ID]);
	});

	it("installs the rest of a batch that carries a welcome no core here can open", async () => {
		// A Welcome minted by a different core or for a different ciphersuite is
		// unusable on every attempt. It leaves the spool — but the pass carries on,
		// because abandoning it would skip key-package replenishment and throw away
		// the ids this pass DID install. The Python twin logs and continues; this
		// stack used to throw, which is the asymmetry.
		inbox.deliver("AQIDBAUGBwg=", OTHER_GROUP_ID);
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);

		const result = await processMlsWelcomes(dir, VICTIM, client);

		expect(result.groupIds).toEqual([GROUP_ID]);
		expect(spooledWelcomes(dir, VICTIM)).toBe(0);
	});
});

describe("refusalIsRetryable", () => {
	it("test_retryable_when_the_refusal_is_final_for_the_tree_then_the_bytes_are_not_kept", () => {
		expect(refusalIsRetryable("peer_not_admitted")).toBe(false);
		expect(refusalIsRetryable("group_id_mismatch")).toBe(false);
		expect(refusalIsRetryable("roster_uncorroborated")).toBe(true);
		expect(refusalIsRetryable("state_would_be_overwritten")).toBe(true);
	});
});
