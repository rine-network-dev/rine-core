/**
 * What the roster read answers, and what the welcome pass does about it.
 *
 * The pass reads each spooled Welcome's group roster BEFORE it opens the
 * Welcome, and the answer is a closed set rather than a boolean: a 403 is an
 * invitation this agent has not accepted yet, a 404 is a group that no longer
 * exists, and anything else is transient. The first two keep the Welcome
 * unopened — one retained, one dropped — and both leave the private half the
 * Welcome was sealed to sitting on disk, so the local mirror over-counts what
 * the server holds. That is the one state the local count cannot see, and it is
 * why a pass that set something aside asks the server for its count and
 * publishes the shortfall.
 *
 * The adversary here is the server, and it is played by a real MLS client: a
 * separate config dir founds the group, so the victim's device does NOT hold the
 * founder's keys. The HTTP surface is faked, and so are the key-package upload,
 * the claim and the commit post that sit behind it; the MLS state, the keys and
 * the welcome spool are real.
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

// The harness imports come first: its factory has to exist before any source
// module that reaches the mocked escrow key is loaded.
import { World } from "./crypto/world.js";
import { escrowKeyModule, withPeerReads } from "./mls-escrow-harness.js";
import {
	mintHonestWelcome,
	spooledWelcomes,
	welcomeQueue,
} from "./mls-welcome-harness.js";
import {
	claimKeyPackagesBatch,
	type MlsCommitBody,
	mlsCommit,
	mlsToBase64,
	uploadKeyPackages,
} from "../src/crypto/mls-api.js";
import { loadMlsGroup, openMlsClient } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import { admitPeers } from "../src/mls-allowed.js";
import { resetProcessGates } from "../src/process-gate.js";
import { MLS_KEY_PACKAGE_TARGET } from "../src/mls-keypackages.js";
import { processMlsWelcomes } from "../src/mls-ops.js";
import { welcomeSpoolDir } from "../src/mls-welcome-spool.js";

const VICTIM = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const COUNT_PATH = `/agents/${VICTIM}/mls/key-packages/count`;

/** The two roster answers that are transient: the Welcome is kept, never opened. */
const transientRosterFailures: [string, () => Error][] = [
	["a 5xx", () => new RineApiError(503, "unavailable")],
	["a network error", () => new TypeError("fetch failed")],
];

/** The victim's config dir: it holds the victim's keys and nobody else's. */
let dir: string;
/** The founder's own config dir, so the victim's device holds no founder keys. */
let founderDir: string;
let world: World;
/** The founder's agent id, minted fresh for each test. */
let founder: string;
/** Every commit body the fake server accepted, in order. */
let posted: MlsCommitBody[];
/** Agent ids `GET /groups/{id}/members` reports, per group. */
let members: Map<string, string[]>;
/** What `GET /agents/{id}/mls/welcomes` hands the victim. */
let inbox: ReturnType<typeof welcomeQueue>;
/** Set to make the roster read fail, as it does for a non-member or a dead group. */
let rosterFailure: Error | null;
/** What `GET /agents/{id}/mls/key-packages/count` says the server holds; null when it will not say. */
let serverHeld: number | null;
let fakeClient: { get: ReturnType<typeof vi.fn> };
let client: never;

/**
 * The group roster `GET /groups/{id}/members` reports. When a failure is set it
 * throws, which is how the pass is told the roster answered definitively.
 */
function roster(groupId: string): string[] {
	if (rosterFailure) throw rosterFailure;
	return members.get(groupId) ?? [];
}

/**
 * An honest founder seats the victim in `groupId` and returns the Welcome the
 * commit minted for it — the bytes the server would file under that group.
 *
 * Mint it with no roster failure set; the failure belongs to the pass under
 * test, not to the invitation.
 */
async function honestWelcome(groupId: string): Promise<string> {
	members.set(groupId, [founder, VICTIM]);
	return mintHonestWelcome({
		founderDir,
		founder,
		victim: VICTIM,
		groupId,
		client,
		posted,
	});
}

/** How many times the pass asked the server what it holds. */
function countReads(): number {
	return fakeClient.get.mock.calls.filter((call) => call[0] === COUNT_PATH)
		.length;
}

/** Total key packages every upload carried, across all calls. */
function uploaded(): number {
	return vi
		.mocked(uploadKeyPackages)
		.mock.calls.reduce((n, call) => n + call[2].length, 0);
}

/**
 * Give the victim a full local mirror, so the forced heartbeat publishes
 * nothing and every upload this test sees belongs to the pass under test.
 */
function fillLocalMirror(): void {
	openMlsClient(dir, VICTIM).generateKeyPackages(MLS_KEY_PACKAGE_TARGET);
	vi.mocked(uploadKeyPackages).mockClear();
	fakeClient.get.mockClear();
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-welcome-admission-"));
	founderDir = fs.mkdtempSync(
		join(tmpdir(), "rine-welcome-admission-founder-"),
	);
	world = new World();
	posted = [];
	members = new Map();
	rosterFailure = null;
	serverHeld = 0;
	vi.clearAllMocks();
	resetProcessGates();
	world.save(dir, world.addAgent({ id: VICTIM }));
	founder = randomUUID();
	world.save(founderDir, world.addAgent({ id: founder }));
	vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => {
		posted.push(body);
		return { epoch: body.epoch ?? null, delivered_to: 1 };
	});
	// The claimed package is minted on the VICTIM's config dir, so the victim
	// holds the private half the Welcome is sealed to — exactly as in life.
	vi.mocked(claimKeyPackagesBatch).mockImplementation(async (_c, ids) => ({
		claims: ids.map((agent_id) => ({
			agent_id,
			packages: [
				mlsToBase64(openMlsClient(dir, agent_id).generateKeyPackage()),
			],
		})),
	}));
	inbox = welcomeQueue(VICTIM, (path) => {
		if (path !== COUNT_PATH) throw new Error(`unexpected GET ${path}`);
		if (serverHeld === null) throw new RineApiError(404, "Not Found");
		return { available: serverHeld };
	});
	fakeClient = { get: inbox.get };
	client = withPeerReads(world, fakeClient, roster) as never;
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
	fs.rmSync(founderDir, { recursive: true, force: true });
});

describe("processMlsWelcomes — what the roster read answers", () => {
	it("keeps an invitation's Welcome unopened when the roster answers 403, and publishes the server's shortfall", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		fillLocalMirror();
		rosterFailure = new RineApiError(403, "Membership required");
		serverHeld = 0;

		const outcome = await processMlsWelcomes(dir, VICTIM, client);

		expect(outcome.discarded).toBe(0);
		expect(spooledWelcomes(dir, VICTIM)).toBe(1);
		expect(loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)).toBeNull();
		expect(countReads()).toBe(1);
		expect(uploaded()).toBe(MLS_KEY_PACKAGE_TARGET);
	});

	it("publishes only the gap the server reports", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		fillLocalMirror();
		rosterFailure = new RineApiError(403, "Membership required");
		serverHeld = 4;

		await processMlsWelcomes(dir, VICTIM, client);

		expect(countReads()).toBe(1);
		expect(uploaded()).toBe(MLS_KEY_PACKAGE_TARGET - 4);
	});

	it("drops the Welcome of a group that no longer exists, and publishes the server's shortfall", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		fillLocalMirror();
		rosterFailure = new RineApiError(404, "Not Found");
		serverHeld = 0;

		const outcome = await processMlsWelcomes(dir, VICTIM, client);

		expect(outcome.discarded).toBe(1);
		expect(spooledWelcomes(dir, VICTIM)).toBe(0);
		expect(loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)).toBeNull();
		expect(countReads()).toBe(1);
		expect(uploaded()).toBe(MLS_KEY_PACKAGE_TARGET);
	});

	it.each(transientRosterFailures)(
		"keeps the Welcome on %s and asks the server nothing more",
		async (_label, makeError) => {
			inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
			fillLocalMirror();
			rosterFailure = makeError();

			const outcome = await processMlsWelcomes(dir, VICTIM, client);

			expect(outcome.discarded).toBe(0);
			expect(spooledWelcomes(dir, VICTIM)).toBe(1);
			expect(loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)).toBeNull();
			expect(countReads()).toBe(0);
			expect(uploaded()).toBe(0);
		},
	);

	it("installs on a readable roster and makes no count request", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		fillLocalMirror();

		const result = await processMlsWelcomes(dir, VICTIM, client);

		expect(result.groupIds).toEqual([GROUP_ID]);
		expect(loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)).not.toBeNull();
		expect(countReads()).toBe(0);
		expect(spooledWelcomes(dir, VICTIM)).toBe(0);
	});

	it("never installs a group whose roster answers 403, even with its peers already admitted in this process", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		await admitPeers({ configDir: dir, agentId: VICTIM, client }, [founder]);
		fillLocalMirror();
		rosterFailure = new RineApiError(403, "Membership required");
		serverHeld = 0;

		const result = await processMlsWelcomes(dir, VICTIM, client);

		expect(loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)).toBeNull();
		expect(result.groupIds).toEqual([]);
		expect(spooledWelcomes(dir, VICTIM)).toBe(1);
	});

	it("lets an invitation's kept Welcome install once the agent is seated", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		fillLocalMirror();
		rosterFailure = new RineApiError(403, "Membership required");
		serverHeld = 0;
		await processMlsWelcomes(dir, VICTIM, client);
		expect(spooledWelcomes(dir, VICTIM)).toBe(1);

		rosterFailure = null;
		const result = await processMlsWelcomes(dir, VICTIM, client);

		expect(result.groupIds).toEqual([GROUP_ID]);
		expect(loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)).not.toBeNull();
		expect(spooledWelcomes(dir, VICTIM)).toBe(0);
	});

	it("flags the kept Welcome of an invitation as refused, so the spool bounds it", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		fillLocalMirror();
		rosterFailure = new RineApiError(403, "Membership required");

		await processMlsWelcomes(dir, VICTIM, client);

		const dirOnDisk = welcomeSpoolDir(dir, VICTIM);
		const flags = fs
			.readdirSync(dirOnDisk)
			.map((name) => JSON.parse(fs.readFileSync(join(dirOnDisk, name), "utf8")))
			.map((entry: { refused?: boolean }) => entry.refused);
		expect(flags).toEqual([true]);
	});

	it("asks the server for its count again on the next pass while the invitation is kept", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		fillLocalMirror();
		rosterFailure = new RineApiError(403, "Membership required");
		serverHeld = 0;
		await processMlsWelcomes(dir, VICTIM, client);
		serverHeld = MLS_KEY_PACKAGE_TARGET;

		await processMlsWelcomes(dir, VICTIM, client);

		expect(countReads()).toBe(2);
		expect(uploaded()).toBe(MLS_KEY_PACKAGE_TARGET);
		expect(spooledWelcomes(dir, VICTIM)).toBe(1);
	});

	it("publishes nothing when the server will not say what it holds", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		fillLocalMirror();
		rosterFailure = new RineApiError(403, "Membership required");
		serverHeld = null;

		await processMlsWelcomes(dir, VICTIM, client);

		expect(countReads()).toBe(1);
		expect(uploaded()).toBe(0);
		expect(spooledWelcomes(dir, VICTIM)).toBe(1);
	});

	it("never installs a group whose roster answers 503, even with its peers already admitted in this process", async () => {
		inbox.deliver(await honestWelcome(GROUP_ID), GROUP_ID);
		await admitPeers({ configDir: dir, agentId: VICTIM, client }, [founder]);
		fillLocalMirror();
		rosterFailure = new RineApiError(503, "unavailable");

		const result = await processMlsWelcomes(dir, VICTIM, client);

		expect(result.groupIds).toEqual([]);
		expect(loadMlsGroup(openMlsClient(dir, VICTIM), GROUP_ID)).toBeNull();
		expect(spooledWelcomes(dir, VICTIM)).toBe(1);
		expect(countReads()).toBe(0);
	});
});
