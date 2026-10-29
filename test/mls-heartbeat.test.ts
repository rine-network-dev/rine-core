/**
 * The key-package heartbeat: that every MLS operation carries one, and that a
 * verb added later cannot ship without one.
 *
 * The defect this pins is an absorbing state, not a slow leak. Peers claim one
 * of an agent's published key packages each time they add it to a group, so a
 * pool that is never topped up runs out — and at zero the agent is
 * **un-addable**: no member can mint it a Welcome, every further admission
 * degrades to a self-join, and a self-join processes no Welcome. So the agent
 * that most needs a top-up is the one that never gets one. It is then seated on
 * a roster by a carried vote with no leaf in the ratchet tree, listed as a full
 * member, and reads nothing the group says.
 *
 * Two halves, and the second is why this file exists at all:
 *
 *   1. **Behaviour** — each seam is driven against the REAL native core, with
 *      only `crypto/mls-api.js` standing in for the server, and the assertion is
 *      that `uploadKeyPackages` REACHED THE WIRE carrying the ACTING agent's id.
 *      Not that a helper was called: a mocked helper would have passed against
 *      every build that shipped this defect.
 *   2. **Enumeration** — every MLS name this package exports is classified by
 *      the seam its heartbeat comes from, and the classification is checked
 *      against the module's runtime exports. A new verb makes this red until
 *      somebody says where its beat comes from, which is the property nine
 *      near-identical call sites never had.
 */
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
		claimKeyPackages: vi.fn(async () => ({ packages: [], agent_id: "" })),
		claimKeyPackagesBatch: vi.fn(async () => ({ claims: [] })),
		mlsInit: vi.fn(async () => ({ mls_pending: true, members: [] })),
		mlsCommit: vi.fn(async () => ({ epoch: null, delivered_to: 1 })),
		mlsAck: vi.fn(async () => ({ confirmed: true, acks: 1, needed: 1 })),
		mlsNack: vi.fn(async () => ({ quarantined: true })),
		fetchHandshakes: vi.fn(async () => ({ handshakes: [] })),
		fetchWelcomes: vi.fn(async () => ({ welcomes: [] })),
		fetchGroupInfo: vi.fn(async () => ({ group_info: null, epoch: null })),
	};
});

import { World } from "./crypto/world.js";
import { escrowKeyModule, withPeerReads } from "./mls-escrow-harness.js";
import {
	claimKeyPackages,
	claimKeyPackagesBatch,
	fetchGroupInfo,
	fetchWelcomes,
	mlsCommit,
	mlsInit,
	mlsToBase64,
	uploadKeyPackages,
} from "../src/crypto/mls-api.js";
import { mlsGroupIdBytes, openMlsClient } from "../src/crypto/mls.js";
import * as groupRecovery from "../src/group-recovery.js";
import * as mlsAllowed from "../src/mls-allowed.js";
import * as mlsAllowedTree from "../src/mls-allowed-tree.js";
import * as mlsEscrowDrain from "../src/mls-escrow-drain.js";
import * as mlsEscrowKey from "../src/mls-escrow-key.js";
import * as mlsEscrowSend from "../src/mls-escrow-send.js";
import * as mlsEscrowGap from "../src/mls-escrow-gap.js";
import * as mlsEscrowGapList from "../src/mls-escrow-gap-list.js";
import * as mlsEscrowMarkers from "../src/mls-escrow-markers.js";
import * as mlsEscrowReport from "../src/mls-escrow-report.js";
import * as mlsEscrowSettle from "../src/mls-escrow-settle.js";
import * as mlsEscrowSweep from "../src/mls-escrow-sweep.js";
import * as mlsGroupSend from "../src/mls-group-send.js";
import * as mlsJoinEstablish from "../src/mls-join-establish.js";
import * as mlsJoinSeat from "../src/mls-join-seat.js";
import * as topUp from "../src/mls-keypackage-topup.js";
import * as mlsWelcomeAdmission from "../src/mls-welcome-admission.js";
import * as messageMls from "../src/message-mls.js";
import * as mlsCommitModule from "../src/mls-commit.js";
import * as mlsOps from "../src/mls-ops.js";
import * as mlsResync from "../src/mls-ops-resync.js";
import * as readRefusal from "../src/mls-read-refusal.js";
import * as rotatedLeaf from "../src/mls-rotated-leaf.js";
import * as recoveryFormat from "../src/mls-recovery-format.js";
import * as seatSentences from "../src/mls-seat-sentences.js";
import * as seatSweep from "../src/mls-seat-sweep.js";
import * as seatUpdate from "../src/mls-seat-update.js";
import * as selfUpdate from "../src/mls-self-update.js";
import * as packageRoot from "../src/index.js";
import {
	externalJoinMlsGroup,
	initMlsGroup,
	needsMlsKeyPackageCutover,
	processMlsWelcomes,
	removeMlsGroupMember,
	syncMlsGroup,
} from "../src/mls-ops.js";
// Off the module and not off the barrel: both gates are test seams that defeat
// a rate limit, so neither is on the published surface of @rine-network/core.
import { resetProcessGates } from "../src/process-gate.js";
import { resetMlsHeartbeatGate } from "../src/mls-heartbeat.js";

const SELF_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const MEMBER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
/** A group this agent holds no state for, so a Welcome for it cannot be read as installed. */
const OTHER_GROUP_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";
const HEADERS = { "X-Rine-Agent": SELF_ID };

let dir: string;
let world: World;
let client: never;

/**
 * The reads the admission path makes outside `crypto/mls-api.js`: the group's
 * size and its outstanding vouchers. The roster and the published keys are
 * answered by `withPeerReads` from the world, so every peer's chain verifies.
 */
const readsOnly = {
	get: async (path: string) => {
		if (path === `/groups/${GROUP_ID}`) return { member_count: 2 };
		if (path === `/groups/${GROUP_ID}/requests`) return { items: [] };
		throw new Error(`unexpected GET ${path}`);
	},
};

/** Every agent id an upload was posted for, in order. */
function uploadedFor(): string[] {
	return vi.mocked(uploadKeyPackages).mock.calls.map((call) => String(call[1]));
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-heartbeat-"));
	world = new World();
	client = withPeerReads(world, readsOnly) as never;
	vi.clearAllMocks();
	// Per process by design, so a test that inherited the previous test's stamp
	// would measure the gate rather than the beat.
	resetMlsHeartbeatGate();
	resetProcessGates();
	vi.mocked(uploadKeyPackages).mockImplementation(async (_c, _a, p) => ({
		stored: p.length,
	}));
	// Accept every commit at the epoch it declares: what a commit carried is
	// `mls-ops.test.ts`'s subject, and this file's is what happens behind it.
	vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => ({
		epoch: body.epoch ?? null,
		delivered_to: 1,
	}));
	vi.mocked(fetchWelcomes).mockResolvedValue({ welcomes: [] });
	for (const id of [SELF_ID, MEMBER_ID]) {
		world.save(dir, world.addAgent({ id }));
	}
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

/** Group state for SELF only, founded locally — no HTTP, so no beat yet. */
function seedGroupState(): void {
	openMlsClient(dir, SELF_ID).createGroup(mlsGroupIdBytes(GROUP_ID)).save();
}

/**
 * A Welcome the server serves and no core can ever open, so the pass spools it,
 * discards it and ends with no group id — the shape a beat conditioned on an
 * install would sit out.
 */
function spoolOneUnusableWelcome(groupId: string = GROUP_ID): void {
	vi.mocked(fetchWelcomes).mockResolvedValue({
		welcomes: [
			{
				id: "w1",
				group_id: groupId,
				blob: mlsToBase64(new Uint8Array([1, 2, 3])),
				created_at: "2026-01-01T00:00:00Z",
			},
		],
	});
}

/** One claimable key package for `agentId`, minted by that agent's own client. */
function offerKeyPackage(agentId: string): void {
	const pkg = mlsToBase64(openMlsClient(dir, agentId).generateKeyPackage());
	vi.mocked(claimKeyPackages).mockResolvedValue({
		packages: [pkg],
		agent_id: agentId,
	});
	vi.mocked(claimKeyPackagesBatch).mockResolvedValue({
		claims: [{ agent_id: agentId, packages: [pkg] }],
	});
}

describe("a beat rides on every MLS operation", () => {
	it("a plain sync publishes key packages for the agent that synced", async () => {
		// The structural case, and the one no verb used to cover: a member that
		// only ever reads its group spends nothing, so nothing prompted a top-up
		// and its pool drained to zero under it.
		seedGroupState();

		await syncMlsGroup(dir, SELF_ID, GROUP_ID, client, HEADERS);

		expect(uploadedFor()).toEqual([SELF_ID]);
	});

	it("founding a group publishes key packages for the founder", async () => {
		offerKeyPackage(MEMBER_ID);
		vi.mocked(mlsInit).mockResolvedValue({
			mls_pending: true,
			members: [
				{ agent_id: SELF_ID, has_key_package: true },
				{ agent_id: MEMBER_ID, has_key_package: true },
			],
		});

		await initMlsGroup(dir, SELF_ID, GROUP_ID, client);

		expect(uploadedFor()).toContain(SELF_ID);
	});

	it("a self-join publishes key packages, though it processes no Welcome", async () => {
		// The absorbing state itself. An agent at zero cannot be sent a Welcome,
		// so admission degrades to this path — and a top-up hung off Welcome
		// processing would never fire for the one agent that needs it.
		const peer = openMlsClient(dir, MEMBER_ID).createGroup(
			mlsGroupIdBytes(GROUP_ID),
		);
		peer.save();
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: mlsToBase64(peer.groupInfo()),
			epoch: 1,
		});

		await externalJoinMlsGroup(dir, SELF_ID, GROUP_ID, client, HEADERS);

		expect(uploadedFor()).toEqual([SELF_ID]);
	});

	it("a removal publishes for the remover, never for the removed member", async () => {
		seedGroupState();

		await removeMlsGroupMember(
			dir,
			SELF_ID,
			GROUP_ID,
			MEMBER_ID,
			client,
			HEADERS,
		);

		expect(uploadedFor()).toEqual([SELF_ID]);
		expect(uploadedFor()).not.toContain(MEMBER_ID);
	});

	it("a Welcome pass that installed nothing still publishes", async () => {
		// The deleted guard, pinned. A pass that installs nothing is the pass
		// most likely to have found nothing to install, so making the beat
		// conditional on an install is conditioning the cure on the symptom's
		// absence. This Welcome is unusable, so the pass ends with no group id.
		spoolOneUnusableWelcome();

		const outcome = await processMlsWelcomes(dir, SELF_ID, client);

		expect(outcome.groupIds).toEqual([]);
		expect(uploadedFor()).toEqual([SELF_ID]);
	});
});

describe("the process-local floor", () => {
	it("collapses a run of gated beats into one", async () => {
		// A 500-member founding posts one commit per batch of thirteen joiners.
		// Without the floor each of those commits would sweep the key store and
		// derive three asymmetric public keys for nothing.
		seedGroupState();

		await syncMlsGroup(dir, SELF_ID, GROUP_ID, client, HEADERS);
		await syncMlsGroup(dir, SELF_ID, GROUP_ID, client, HEADERS);
		await syncMlsGroup(dir, SELF_ID, GROUP_ID, client, HEADERS);

		expect(uploadedFor()).toEqual([SELF_ID]);
	});

	it("does not let one agent's beat stand in for another's", async () => {
		// Keyed on the agent because the pool is per-agent. A multi-agent org
		// running one process must not have its second agent silenced by its
		// first.
		seedGroupState();
		openMlsClient(dir, MEMBER_ID).createGroup(mlsGroupIdBytes(GROUP_ID)).save();

		await syncMlsGroup(dir, SELF_ID, GROUP_ID, client, HEADERS);
		await syncMlsGroup(dir, MEMBER_ID, GROUP_ID, client, {
			"X-Rine-Agent": MEMBER_ID,
		});

		expect(uploadedFor()).toEqual([SELF_ID, MEMBER_ID]);
	});

	/**
	 * A second beat inside the window cannot be told apart by its uploads: the
	 * first one left the pool at target, so the low-water check is a no-op
	 * whether the beat ran or was skipped. The cutover is the probe that tells
	 * them apart — it runs ahead of that check, and it leaves a marker on disk.
	 */
	function legacyStoreAppears(): void {
		fs.mkdirSync(join(dir, "keys", SELF_ID, "mls"), { recursive: true });
		expect(needsMlsKeyPackageCutover(dir, SELF_ID)).toBe(true);
	}

	it("skips a gated beat raised inside the window", async () => {
		seedGroupState();
		await syncMlsGroup(dir, SELF_ID, GROUP_ID, client, HEADERS);
		legacyStoreAppears();

		await syncMlsGroup(dir, SELF_ID, GROUP_ID, client, HEADERS);

		expect(needsMlsKeyPackageCutover(dir, SELF_ID)).toBe(true);
	});

	it("runs a forced beat raised inside the same window", async () => {
		// `forced`, and the reason it exists: the Welcome pass just spent a key
		// package, and waiting out a floor would leave the agent short in exactly
		// the window a peer is most likely to add it.
		seedGroupState();
		// For a group this agent holds nothing for: a Welcome naming a group it
		// IS already in reads as an install, and this test is about the pass that
		// installs nothing.
		spoolOneUnusableWelcome(OTHER_GROUP_ID);
		await syncMlsGroup(dir, SELF_ID, GROUP_ID, client, HEADERS);
		legacyStoreAppears();

		await processMlsWelcomes(dir, SELF_ID, client);

		expect(needsMlsKeyPackageCutover(dir, SELF_ID)).toBe(false);
	});
});

describe("the KeyPackage cutover", () => {
	it("is reached by a read-only sync, which is the only verb some agents run", async () => {
		// The cutover fires from `ensureMlsKeyPackages` and from nowhere else, so
		// before the heartbeat an upgraded agent that only read, synced,
		// self-joined or removed never cut over — and its whole published pool
		// stayed unreadable to every peer.
		fs.mkdirSync(join(dir, "keys", SELF_ID, "mls"), { recursive: true });
		expect(needsMlsKeyPackageCutover(dir, SELF_ID)).toBe(true);
		seedGroupState();

		await syncMlsGroup(dir, SELF_ID, GROUP_ID, client, HEADERS);

		expect(uploadedFor()).toEqual([SELF_ID]);
		expect(needsMlsKeyPackageCutover(dir, SELF_ID)).toBe(false);
	});
});

/**
 * Where a name's beat comes from. Not free text: a seam is a place in the code,
 * and every name below is answerable by reading one.
 */
type HeartbeatSeam =
	/** Beats inside `postMlsCommit` — every commit this package posts. */
	| "commit"
	/** Beats inside `syncMlsGroup` — every read-side catch-up. */
	| "sync"
	/** Calls `mlsHeartbeat` itself, forced, having just spent a package. */
	| "forced"
	/** Is the key-package machinery, so it publishes as its own purpose. */
	| "key-packages"
	/** Spends no key package and holds no MLS state: a reader, a type or a word. */
	| "no-mls-state";

/**
 * Every MLS name this package exports, and the seam that beats for it.
 *
 * 🔴 The point of the table is the check under it, not the table. A verb added
 * to `mls-ops.ts` without a line here fails this file, and the only way to add
 * the line is to answer where its heartbeat comes from — which is the question
 * that went unasked for eleven verbs.
 */
const HEARTBEAT_SEAMS: Record<HeartbeatSeam, readonly string[]> = {
	commit: [
		// The seam itself, and every verb that posts through it.
		"postMlsCommit",
		"addMlsGroupMember",
		"addMlsGroupMembers",
		"initMlsGroup",
		"resumeMlsGroupAdmission",
		"externalJoinMlsGroup",
		"reclaimOrphanLeaves",
		"removeMlsGroupMember",
		// The bundle poster beats inside the settlement hold, and the self-update
		// builds its commit through it.
		"postMlsCommitBundle",
		"selfUpdateGroup",
		"selfUpdateStaleLeaves",
	],
	sync: [
		"syncMlsGroup",
		"catchUpMlsGroup",
		"recoverMlsGroup",
		"recoverGroup",
		// The group send syncs to the current epoch before it seals, and installs
		// a pending Welcome only through `processMlsWelcomes`, which beats forced.
		"sealAndPostMlsGroupMessage",
		// The MLS group read: a read that opens runs the catch-up, and one that
		// cannot recovers through the scoped Welcome pass (forced), an external
		// join (a commit) and a sync.
		"readMlsGroupMessage",
	],
	forced: [
		"processMlsWelcomes",
		// Runs the scoped Welcome pass first, which beats forced, and every commit
		// it posts beats inside `postMlsCommit`.
		"establishMlsMembership",
		// Reads local state, then runs the establishment above.
		"establishAfterAlreadyAMember",
		// Answers an `already_a_member` 409 through the establishment above.
		"seatedMemberAfterConflict",
	],
	"key-packages": [
		"cutoverMlsKeyPackages",
		"drainAndRepublishMlsKeyPackages",
		"ensureMlsKeyPackages",
		"needsMlsKeyPackageCutover",
		"publishMlsKeyPackages",
		"replenishMlsKeyPackages",
		"topUpKeyPackages",
		"topUpFromServerCount",
		// The settlement runs ahead of the top-up on a beat and replaces the
		// published packages itself when a rotation superseded them.
		"settleRotation",
		"NO_KEY_PACKAGE_TOP_UP",
	],
	"no-mls-state": [
		// The predicate beside the commit poster: it reads an error and mints
		// nothing.
		"isEpochConflict",
		// Hands a failed establishment to the caller's renderer and mints nothing.
		"reportFailedSetup",
		// The once-only retry around it: it runs the caller's attempt and posts
		// nothing of its own, so the caller's attempt carries any heartbeat.
		"retryOnEpochConflict",
		// Tree and roster readers: they answer questions about other agents'
		// leaves and mint nothing.
		"fetchMlsIdentities",
		"isSeated",
		"orphanLeaves",
		// The admission helpers: they read the roster and the chain-verified keys
		// and insert into the allowed set. None of them opens an MLS store or
		// spends a key package.
		"allowedFor",
		"admitPeers",
		"admitGroupPeers",
		"admitTree",
		"admitWelcomePeers",
		"openPeerMlsClient",
		"openPeerMlsGroup",
		// The read escrow: it seals and uploads what a group already yielded, and
		// the send helpers drain it and read back the head. None of them spends a
		// key package or posts a commit.
		"drainEscrow",
		"takeAndSeal",
		// Settle a group's old state before a wipe or a replace discards it
		// (local only), and the join's escrow tail that settles and then drains
		// the joined group: neither spends a key package or posts a commit.
		"settleEscrow",
		"settleAfterJoin",
		// The cross-group sweep and the typed report every result carries.
		"hasEscrowWork",
		"sweepPendingEscrow",
		"startupEscrowSweep",
		"inBackground",
		"EscrowDeferral",
		// The gap markers: files naming epochs the sweep gave up on. Local
		// bookkeeping, nothing spends a key package.
		"EscrowLoss",
		"writeGap",
		"clearGap",
		"fileGaps",
		"lostGaps",
		"toDrainGap",
		"giveUpPending",
		"readGap",
		"groupMarkers",
		"asGapReason",
		"listGapMarkers",
		"describeGapMarkers",
		"deferralFor",
		"describeEscrowGaps",
		"emptyOutcome",
		"emptyReport",
		"mergeReports",
		"reportDrain",
		"reportOf",
		"resolveEscrowKey",
		"cachedEscrowKey",
		"forgetEscrowKey",
		"dropEscrowKeys",
		"BranchRevokedError",
		"ESCROW_KEY_REVOKED",
		"prepareEscrowForSend",
		"postWithEscrowRetry",
		"isEscrowMissing",
		"EscrowUnavailableError",
		"ESCROW_MISSING_CODE",
		// The refusal vocabulary. No MLS work.
		"MlsWelcomeRefusedError",
		"isMlsWelcomeRefusedError",
		"MLS_RESYNC_REQUIRED_CODE",
		"MLS_RESYNC_UNAVAILABLE_CODE",
		"MlsResyncUnavailableError",
		"isMlsResyncRequired",
		"isMlsResyncUnavailable",
		// The rotated-leaf outcome: a typed refusal and the wrapper that raises it
		// around a resync attempt the caller supplies. The wrapper admits peers and
		// runs that attempt; it opens no store and mints no key package itself.
		"MlsRotatedLeafError",
		"isMlsRotatedLeaf",
		"rotatedLeafMessage",
		"admitRefusingRotatedLeaf",
		// The recovery's sentence renderers. They read a result and return prose;
		// none of them opens an MLS store, so none of them can spend a key package.
		"MLS_EVICTED_BY_COMMIT",
		"MLS_NEVER_FOUNDED_NOTE",
		"describeMlsReclamation",
		"describeMlsRecovery",
		"joinLines",
		"keyPackageTopUpLine",
		"mlsInitInFlightSync",
		"mlsNeverFoundedSync",
		"notAnMlsGroupResume",
		"unfoundedGroupNote",
		// The unopenable-read sentence and the CLI's remedy clause for it. Prose
		// about a key this agent does not hold — reading no store, and minting
		// nothing that could spend one.
		"cliSyncRemedy",
		"mlsReadRefusal",
		"sdkSyncRemedy",
		// The join's outcome vocabulary and the predicates beside it: they read a
		// result or an error and open no store.
		"ALREADY_A_MEMBER_CODE",
		"isAlreadyAMember",
		"MlsEstablishStep",
		"MlsMembershipOutcome",
		"mlsStateEstablished",
		// The rotation report's vocabulary and the sentence that renders it:
		// words about a leaf, reading no store.
		"SeatUpdateStatus",
		"SeatDeferReason",
		"SeatFailReason",
		"KeyPackageRotation",
		"seatUpdateLine",
		// The MLS application-message seal: it ratchets a group this agent
		// already holds, spends no key package and posts no commit, and the send
		// that calls it syncs first.
		"encryptMlsGroupMessage",
	],
};

/**
 * The modules that carry this package's MLS surface: the verb barrel, the
 * commit poster, the recovery ladder, the recovery's key-package top-up, the
 * regime branch every surface's sync verb funnels into, and the prose that
 * reports what any of them did. Read as runtime exports rather than parsed out
 * of the source, so the check cannot be fooled by a re-export the regex did not
 * know about.
 */
const CENSUS_MODULES = {
	"mls-ops.js": mlsOps,
	"mls-commit.js": mlsCommitModule,
	"mls-ops-resync.js": mlsResync,
	"mls-rotated-leaf.js": rotatedLeaf,
	"mls-allowed.js": mlsAllowed,
	"mls-allowed-tree.js": mlsAllowedTree,
	"mls-welcome-admission.js": mlsWelcomeAdmission,
	"mls-escrow-drain.js": mlsEscrowDrain,
	"mls-escrow-key.js": mlsEscrowKey,
	"mls-escrow-send.js": mlsEscrowSend,
	"mls-escrow-gap.js": mlsEscrowGap,
	"mls-escrow-gap-list.js": mlsEscrowGapList,
	"mls-escrow-markers.js": mlsEscrowMarkers,
	"mls-escrow-report.js": mlsEscrowReport,
	"mls-escrow-settle.js": mlsEscrowSettle,
	"mls-escrow-sweep.js": mlsEscrowSweep,
	"mls-group-send.js": mlsGroupSend,
	"mls-join-establish.js": mlsJoinEstablish,
	"mls-join-seat.js": mlsJoinSeat,
	"mls-keypackage-topup.js": topUp,
	"mls-recovery-format.js": recoveryFormat,
	"mls-seat-sentences.js": seatSentences,
	"mls-seat-sweep.js": seatSweep,
	"mls-seat-update.js": seatUpdate,
	"mls-self-update.js": selfUpdate,
	"mls-read-refusal.js": readRefusal,
	"group-recovery.js": groupRecovery,
	"message-mls.js": messageMls,
};

/** A module path the census is answerable for, as `index.ts` names it. */
const MLS_MODULE = /^(mls-[\w-]+|message-mls|group-recovery)\.js$/;

const BARREL_SOURCE = fs.readFileSync(
	new URL("../src/index.ts", import.meta.url),
	"utf8",
);

/**
 * The package barrel's explicit lines: every module it publishes from, and the
 * VALUE names each `export { … } from "./….js"` line lists (an `export type`
 * line counts its module but names nothing that exists at runtime).
 */
const BARREL = new Map<string, string[]>();
// Both groups always take part in a match; the defaults only satisfy the type.
for (const [, typeOnly, list = "", mod = ""] of BARREL_SOURCE.matchAll(
	/^export (type )?\{([^}]*)\} from "\.\/([\w./-]+\.js)";$/gm,
)) {
	const names = typeOnly
		? []
		: list
				.split(",")
				.map((n) => n.trim())
				.filter(Boolean);
	BARREL.set(mod, [...(BARREL.get(mod) ?? []), ...names]);
}

describe("every MLS name is answerable for its heartbeat", () => {
	const exported = Object.values(CENSUS_MODULES)
		.flatMap((mod) => Object.keys(mod))
		.sort();

	it("classifies exactly the names the package exports, no more and no fewer", () => {
		const classified = Object.values(HEARTBEAT_SEAMS).flat();
		expect([...new Set(classified)].sort()).toEqual([
			...new Set(exported),
		].sort());
	});

	it("classifies each name once", () => {
		const classified = Object.values(HEARTBEAT_SEAMS).flat();
		expect(classified).toHaveLength(new Set(classified).size);
	});

	it("counts every MLS module the package barrel publishes from", () => {
		// 🔴 The census is a set of MODULES, so a name can reach the public
		// surface without entering it — `index.ts` publishes `isEpochConflict`
		// straight off `mls-commit.js`, which is exactly that door. This is the
		// door's own gate: an MLS module `index.ts` publishes from and this table
		// does not read is a name nobody has been asked to answer for.
		for (const mod of BARREL.keys()) {
			if (!MLS_MODULE.test(mod)) continue;
			expect(
				Object.hasOwn(CENSUS_MODULES, mod),
				`${mod} reaches the barrel but no seam table reads it`,
			).toBe(true);
		}
	});

	it("reads the barrel as the package publishes it", () => {
		// The door above reads `index.ts` as source, so it is only as good as
		// the parse. Two ways it could see less than the package publishes: an
		// `export *` line, which names nothing to read, and a line in a shape the
		// parse does not know. The first is refused outright; the second is
		// caught at runtime, where every root export that is an MLS module's own
		// binding must have been read off a line naming that module.
		expect(BARREL_SOURCE).not.toMatch(/^export \*/m);
		const parsed = new Set(
			[...BARREL.entries()]
				.filter(([mod]) => MLS_MODULE.test(mod))
				.flatMap(([, names]) => names),
		);
		const root: Record<string, unknown> = packageRoot;
		for (const [mod, exports] of Object.entries(CENSUS_MODULES)) {
			const own: Record<string, unknown> = exports;
			for (const name of Object.keys(own)) {
				if (Object.hasOwn(root, name) && root[name] === own[name]) {
					expect(
						parsed.has(name),
						`${name} (${mod}) is published off no parsed line`,
					).toBe(true);
				}
			}
		}
		for (const [mod, names] of BARREL) {
			if (!Object.hasOwn(CENSUS_MODULES, mod)) continue;
			const own: Record<string, unknown> =
				CENSUS_MODULES[mod as keyof typeof CENSUS_MODULES];
			for (const name of names) {
				expect(
					Object.hasOwn(own, name),
					`${name} is parsed off ${mod}, which does not export it`,
				).toBe(true);
			}
		}
	});

	it("routes every verb that can spend a key package through a beating seam", () => {
		const beating = new Set([
			...HEARTBEAT_SEAMS.commit,
			...HEARTBEAT_SEAMS.sync,
			...HEARTBEAT_SEAMS.forced,
		]);
		// Named one by one rather than derived: this is the list an operator's
		// group membership depends on, and deriving it from the same table it
		// checks would make the assertion agree with itself.
		for (const verb of [
			"addMlsGroupMember",
			"addMlsGroupMembers",
			"catchUpMlsGroup",
			"externalJoinMlsGroup",
			"initMlsGroup",
			"processMlsWelcomes",
			"reclaimOrphanLeaves",
			"recoverGroup",
			"recoverMlsGroup",
			"removeMlsGroupMember",
			"resumeMlsGroupAdmission",
			"syncMlsGroup",
		]) {
			expect(beating.has(verb), `${verb} has no heartbeat seam`).toBe(true);
		}
	});
});
