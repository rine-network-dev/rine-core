/**
 * `recoverGroup` — which recovery a group gets, and what decides it.
 *
 * The decision is the whole subject here. It is made from the group row's
 * `mls_group_id` latch and never from whether local state happens to load:
 * absent state is a symptom shared by an MLS member whose store was deleted and
 * by every member of an open group, and a build that branched on it told the
 * second to ask an admin to remove and re-invite them.
 *
 * So the MLS-with-no-state case runs against the REAL ladder rather than a mock
 * — it is the direct unit mirror of `scripts/firstperson/act4d-sync-verb.sh`,
 * which takes an MLS group's state away for real and grades the refusal — while
 * the arms that would need a founded group or a full inbox drive stubs of the
 * two primitives, which are covered in their own suites.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const recoverMlsGroupSpy = vi.fn();
const scanSpy = vi.fn();
const retirementSpy = vi.fn();
/**
 * The key-package top-up rides ahead of the regime branch on every call, so it
 * is stubbed here for the same reason the two primitives are: this suite is
 * about which recovery a group GETS. It answers `healthy` — the one arm that
 * spreads no field — so every assertion below stays about the shape the
 * decision produced. That the top-up really runs, really reaches the wire, and
 * really rides on the refusal is `group-recovery-topup.test.ts`, against the
 * real one.
 */
const topUpSpy = vi.fn(async () => ({ outcome: "healthy", published: 0 }));
/**
 * The self-update runs after a recovery that kept the agent in the group. Its
 * own behaviour is `mls-self-update.test.ts`; here it only has to be reached and
 * its answer carried.
 */
const selfUpdateSpy = vi.fn(async (_actor: unknown, groupId: string) => ({
	group_id: groupId,
	status: "current",
}));

vi.mock("../src/mls-ops-resync.js", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("../src/mls-ops-resync.js")>();
	return {
		...actual,
		recoverMlsGroup: (...args: unknown[]) => recoverMlsGroupSpy(...args),
	};
});

vi.mock("../src/mls-keypackage-topup.js", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("../src/mls-keypackage-topup.js")>();
	return { ...actual, topUpKeyPackages: () => topUpSpy() };
});

vi.mock("../src/mls-self-update.js", () => ({
	selfUpdateGroup: (...args: [unknown, string]) => selfUpdateSpy(...args),
}));

vi.mock("../src/sender-key-recovery.js", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("../src/sender-key-recovery.js")>();
	return {
		...actual,
		scanPendingSKDistributions: (...args: unknown[]) => scanSpy(...args),
		retirementBlocksRead: (...args: unknown[]) => retirementSpy(...args),
	};
});

const realResync = await vi.importActual<
	typeof import("../src/mls-ops-resync.js")
>("../src/mls-ops-resync.js");

import { saveAgentKeys } from "../src/crypto/keys.js";
import { generateAgentKeys } from "./helpers/keys.js";
import { recoverGroup } from "../src/group-recovery.js";
import type { GroupRecoveryResult } from "../src/group-recovery.js";
import { MlsResyncUnavailableError } from "../src/mls-ops-resync.js";

/**
 * The warning, read through the discriminant rather than around it.
 *
 * An MLS result carries no such field at all, and a test that reached for it
 * with a cast would be asserting on a shape the type says cannot exist — which
 * is the thing the union is for.
 */
const noteOf = (result: GroupRecoveryResult): string | undefined =>
	result.regime === "sender-key" ? result.mlsNeverFoundedNote : undefined;

const AGENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

// Every row states its `enrollment_policy`, because the parameter type requires
// it: the fourth arm is decided from what the group was created FOR, and a row
// that could omit it would fall back to the sender-key arm silently — which is
// the defect the arm exists to close, reinstated one level up.
const MLS_ROW = {
	id: GROUP_ID,
	enrollment_policy: "closed",
	mls_enabled: true,
	mls_group_id: "latched",
	mls_pending: false,
};
const OPEN_ROW = {
	id: GROUP_ID,
	enrollment_policy: "open",
	mls_enabled: true,
	mls_group_id: null,
	mls_pending: false,
};
const IN_FLIGHT_ROW = {
	id: GROUP_ID,
	enrollment_policy: "closed",
	mls_enabled: true,
	mls_group_id: null,
	mls_pending: true,
};
/** Created to run MLS, and its tree was never founded. */
const UNFOUNDED_ROW = {
	id: GROUP_ID,
	enrollment_policy: "closed",
	mls_enabled: true,
	mls_group_id: null,
	mls_pending: false,
};

const REPLAYED = {
	regime: "mls" as const,
	rung: "replay" as const,
	fromEpoch: 4,
	epoch: 9,
	behind: 5,
	processed: 5,
	evicted: false,
};

/** Nothing in this suite is allowed to reach the network. */
const client = {
	get: async (path: string) => {
		throw new Error(`unexpected GET ${path}`);
	},
} as never;

let dir: string;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-grouprecovery-"));
	vi.clearAllMocks();
	// The default is the REAL ladder, so an arm that means to exercise it is not
	// silently answered by a stub.
	recoverMlsGroupSpy.mockImplementation(realResync.recoverMlsGroup);
	retirementSpy.mockResolvedValue(false);
	scanSpy.mockResolvedValue({ ingested: 0, unscanned: 0 });
	saveAgentKeys(dir, AGENT_ID, generateAgentKeys());
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("recoverGroup — a sender-key group", () => {
	it("installs the keys waiting in this agent's inbox and commits nothing", async () => {
		scanSpy.mockResolvedValue({ ingested: 3, unscanned: 0 });

		const result = await recoverGroup(dir, AGENT_ID, OPEN_ROW, client);

		expect(result).toEqual({
			regime: "sender-key",
			ingested: 3,
			retired: false,
		});
		expect(recoverMlsGroupSpy).not.toHaveBeenCalled();
	});

	it("carries the shortfall when the scan's one page did not cover the inbox", async () => {
		// The number the sync answer states. It is the server's own `total` minus
		// the page that was read, so it reaches the renderer or it is lost — the
		// scan is not run twice.
		scanSpy.mockResolvedValue({ ingested: 0, unscanned: 37 });

		const result = await recoverGroup(dir, AGENT_ID, OPEN_ROW, client);

		expect(result).toEqual({
			regime: "sender-key",
			ingested: 0,
			retired: false,
			unscanned: 37,
		});
	});

	it("omits the shortfall entirely when the page covered the whole inbox", async () => {
		// Absent, never `0`: this result is spread into JSON by `rine_group_sync`,
		// and a zero there is a number reporting that nothing happened.
		const result = await recoverGroup(dir, AGENT_ID, OPEN_ROW, client);

		expect(Object.keys(result)).not.toContain("unscanned");
	});

	it("omits the shortfall for a retired group, where no scan ran to fall short", async () => {
		retirementSpy.mockResolvedValue(true);

		const result = await recoverGroup(dir, AGENT_ID, OPEN_ROW, client);

		expect(Object.keys(result)).not.toContain("unscanned");
	});

	it("passes the group id to the scan, because nothing else spends a retirement", async () => {
		// The scan's own retirement gate is keyed on the group whose read
		// missed. Omitting it leaves a re-admitted member refusing every
		// distribution its new peers send it, for ever.
		await recoverGroup(dir, AGENT_ID, OPEN_ROW, client, { "X-Rine-Agent": AGENT_ID });

		expect(scanSpy).toHaveBeenCalledWith(
			client,
			dir,
			AGENT_ID,
			undefined,
			GROUP_ID,
		);
	});

	it("reports a retired group as retired, and never pays for the scan", async () => {
		retirementSpy.mockResolvedValue(true);

		const result = await recoverGroup(dir, AGENT_ID, OPEN_ROW, client);

		expect(result).toEqual({
			regime: "sender-key",
			ingested: 0,
			retired: true,
		});
		expect(scanSpy).not.toHaveBeenCalled();
	});

	it("succeeds for a member holding no local state at all", async () => {
		// The ordinary case: installing keys from scratch is exactly what the
		// ingest does, so no state precondition may stand in front of this arm.
		const result = await recoverGroup(dir, AGENT_ID, OPEN_ROW, client);

		expect(result.regime).toBe("sender-key");
	});
});

describe("recoverGroup — an MLS group", () => {
	it("delegates to the ladder and reports the rung it took", async () => {
		recoverMlsGroupSpy.mockResolvedValue(REPLAYED);

		const result = await recoverGroup(dir, AGENT_ID, MLS_ROW, client, {
			"X-Rine-Agent": AGENT_ID,
		});

		expect(result).toEqual({
			...REPLAYED,
			seat: { group_id: GROUP_ID, status: "current" },
		});
		expect(recoverMlsGroupSpy).toHaveBeenCalledWith(dir, AGENT_ID, GROUP_ID, client, {
			"X-Rine-Agent": AGENT_ID,
		});
		expect(scanSpy).not.toHaveBeenCalled();
	});

	it("moves the agent's own leaf only after a recovery that kept it in the group", async () => {
		recoverMlsGroupSpy.mockResolvedValue({ ...REPLAYED, evicted: true });

		const result = await recoverGroup(dir, AGENT_ID, MLS_ROW, client);

		expect(selfUpdateSpy).not.toHaveBeenCalled();
		expect(result).not.toHaveProperty("seat");
	});

	it("still refuses by name when the local state will not load", async () => {
		// 🔴 The regression the r5 revert undid. The row is MLS-latched and the
		// store is empty, which is the one case that must NOT be read as an open
		// group: the remedy is an admin re-inviting this agent, and telling a
		// sender-key member that is advice about a tree their group has not got.
		// Driven against the real ladder — the spy is not stubbed here. The ladder
		// asks the server for a waiting Welcome and for a GroupInfo to take a leaf
		// back from before it gives up, and this server has neither.
		const emptyServer = {
			get: async (path: string) => {
				if (path.endsWith("/mls/welcomes")) return { welcomes: [] };
				if (path.endsWith("/mls/group-info")) return { group_info: null, epoch: null };
				throw new Error(`unexpected GET ${path}`);
			},
		} as never;
		const err = await recoverGroup(dir, AGENT_ID, MLS_ROW, emptyServer).catch(
			(e: unknown) => e,
		);

		expect(err).toBeInstanceOf(MlsResyncUnavailableError);
		expect((err as { code?: string }).code).toBe("mls_resync_unavailable");
		expect((err as Error).message).toContain("remove this agent");
		expect(scanSpy).not.toHaveBeenCalled();
	});
});

describe("recoverGroup — a group whose MLS init is in flight", () => {
	it("refuses with its own sentence and runs neither recovery", async () => {
		const err = await recoverGroup(dir, AGENT_ID, IN_FLIGHT_ROW, client).catch(
			(e: unknown) => e,
		);

		expect((err as Error).message).toContain("still founding its MLS state");
		expect(recoverMlsGroupSpy).not.toHaveBeenCalled();
		expect(scanSpy).not.toHaveBeenCalled();
		expect(retirementSpy).not.toHaveBeenCalled();
	});

	it("is a bare Error, so no surface has to learn a new class for it", async () => {
		const err = await recoverGroup(dir, AGENT_ID, IN_FLIGHT_ROW, client).catch(
			(e: unknown) => e,
		);

		expect(err).toBeInstanceOf(Error);
		expect(err).not.toBeInstanceOf(MlsResyncUnavailableError);
		expect((err as { code?: string }).code).toBeUndefined();
	});
});

describe("recoverGroup — a group whose ratchet tree was never founded", () => {
	it("runs the scan this group really does have, then warns about the tree it has not", async () => {
		// 🔴 The state this row describes is NOT frozen: the server accepts a
		// sender-key send into it, the send path mints and fans out keys for it,
		// so the distribution scan can and does find things. Refusing ahead of the
		// scan cost an operator those keys to buy a sentence.
		scanSpy.mockResolvedValue({ ingested: 3, unscanned: 0 });

		const result = await recoverGroup(dir, AGENT_ID, UNFOUNDED_ROW, client);

		expect(result).toEqual({
			regime: "sender-key",
			ingested: 3,
			retired: false,
			mlsNeverFoundedNote: expect.stringContaining("never founded"),
		});
		expect(scanSpy).toHaveBeenCalledWith(
			client,
			dir,
			AGENT_ID,
			undefined,
			GROUP_ID,
		);
		expect(retirementSpy).toHaveBeenCalled();
		// The one thing that must NOT happen: the MLS ladder has nothing to walk
		// on a group with no epoch chain.
		expect(recoverMlsGroupSpy).not.toHaveBeenCalled();
	});

	it("warns on every answer the scan can produce, because the fact is the group's", async () => {
		// The warning is about the GROUP and is orthogonal to what the scan did,
		// so all three sender-key answers carry it — including the retired one,
		// whose own remedy is the retry that unblocks the scan and is stated first.
		scanSpy.mockResolvedValue({ ingested: 0, unscanned: 0 });
		const empty = await recoverGroup(dir, AGENT_ID, UNFOUNDED_ROW, client);
		retirementSpy.mockResolvedValue(true);
		const retired = await recoverGroup(dir, AGENT_ID, UNFOUNDED_ROW, client);

		expect(empty).toMatchObject({ ingested: 0, retired: false });
		expect(noteOf(empty)).toContain("never founded");
		expect(retired).toMatchObject({ ingested: 0, retired: true });
		expect(noteOf(retired)).toContain("never founded");
	});

	it("names no verb by default, and this surface's verb when told one", async () => {
		const silent = await recoverGroup(dir, AGENT_ID, UNFOUNDED_ROW, client);
		const named = await recoverGroup(
			dir,
			AGENT_ID,
			UNFOUNDED_ROW,
			client,
			undefined,
			"cli-resume-admission",
		);

		expect(noteOf(silent)).not.toContain("resume-admission");
		expect(noteOf(named)).toContain("Run rine group resume-admission on it");
	});

	it("still refuses an init in flight, which is the case that has no keys either", async () => {
		// 🔴 The two states are field-for-field alike in the MLS columns and only
		// one of them changed. An init in flight is FROZEN server-side: a
		// sender-key send into it is refused, so there is nothing for a scan to
		// find and running one would be a wrong action, not a wrong sentence.
		const err = await recoverGroup(dir, AGENT_ID, IN_FLIGHT_ROW, client).catch(
			(e: unknown) => e,
		);

		expect(err).toBeInstanceOf(Error);
		expect(err).not.toBeInstanceOf(MlsResyncUnavailableError);
		expect(scanSpy).not.toHaveBeenCalled();
	});

	it("leaves a closed group that opted out of MLS on the sender-key arm", async () => {
		// `mls_enabled: false` on a closed group is legal on the wire and means
		// the group really is a sender-key group. Reading `enrollment_policy`
		// alone would refuse it for ever.
		const optedOut = { ...UNFOUNDED_ROW, mls_enabled: false };

		const result = await recoverGroup(dir, AGENT_ID, optedOut, client);

		expect(result).toEqual({
			regime: "sender-key",
			ingested: 0,
			retired: false,
		});
	});

	it("leaves a legitimately open group on the plain sender-key arm, with no warning", async () => {
		// 🔴 The regression this change most plausibly causes: an open group
		// carries `mls_enabled: true` from birth and has the same null latch, so
		// a warning keyed off the latch alone would tell every open group it was
		// created to run MLS.
		const result = await recoverGroup(dir, AGENT_ID, OPEN_ROW, client);

		expect(result).toEqual({
			regime: "sender-key",
			ingested: 0,
			retired: false,
		});
		expect(result).not.toHaveProperty("mlsNeverFoundedNote");
	});

	it("leaves a founded MLS group untouched", async () => {
		recoverMlsGroupSpy.mockResolvedValue(REPLAYED);

		const result = await recoverGroup(dir, AGENT_ID, MLS_ROW, client);

		expect(result).toEqual({
			...REPLAYED,
			seat: { group_id: GROUP_ID, status: "current" },
		});
		expect(result).not.toHaveProperty("mlsNeverFoundedNote");
	});
});
