/**
 * The KeyPackage cutover, driven against the REAL native core.
 *
 * Only the network is mocked: `crypto/mls-api.js` stands in for the server's
 * upload/claim pair, backed by an in-memory pool that behaves the way the
 * server does — a claim consumes what it returns, oldest first, and an
 * exhausted pool is a conflict.
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
		uploadKeyPackages: vi.fn(),
		claimKeyPackages: vi.fn(),
	};
});

// The pre-check that the disk key is the agent's published one is pinned against
// the real predicate in the seat-sweep suites; the cutover mechanics are what is
// under test here, so the check answers yes.
vi.mock("../src/mls-key-current.js", () => ({
	diskKeyIsCurrent: vi.fn(async () => true),
}));

import { saveAgentKeys } from "../src/crypto/keys.js";
import { generateAgentKeys } from "./helpers/keys.js";
import { claimKeyPackages, uploadKeyPackages } from "../src/crypto/mls-api.js";
import { mlsFromBase64, mlsToBase64 } from "../src/crypto/mls-api.js";
import { MLS_ERR_UNREADABLE_KEY_PACKAGE } from "../src/crypto/mls-errors.js";
import { mlsErrorCode } from "../src/crypto/mls-errors.js";
import { mlsGroupIdBytes, openMlsClient } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import { MLS_KEY_PACKAGE_TARGET } from "../src/mls-keypackages.js";
import {
	cutoverMlsKeyPackages,
	drainAndRepublishMlsKeyPackages,
	ensureMlsKeyPackages,
	needsMlsKeyPackageCutover,
} from "../src/mls-ops.js";

const SELF_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const MEMBER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

const client = {} as never;

let dir: string;
/** Every base64 package the code uploaded, in order. */
let uploaded: string[][];

/**
 * The server's key-package pool for one agent: FIFO, claims consume, and an
 * empty pool is `ConflictError("No key packages available")`.
 */
function serverPool(packages: string[]): void {
	const pool = [...packages];
	vi.mocked(claimKeyPackages).mockImplementation(async (_c, agentId, count) => {
		const taken = pool.splice(0, count ?? 1);
		if (taken.length === 0) {
			throw new RineApiError(409, "No key packages available");
		}
		return { packages: taken, agent_id: agentId };
	});
}

/** A pre-cutover config dir: the ts-mls-era store exists, no cutover marker. */
function legacyAgent(agentId: string): void {
	saveAgentKeys(dir, agentId, generateAgentKeys());
	fs.mkdirSync(join(dir, "keys", agentId, "mls", "key_packages"), {
		recursive: true,
		mode: 0o700,
	});
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-mls-cutover-"));
	uploaded = [];
	vi.mocked(uploadKeyPackages).mockImplementation(async (_c, _a, packages) => {
		uploaded.push(packages);
		return { stored: packages.length };
	});
	serverPool([]);
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
	vi.clearAllMocks();
});

// ── the drain itself ─────────────────────────────────────────────────────────

describe("drainAndRepublishMlsKeyPackages", () => {
	it("claims the stale pool out of the server before publishing the new one", async () => {
		saveAgentKeys(dir, SELF_ID, generateAgentKeys());
		const stale = ["stale-1", "stale-2", "stale-3"];
		serverPool(stale);

		const result = await drainAndRepublishMlsKeyPackages(dir, SELF_ID, client);

		expect(result).toEqual({ drained: 3, stored: MLS_KEY_PACKAGE_TARGET });
		// Publishing before draining would leave peers claiming stale packages
		// first, because the server hands out the oldest unconsumed one.
		expect(
			vi.mocked(claimKeyPackages).mock.invocationCallOrder[0],
		).toBeLessThan(vi.mocked(uploadKeyPackages).mock.invocationCallOrder[0]!);
		// The stale pool is gone server-side, not merely outnumbered.
		await expect(claimKeyPackages(client, SELF_ID, 1)).rejects.toThrow(
			"No key packages available",
		);
	});

	it("replaces the local pool rather than adding to it", async () => {
		saveAgentKeys(dir, SELF_ID, generateAgentKeys());
		const before = openMlsClient(dir, SELF_ID)
			.generateKeyPackages(4)
			.map(mlsToBase64);

		await drainAndRepublishMlsKeyPackages(dir, SELF_ID, client);

		expect(openMlsClient(dir, SELF_ID).keyPackageCount()).toBe(
			MLS_KEY_PACKAGE_TARGET,
		);
		expect(uploaded[0]).toHaveLength(MLS_KEY_PACKAGE_TARGET);
		expect(uploaded[0]!.some((p) => before.includes(p))).toBe(false);
	});

	it("pages through a pool larger than one claim request", async () => {
		saveAgentKeys(dir, SELF_ID, generateAgentKeys());
		serverPool(Array.from({ length: 150 }, (_, i) => `stale-${i}`));

		const result = await drainAndRepublishMlsKeyPackages(dir, SELF_ID, client);

		expect(result.drained).toBe(150);
		expect(vi.mocked(claimKeyPackages)).toHaveBeenCalledTimes(2);
	});

	it("propagates a claim failure that is not an empty pool", async () => {
		saveAgentKeys(dir, SELF_ID, generateAgentKeys());
		vi.mocked(claimKeyPackages).mockRejectedValue(
			new RineApiError(503, "upstream down"),
		);

		await expect(
			drainAndRepublishMlsKeyPackages(dir, SELF_ID, client),
		).rejects.toThrow("upstream down");
		// Nothing was published into a pool we failed to drain.
		expect(uploadKeyPackages).not.toHaveBeenCalled();
	});
});

// ── when it fires ────────────────────────────────────────────────────────────

describe("needsMlsKeyPackageCutover", () => {
	it("is false for an agent this core onboarded", () => {
		saveAgentKeys(dir, SELF_ID, generateAgentKeys());
		expect(needsMlsKeyPackageCutover(dir, SELF_ID)).toBe(false);
	});

	it("is true while a ts-mls-era store is present and uncut", () => {
		legacyAgent(SELF_ID);
		expect(needsMlsKeyPackageCutover(dir, SELF_ID)).toBe(true);
	});

	it("is false once the cutover has been recorded", async () => {
		legacyAgent(SELF_ID);
		await cutoverMlsKeyPackages(dir, SELF_ID, client);
		expect(needsMlsKeyPackageCutover(dir, SELF_ID)).toBe(false);
	});

	it("leaves the ts-mls-era key material on disk", async () => {
		legacyAgent(SELF_ID);
		await cutoverMlsKeyPackages(dir, SELF_ID, client);
		expect(fs.existsSync(join(dir, "keys", SELF_ID, "mls"))).toBe(true);
	});
});

describe("cutoverMlsKeyPackages", () => {
	it("does nothing for an agent that never ran ts-mls", async () => {
		saveAgentKeys(dir, SELF_ID, generateAgentKeys());
		expect(await cutoverMlsKeyPackages(dir, SELF_ID, client)).toBeNull();
		expect(uploadKeyPackages).not.toHaveBeenCalled();
	});

	it("is not recorded when the republish fails, so the next attempt retries", async () => {
		legacyAgent(SELF_ID);
		vi.mocked(uploadKeyPackages).mockRejectedValueOnce(
			new RineApiError(503, "upstream down"),
		);

		await expect(cutoverMlsKeyPackages(dir, SELF_ID, client)).rejects.toThrow(
			"upstream down",
		);
		expect(needsMlsKeyPackageCutover(dir, SELF_ID)).toBe(true);

		const retried = await cutoverMlsKeyPackages(dir, SELF_ID, client);
		expect(retried?.stored).toBe(MLS_KEY_PACKAGE_TARGET);
	});
});

describe("ensureMlsKeyPackages", () => {
	it("cuts a pre-cutover agent over instead of topping its stale pool up", async () => {
		legacyAgent(SELF_ID);
		serverPool(["stale-1", "stale-2"]);

		const status = await ensureMlsKeyPackages(dir, SELF_ID, client);

		expect(status.published).toBe(MLS_KEY_PACKAGE_TARGET);
		expect(claimKeyPackages).toHaveBeenCalled();
	});

	it("cuts over once, then behaves as ordinary low-water replenishment", async () => {
		legacyAgent(SELF_ID);
		await ensureMlsKeyPackages(dir, SELF_ID, client);
		vi.mocked(claimKeyPackages).mockClear();

		const second = await ensureMlsKeyPackages(dir, SELF_ID, client);

		expect(second).toEqual({
			available: MLS_KEY_PACKAGE_TARGET,
			published: 0,
			capReached: false,
		});
		expect(claimKeyPackages).not.toHaveBeenCalled();
		expect(uploaded).toHaveLength(1);
	});
});

// ── the framing the pool must carry ──────────────────────────────────────────

describe("the framing a replenished pool carries", () => {
	it("publishes key packages this core can actually add to a group", async () => {
		saveAgentKeys(dir, SELF_ID, generateAgentKeys());
		saveAgentKeys(dir, MEMBER_ID, generateAgentKeys());

		await ensureMlsKeyPackages(dir, MEMBER_ID, client);
		const published = uploaded[0]![0]!;

		const group = openMlsClient(dir, SELF_ID).createGroupWithMembers(
			mlsGroupIdBytes(GROUP_ID),
			[mlsFromBase64(published)],
		);
		expect(group.epoch()).toBeGreaterThan(0);
	});

	it("refuses a pre-cutover bare KeyPackage rather than accepting both framings", async () => {
		saveAgentKeys(dir, SELF_ID, generateAgentKeys());
		saveAgentKeys(dir, MEMBER_ID, generateAgentKeys());

		await ensureMlsKeyPackages(dir, MEMBER_ID, client);
		// ts-mls published the KeyPackage without its MLSMessage header
		// (version + wire_format), which is exactly these four leading bytes.
		const framed = mlsFromBase64(uploaded[0]![0]!);
		expect(Array.from(framed.slice(0, 4))).toEqual([0x00, 0x01, 0x00, 0x05]);
		const bare = framed.slice(4);

		try {
			openMlsClient(dir, SELF_ID).createGroupWithMembers(
				mlsGroupIdBytes(GROUP_ID),
				[bare],
			);
			expect.unreachable("a bare KeyPackage must not be accepted");
		} catch (err) {
			expect(mlsErrorCode(err)).toBe(MLS_ERR_UNREADABLE_KEY_PACKAGE);
		}
	});
});
