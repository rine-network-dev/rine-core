/**
 * Founding a group at the 500-member ceiling: how big each commit may be, and
 * how the KeyPackages for it are claimed.
 *
 * The budget assertions price each planned commit from coefficients MEASURED on
 * a full-size tree rather than from the estimator under test, so a change that
 * quietly re-fits the model is caught here instead of agreeing with itself.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/crypto/mls-api.js")
	>("../src/crypto/mls-api.js");
	return {
		...actual,
		claimKeyPackagesBatch: vi.fn(async () => ({ claims: [] })),
	};
});

import { claimKeyPackagesBatch } from "../src/crypto/mls-api.js";
import {
	MLS_CLAIM_AGENTS_MAX,
	MLS_FOUNDING_POST_BUDGET_B64,
	claimFoundingKeyPackages,
	mlsFoundingBatchSizes,
} from "../src/mls-founding.js";

/** The group-size ceiling — `MAX_GROUP_MEMBERS` in `rine/core/group_limits.py`. */
const MAX_GROUP_MEMBERS = 500;

/** Welcome entries one commit may carry — `MLS_WELCOMES_PER_COMMIT_MAX`. */
const SERVER_WELCOMES_PER_COMMIT_MAX = 32;

const client = {} as never;

beforeEach(() => {
	vi.clearAllMocks();
});

/**
 * What a commit admitting `batch` members into a tree of `seated` really weighs,
 * in base64 bytes, on the default post-quantum suite.
 *
 * MEASURED: a Welcome is 198,452 B at N=100 and 1,866,664 B at N=1000, i.e.
 * 1,853.6 B per member over a 13,092 B base; the commit's UpdatePath plus the
 * republished GroupInfo weigh a further 1.85 Welcomes at every measured size.
 */
function measuredPostB64(seated: number, batch: number): number {
	return Math.round((1853.6 * seated + 13_092) * (batch + 1.85));
}

/** Each planned commit as `[treeSizeAfterIt, batch]`, founder included. */
function plannedCommits(joinerCount: number): [number, number][] {
	let seated = 1;
	return mlsFoundingBatchSizes(joinerCount).map((batch) => {
		seated += batch;
		return [seated, batch];
	});
}

describe("mlsFoundingBatchSizes", () => {
	it("keeps every commit of a ceiling-sized founding inside the post budget", () => {
		for (const [seated, batch] of plannedCommits(MAX_GROUP_MEMBERS - 1)) {
			expect(measuredPostB64(seated, batch)).toBeLessThanOrEqual(
				MLS_FOUNDING_POST_BUDGET_B64,
			);
		}
	});

	it("seats every member of a ceiling-sized group", () => {
		const sizes = mlsFoundingBatchSizes(MAX_GROUP_MEMBERS - 1);
		expect(sizes.reduce((a, b) => a + b, 0)).toBe(MAX_GROUP_MEMBERS - 1);
		expect(sizes.every((size) => size >= 1)).toBe(true);
	});

	it("never asks the server for more welcomes than one commit accepts", () => {
		for (const size of mlsFoundingBatchSizes(MAX_GROUP_MEMBERS - 1)) {
			expect(size).toBeLessThanOrEqual(SERVER_WELCOMES_PER_COMMIT_MAX);
		}
	});

	it("shrinks the batch as the tree grows, because a Welcome carries the tree", () => {
		const sizes = mlsFoundingBatchSizes(MAX_GROUP_MEMBERS - 1);
		expect(sizes[0]).toBe(SERVER_WELCOMES_PER_COMMIT_MAX);
		expect(sizes[sizes.length - 1]).toBeLessThan(
			SERVER_WELCOMES_PER_COMMIT_MAX,
		);
		// Why it has to shrink: keeping the server's full 32-member batch all the
		// way to the ceiling would put a 31 MB body in the last commit.
		expect(
			measuredPostB64(MAX_GROUP_MEMBERS, SERVER_WELCOMES_PER_COMMIT_MAX),
		).toBeGreaterThan(MLS_FOUNDING_POST_BUDGET_B64);
	});

	it("founds a small group in one commit", () => {
		expect(mlsFoundingBatchSizes(0)).toEqual([]);
		expect(mlsFoundingBatchSizes(5)).toEqual([5]);
		expect(mlsFoundingBatchSizes(SERVER_WELCOMES_PER_COMMIT_MAX)).toEqual([
			SERVER_WELCOMES_PER_COMMIT_MAX,
		]);
	});

	it("spills into a second commit past the server's welcome cap", () => {
		expect(mlsFoundingBatchSizes(SERVER_WELCOMES_PER_COMMIT_MAX + 8)).toEqual([
			SERVER_WELCOMES_PER_COMMIT_MAX,
			8,
		]);
	});

	it("plans a ceiling-sized founding in 39 commits, unchanged by the seated parameter", () => {
		const sizes = mlsFoundingBatchSizes(MAX_GROUP_MEMBERS - 1);
		expect(sizes).toHaveLength(39);
		expect(sizes[0]).toBe(SERVER_WELCOMES_PER_COMMIT_MAX);
		expect(sizes).toEqual(mlsFoundingBatchSizes(MAX_GROUP_MEMBERS - 1, 1));
	});

	it("keeps a later admission inside the budget too, at the tree it joins", () => {
		// 100 members added to a group that already holds 400 — the case
		// founding never reaches and batched adds do.
		let seated = 400;
		const sizes = mlsFoundingBatchSizes(100, seated);
		expect(sizes.reduce((a, b) => a + b, 0)).toBe(100);
		for (const batch of sizes) {
			seated += batch;
			expect(measuredPostB64(seated, batch)).toBeLessThanOrEqual(
				MLS_FOUNDING_POST_BUDGET_B64,
			);
		}
	});

	it("shrinks the batch as the tree it is joining grows", () => {
		const early = mlsFoundingBatchSizes(100, 1)[0]!;
		const late = mlsFoundingBatchSizes(100, 400)[0]!;
		expect(late).toBeLessThan(early);
		expect(late).toBeGreaterThanOrEqual(1);
	});
});

describe("claimFoundingKeyPackages", () => {
	/** `count` agent ids, each carrying one claimable package. */
	function agents(count: number): string[] {
		return Array.from({ length: count }, (_, i) => `agent-${i}`);
	}

	function claimEverythingAsked(): void {
		vi.mocked(claimKeyPackagesBatch).mockImplementation(
			async (_client, agentIds) => ({
				claims: agentIds.map((agent_id) => ({
					agent_id,
					packages: [`pkg-${agent_id}`],
				})),
			}),
		);
	}

	/** The id lists the client actually sent, one per request. */
	function requestedIds(): string[][] {
		return vi.mocked(claimKeyPackagesBatch).mock.calls.map((call) => call[1]);
	}

	it("asks once when the roster is exactly the per-request id cap", async () => {
		claimEverythingAsked();
		const claimed = await claimFoundingKeyPackages(
			client,
			agents(MLS_CLAIM_AGENTS_MAX),
		);

		expect(requestedIds()).toHaveLength(1);
		expect(requestedIds()[0]).toHaveLength(MLS_CLAIM_AGENTS_MAX);
		expect(claimed.size).toBe(MLS_CLAIM_AGENTS_MAX);
	});

	it("splits the one id past the cap into a second request", async () => {
		claimEverythingAsked();
		const roster = agents(MLS_CLAIM_AGENTS_MAX + 1);
		const claimed = await claimFoundingKeyPackages(client, roster);

		expect(requestedIds().map((ids) => ids.length)).toEqual([
			MLS_CLAIM_AGENTS_MAX,
			1,
		]);
		expect(requestedIds().flat()).toEqual(roster);
		expect(claimed.size).toBe(MLS_CLAIM_AGENTS_MAX + 1);
	});

	it("chunks a ceiling-sized roster without dropping or repeating an id", async () => {
		claimEverythingAsked();
		const roster = agents(MAX_GROUP_MEMBERS - 1);
		await claimFoundingKeyPackages(client, roster);

		expect(requestedIds().flat()).toEqual(roster);
		for (const ids of requestedIds()) {
			expect(ids.length).toBeLessThanOrEqual(MLS_CLAIM_AGENTS_MAX);
		}
	});

	it("leaves out an agent with no package available, and keeps the rest", async () => {
		vi.mocked(claimKeyPackagesBatch).mockResolvedValue({
			claims: [
				{ agent_id: "has-one", packages: ["pkg"] },
				{ agent_id: "pool-empty", packages: [] },
			],
		});

		const claimed = await claimFoundingKeyPackages(client, [
			"has-one",
			"pool-empty",
		]);

		expect(claimed.get("has-one")).toBe("pkg");
		expect(claimed.has("pool-empty")).toBe(false);
	});

	it("finds a claim whatever case the caller holds the agent id in", async () => {
		vi.mocked(claimKeyPackagesBatch).mockResolvedValue({
			claims: [{ agent_id: "AB-CD", packages: ["pkg"] }],
		});

		const claimed = await claimFoundingKeyPackages(client, ["AB-CD"]);
		expect(claimed.get("ab-cd")).toBe("pkg");
	});

	it("sends no request at all for an empty roster", async () => {
		const claimed = await claimFoundingKeyPackages(client, []);

		expect(claimed.size).toBe(0);
		expect(claimKeyPackagesBatch).not.toHaveBeenCalled();
	});
});
