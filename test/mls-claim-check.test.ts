/**
 * The claim check that keeps a stale KeyPackage out of a Welcome, against the
 * REAL native core.
 *
 * A claim hands back whatever the server holds, including a package minted under
 * a key generation a rotation has since superseded. Seating one would put a leaf
 * in the tree under a key the agent no longer holds, so the Welcome it receives
 * is one it can never open. The check compares the claimed package's leaf
 * signature key against the agent's chain-verified published key and drops the
 * package when they differ.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-escrow-key.js", async () =>
	(await import("./mls-escrow-harness.js")).escrowKeyModule(),
);

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<typeof import("../src/crypto/mls-api.js")>(
		"../src/crypto/mls-api.js",
	);
	return {
		...actual,
		uploadKeyPackages: vi.fn(async (_c: unknown, _a: unknown, p: string[]) => ({ stored: p.length })),
		claimKeyPackages: vi.fn(),
		claimKeyPackagesBatch: vi.fn(),
		mlsInit: vi.fn(),
		mlsCommit: vi.fn(),
		mlsAck: vi.fn(),
		mlsNack: vi.fn(),
		fetchHandshakes: vi.fn(),
		fetchWelcomes: vi.fn(),
		fetchGroupInfo: vi.fn(),
	};
});

import { claimKeyPackagesBatch, mlsToBase64 } from "../src/crypto/mls-api.js";
import { openMlsClient } from "../src/crypto/mls.js";
import { addMlsGroupMember, addMlsGroupMembers } from "../src/mls-ops.js";
import {
	A,
	B,
	G1,
	R,
	found,
	joinGroup,
	rotate,
	scene,
	setUpRotationScene,
	tearDownRotationScene,
} from "./mls-rotation-scene.js";

beforeEach(setUpRotationScene);
afterEach(tearDownRotationScene);

/** A package for `id` minted now, under whatever generation its device holds. */
function mintedNow(id: string, dir: string): string {
	return mlsToBase64(openMlsClient(dir, id).generateKeyPackage());
}

/** The Welcomes the server queued for `id`. */
function welcomesFor(id: string) {
	return scene.welcomes.get(id.toLowerCase()) ?? [];
}

/** A client that records every path it is asked for, over the scene's server. */
function countingClient(): { client: never; reads: string[] } {
	const reads: string[] = [];
	const base = scene.client as { get: (...a: unknown[]) => Promise<unknown> };
	const client = {
		...(scene.client as object),
		get: async (path: string, ...rest: unknown[]) => {
			reads.push(path);
			return base.get(path, ...rest);
		},
	} as never;
	return { client, reads };
}

describe("claiming a KeyPackage for a rotated agent", () => {
	beforeEach(async () => {
		await found(scene.dr, R, G1, [A]);
		await joinGroup(scene.d1, A, G1);
		// The admitter chain-verifies the group's members before it builds a
		// commit, so the member it is about to seat must be on the roster.
		scene.rosters.set(G1, [R, A, B]);
	});

	it("test_claim_when_package_minted_under_current_generation_then_member_admitted", async () => {
		rotate(B, scene.d1);

		const result = await addMlsGroupMembers(scene.dr, R, G1, [B], scene.client);

		expect(result.outcomes).toEqual([{ agentId: B, status: "added" }]);
		expect(welcomesFor(B)).toHaveLength(1);
	});

	it("test_claim_when_package_minted_before_rotation_then_skipped_not_current", async () => {
		scene.keyPackages.set(B, [mintedNow(B, scene.d1)]);
		rotate(B, scene.d1);
		const postedBefore = scene.posted.get(G1)?.length ?? 0;

		const result = await addMlsGroupMembers(scene.dr, R, G1, [B], scene.client);

		expect(result.outcomes).toEqual([
			{ agentId: B, status: "skipped", reason: "key_package_not_current" },
		]);
		expect(welcomesFor(B)).toHaveLength(0);
		expect(scene.posted.get(G1)?.length ?? 0).toBe(postedBefore);
	});

	it("test_claim_when_member_keys_absent_from_the_server_then_skipped_not_current", async () => {
		rotate(B, scene.d1);
		scene.omitted.add(B);

		const result = await addMlsGroupMembers(scene.dr, R, G1, [B], scene.client);

		expect(result.outcomes).toEqual([
			{ agentId: B, status: "skipped", reason: "key_package_not_current" },
		]);
		expect(welcomesFor(B)).toHaveLength(0);
	});

	it("test_add_single_member_when_package_not_current_then_error_names_the_member", async () => {
		scene.keyPackages.set(B, [mintedNow(B, scene.d1)]);
		rotate(B, scene.d1);

		const err = await addMlsGroupMember(scene.dr, R, G1, B, scene.client).catch(
			(e: unknown) => e,
		);

		expect(err).toBeInstanceOf(Error);
		expect((err as Error).message).toContain("minted under an earlier key generation");
		expect((err as Error).message).toContain(B);
	});
});

describe("claiming a batch with one stale member", () => {
	it("test_claim_when_one_of_two_is_stale_then_other_still_admitted", async () => {
		await found(scene.dr, R, G1, []);
		scene.rosters.set(G1, [R, A, B]);
		scene.keyPackages.set(B, [mintedNow(B, scene.d1)]);
		rotate(B, scene.d1);

		const result = await addMlsGroupMembers(scene.dr, R, G1, [A, B], scene.client);

		expect(result.outcomes).toEqual([
			{ agentId: A, status: "added" },
			{ agentId: B, status: "skipped", reason: "key_package_not_current" },
		]);
		expect(welcomesFor(A)).toHaveLength(1);
		expect(welcomesFor(B)).toHaveLength(0);
	});
});

describe("a batch whose pools are all empty", () => {
	it("test_claim_when_nobody_claimed_then_no_key_read", async () => {
		await found(scene.dr, R, G1, [A]);
		await joinGroup(scene.d1, A, G1);
		scene.rosters.set(G1, [R, A, B]);
		const { client, reads } = countingClient();
		// The claim check's own read is the one made AFTER the claim returns, so
		// the count is taken at the claim and compared with the count at the end.
		let readsAtClaim = -1;
		vi.mocked(claimKeyPackagesBatch).mockImplementation(async (_c, ids: string[]) => {
			readsAtClaim = reads.length;
			return { claims: ids.map((agent_id) => ({ agent_id, packages: [] })) };
		});

		await addMlsGroupMembers(scene.dr, R, G1, [B], client);

		expect(readsAtClaim).toBeGreaterThanOrEqual(0);
		expect(reads.length).toBe(readsAtClaim);
	});
});
