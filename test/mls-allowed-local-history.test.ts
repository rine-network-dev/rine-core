/**
 * A sibling agent on the same device accepts a rotated sibling's old leaf, against
 * the REAL native core.
 *
 * A rotation leaves the agent's leaf in every group under the key it was seated
 * with. A process that opened its allowed set before the rotation already holds
 * that key; a fresh process reads only the sibling's current pair from disk, so
 * it refused the old leaf in a Welcome (the group was dropped) and in a commit
 * (a NACK and a wedged member). The acting agent's own history stays out of its
 * set by default: a Welcome sealed to its superseded KeyPackage would install a
 * seat it could read from but never write to.
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

import { ascii } from "../src/crypto/bytes.js";
import { mlsNack, mlsToBase64 } from "../src/crypto/mls-api.js";
import { openMlsClient } from "../src/crypto/mls.js";
import { admitPeers, allowedFor } from "../src/mls-allowed.js";
import { addMlsGroupMember, processMlsWelcomes, syncMlsGroup } from "../src/mls-ops.js";
import {
	A,
	B,
	C,
	G1,
	G2,
	R,
	found,
	groupOf,
	joinGroup,
	proc,
	rotate,
	scene,
	setUpRotationScene,
	tearDownRotationScene,
} from "./mls-rotation-scene.js";

beforeEach(setUpRotationScene);
afterEach(tearDownRotationScene);

/** The leaf-signing public key of `id`'s generation `gen`. */
function leafKey(id: string, gen: number): Uint8Array {
	return scene.world.agents.get(id)!.find((g) => g.gen === gen)!.derived.mlsEd25519.publicKey;
}

describe("a sibling in a fresh process and a rotated sibling's old leaf", () => {
	it("test_sync_when_a_rotated_sibling_commits_then_a_fresh_sibling_applies_it_without_a_nack", async () => {
		await found(scene.dr, R, G1, [A, B]);
		await joinGroup(scene.d1, A, G1);
		await joinGroup(scene.d1, B, G1);
		rotate(A, scene.d1);
		scene.rosters.set(G1, [R, A, B, C]);
		await addMlsGroupMember(proc(scene.d1, 1), A, G1, C, scene.client);

		const result = await syncMlsGroup(proc(scene.d1, 2), B, G1, scene.client);

		expect(result).toMatchObject({ epoch: 2, processed: 1 });
		expect(mlsNack).not.toHaveBeenCalled();
	});

	it("test_welcome_when_a_rotated_sibling_is_in_the_tree_then_a_fresh_sibling_installs_the_group", async () => {
		await found(scene.dr, R, G2, [A]);
		await joinGroup(scene.d1, A, G2);
		rotate(A, scene.d1);
		scene.rosters.set(G2, [R, A, B]);
		await addMlsGroupMember(scene.dr, R, G2, B, scene.client);

		const result = await processMlsWelcomes(proc(scene.d1, 1), B, scene.client, { forGroup: G2 });

		expect(result).toMatchObject({ processed: 1, discarded: 0 });
		expect(groupOf(proc(scene.d1, 1), B, G2).epoch()).toBe(2);
	});

	it("test_welcome_when_sealed_to_the_actors_superseded_key_package_then_it_is_dropped_not_installed", async () => {
		scene.keyPackages.set(A, [mlsToBase64(openMlsClient(scene.d1, A).generateKeyPackage())]);
		await found(scene.dr, R, G2, [A]);
		rotate(A, scene.d1);

		const result = await processMlsWelcomes(proc(scene.d1, 1), A, scene.client, { forGroup: G2 });

		expect(result).toMatchObject({ processed: 0, discarded: 1 });
		expect(() => groupOf(proc(scene.d1, 1), A, G2)).toThrow();
	});
});

describe("admitPeers over agents that live on this device", () => {
	it("test_admit_peers_when_a_local_sibling_rotated_then_its_old_generation_is_admitted", async () => {
		rotate(A, scene.d1);
		const actor = { configDir: proc(scene.d1, 3), agentId: B, client: scene.client };

		await admitPeers(actor, [A]);

		const allowed = allowedFor(actor.configDir, B);
		expect(allowed.contains(ascii(A), leafKey(A, 0))).toBe(true);
		expect(allowed.contains(ascii(A), leafKey(A, 1))).toBe(true);
	});

	it("test_admit_peers_when_a_rotated_local_sibling_is_only_in_also_read_then_its_old_generation_is_admitted", async () => {
		rotate(A, scene.d1);
		const actor = { configDir: proc(scene.d1, 7), agentId: B, client: scene.client };

		await admitPeers(actor, [], { alsoRead: [A] });

		const allowed = allowedFor(actor.configDir, B);
		expect(allowed.contains(ascii(A), leafKey(A, 0))).toBe(true);
		expect(allowed.contains(ascii(A), leafKey(A, 1))).toBe(true);
	});

	it("test_admit_peers_when_the_actor_is_only_in_also_read_then_its_own_old_generation_is_not_admitted", async () => {
		rotate(A, scene.d1);
		const actor = { configDir: proc(scene.d1, 8), agentId: A, client: scene.client };

		await admitPeers(actor, [], { alsoRead: [A] });

		expect(allowedFor(actor.configDir, A).contains(ascii(A), leafKey(A, 0))).toBe(false);
	});

	it("test_admit_peers_when_the_actor_rotated_then_its_own_old_generation_is_not_admitted", async () => {
		rotate(A, scene.d1);
		const actor = { configDir: proc(scene.d1, 4), agentId: A, client: scene.client };

		await admitPeers(actor, [A]);

		const allowed = allowedFor(actor.configDir, A);
		expect(allowed.contains(ascii(A), leafKey(A, 0))).toBe(false);
		expect(allowed.contains(ascii(A), leafKey(A, 1))).toBe(true);
	});

	it("test_admit_peers_when_asked_for_the_actors_own_history_then_it_is_admitted", async () => {
		rotate(A, scene.d1);
		const actor = { configDir: proc(scene.d1, 5), agentId: A, client: scene.client };

		await admitPeers(actor, [A], { includeSelfHistory: true });

		expect(allowedFor(actor.configDir, A).contains(ascii(A), leafKey(A, 0))).toBe(true);
	});

	it("test_admit_peers_when_local_agents_never_rotated_then_no_history_is_read", async () => {
		const reads: string[] = [];
		const client = {
			...(scene.client as object),
			get: async (path: string, params?: Record<string, string>, headers?: unknown) => {
				reads.push(path);
				return (scene.client as { get: Function }).get(path, params, headers);
			},
		} as never;

		await admitPeers({ configDir: proc(scene.d1, 6), agentId: B, client }, [A, B]);

		expect(reads).toEqual([]);
	});
});
