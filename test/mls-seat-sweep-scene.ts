/**
 * The shared set-up of the seat-sweep suites: agent A rotated its key on device
 * `d1`, which holds A and its sibling B in G1; A is also in G2, for which `d1`
 * holds no state. Only the network is faked, by the rotation scene's stand-in server.
 */
import { vi } from "vitest";
import { claimKeyPackages, claimKeyPackagesBatch, uploadKeyPackages } from "../src/crypto/mls-api.js";
// The settlement re-seats through the slot mls-self-update.js fills when it loads.
import "../src/mls-self-update.js";
import { clientFor, hold, installHoldServer } from "./mls-hold-scene.js";
import { rotatedDir } from "./mls-pending-commit-scene.js";
import {
	A,
	B,
	G1,
	G2,
	R,
	found,
	joinGroup,
	rotate,
	scene,
	setUpRotationScene,
} from "./mls-rotation-scene.js";

const MLS_ROW = (id: string) => ({ id, mls_group_id: id, member_agent_ids: [A, B, R] });

/** Every GET the sweep client made, by path. */
export const reads: string[] = [];

/** A's client: the scene's, plus the group list the sweep reads. */
export function sweepClient() {
	const base = clientFor(A) as unknown as {
		get: (path: string, ...rest: unknown[]) => Promise<unknown>;
	};
	return {
		...base,
		get: async (path: string, ...rest: unknown[]) => {
			reads.push(path);
			return path === "/groups" ? { items: [MLS_ROW(G1), MLS_ROW(G2)] } : base.get(path, ...rest);
		},
	} as never;
}

/** A's actor in a fresh process after generation 1 reached the disk. */
export function sweptActor(n: number) {
	rotate(A, scene.d1);
	return { configDir: rotatedDir(n), agentId: A, client: sweepClient() };
}

export async function setUpSweepScene(): Promise<void> {
	setUpRotationScene();
	installHoldServer();
	await found(scene.dr, R, G1, [A, B]);
	await joinGroup(scene.d1, A, G1);
	await joinGroup(scene.d1, B, G1);
	await found(scene.dr, R, G2, [A]);
	hold.posts = [];
	reads.length = 0;
	vi.mocked(uploadKeyPackages).mockClear();
	vi.mocked(claimKeyPackages).mockClear();
	vi.mocked(claimKeyPackagesBatch).mockClear();
}
