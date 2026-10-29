/**
 * The shared set-up of the pending-commit and self-update suites: agent A rotated its
 * key and holds a self-update commit it built but never posted, in a group the
 * founder R and the sibling B are in.
 */
import { ascii } from "../src/crypto/bytes.js";
import { loadAgentKeys } from "../src/crypto/keys.js";
import { allowedFor } from "../src/mls-allowed.js";
import { clientFor, hold, installHoldServer } from "./mls-hold-scene.js";
import {
	A,
	B,
	G1,
	R,
	found,
	groupOf,
	joinGroup,
	proc,
	rotate,
	scene,
	setUpRotationScene,
} from "./mls-rotation-scene.js";

/** The leaf-signing public key of `id`'s generation `gen`. */
export function leafKey(id: string, gen: number): Uint8Array {
	return scene.world.agents.get(id)!.find((g) => g.gen === gen)!.derived.mlsEd25519.publicKey;
}

/**
 * A fresh process on A's directory whose allowed set also holds A's
 * pre-rotation leaf: the tree still carries it, and a fresh process seeds the
 * set from the keys on disk, which are the rotated ones.
 */
export function rotatedDir(n: number): string {
	const dir = proc(scene.d1, n);
	allowedFor(dir, A).insert(ascii(A), leafKey(A, 0), 0);
	return dir;
}

/** A's actor in a fresh process after its rotation, whose allowed set also holds its old leaf. */
export function rotatedActor(n: number) {
	rotate(A, scene.d1);
	return { configDir: rotatedDir(n), agentId: A, client: clientFor(A) };
}

/** A's group in `dir` with a pending self-update commit, saved; returns its epoch. */
export function holdPendingUpdate(dir: string): number {
	const group = groupOf(dir, A, G1);
	group.commitUpdate(loadAgentKeys(dir, A).mls.privateKey);
	group.save();
	return group.epoch();
}

/** The scene with the founder R, A and B in `G1`, behind the hold server. */
export async function setUpHeldGroup(): Promise<void> {
	setUpRotationScene();
	installHoldServer();
	await found(scene.dr, R, G1, [A, B]);
	await joinGroup(scene.d1, A, G1);
	await joinGroup(scene.d1, B, G1);
	hold.posts = [];
}
