/**
 * Devices, agents and a stand-in server for the tests that drive the REAL native
 * core through a key rotation.
 *
 * Device `d1` holds the siblings A and B, `dr` holds a remote founder R and `dc`
 * a remote joiner C. A rotation is what the rotate flow writes: a new generation
 * of the agent's keys saved into the device directory, which the server then
 * publishes. "A fresh process" is the same directory under a different string,
 * because the process-wide allowed set is keyed by the config dir string while
 * every path is normalised. The calling test file mocks `crypto/mls-api.js` and
 * `mls-escrow-key.js`; this module drives those mocks.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { vi } from "vitest";
import { mlsInit } from "../src/crypto/mls-api.js";
import { mlsGroupIdBytes } from "../src/crypto/mls.js";
import { openPeerMlsClient } from "../src/mls-allowed.js";
import { initMlsGroup, processMlsWelcomes } from "../src/mls-ops.js";
import { World } from "./crypto/world.js";
import { installServer, serverClient } from "./mls-rotation-server.js";
import { A, B, C, R, deviceOf, scene } from "./mls-rotation-state.js";

export { A, B, C, G1, G2, R, scene } from "./mls-rotation-state.js";
export type { RotationScene } from "./mls-rotation-state.js";

/** A fresh process on the same directory: a new allowed-set key, the same files. */
export function proc(dir: string, n: number): string {
	return dir + "/.".repeat(n);
}

/** Publish the next generation of `id` and write its keys into `dir`. */
export function rotate(id: string, dir: string): void {
	const next = Math.max(...scene.world.agents.get(id)!.map((g) => g.gen)) + 1;
	scene.world.save(dir, scene.world.addAgent({ id, gen: next }));
}

export function groupOf(dir: string, id: string, groupId: string) {
	return openPeerMlsClient({ configDir: dir, agentId: id, client: scene.client }).loadGroup(
		mlsGroupIdBytes(groupId),
	);
}

/** The ids at the group's leaves as `dir`'s agent `id` sees them, sorted. */
export function treeIds(dir: string, id: string, groupId: string): string[] {
	return groupOf(dir, id, groupId)
		.memberIdentities()
		.map((m: { identity: Uint8Array }) => new TextDecoder().decode(m.identity))
		.sort();
}

export async function found(dir: string, founder: string, groupId: string, members: string[]): Promise<void> {
	scene.rosters.set(groupId, [founder, ...members]);
	vi.mocked(mlsInit).mockResolvedValueOnce({
		mls_pending: true,
		members: [founder, ...members].map((agent_id) => ({ agent_id, has_key_package: true })),
	});
	await initMlsGroup(dir, founder, groupId, scene.client);
}

export async function joinGroup(dir: string, id: string, groupId: string) {
	const result = await processMlsWelcomes(dir, id, scene.client, { forGroup: groupId });
	scene.welcomes.set(id, []);
	return result;
}

export function send(dir: string, id: string, groupId: string, text: string): Uint8Array {
	const group = groupOf(dir, id, groupId);
	const sealed = group.encryptApplicationMessage(new TextEncoder().encode(text));
	group.save();
	return sealed;
}

export function read(dir: string, id: string, groupId: string, sealed: Uint8Array): string {
	const group = groupOf(dir, id, groupId);
	const text = new TextDecoder().decode(group.decryptApplicationMessage(sealed).envelope);
	group.save();
	return text;
}

/** Four agents on three devices, none of them in a group yet. */
export function setUpRotationScene(): void {
	scene.root = fs.mkdtempSync(join(tmpdir(), "rine-rotation-scene-"));
	[scene.d1, scene.dr, scene.dc] = ["d1", "dr", "dc"].map((name) => {
		const dir = join(scene.root, name);
		fs.mkdirSync(dir);
		return dir;
	}) as [string, string, string];
	scene.world = new World();
	scene.rosters = new Map();
	scene.posted = new Map();
	scene.welcomes = new Map();
	scene.keyPackages = new Map();
	scene.omitted = new Set();
	vi.clearAllMocks();
	installServer();
	for (const [id, dir] of [[A, scene.d1], [B, scene.d1], [R, scene.dr], [C, scene.dc]] as const) {
		scene.world.save(dir, scene.world.addAgent({ id }));
		deviceOf.set(id, dir);
	}
	scene.client = serverClient() as never;
}

export function tearDownRotationScene(): void {
	fs.rmSync(scene.root, { recursive: true, force: true });
}
