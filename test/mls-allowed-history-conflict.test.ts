/**
 * A history generation whose leaf key the allowed set already holds at another
 * generation, against the REAL native core.
 *
 * The set keeps the first pair it was given and raises a typed conflict for the
 * second. For a history generation that is a skip, so the peer's other valid
 * generations still land; for the current pair it is a real failure and must
 * surface.
 */
import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ascii } from "../src/crypto/bytes.js";
import { MLS_ERR_ALLOWED_GENERATION_CONFLICT, mlsErrorCode } from "../src/crypto/mls-errors.js";
import { admitPeers, allowedFor } from "../src/mls-allowed.js";
import { admitHistory } from "../src/mls-allowed-history.js";
import { World } from "./crypto/world.js";

const SELF_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

let dir: string;
let world: World;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-allowed-conflict-"));
	world = new World();
	world.save(dir, world.addAgent({ id: SELF_ID }));
});
afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

/** A peer with generations 0..2, and the leaf key of each. */
function rotatedPeer() {
	const id = randomUUID();
	const gens = [0, 1, 2].map((gen) => world.addAgent({ id, gen }));
	return { id, keys: gens.map((g) => g.derived.mlsEd25519.publicKey) };
}

describe("admitHistory", () => {
	it("test_admit_history_when_a_generation_key_is_held_at_another_generation_then_it_is_skipped_and_the_rest_land", async () => {
		const peer = rotatedPeer();
		const allowed = allowedFor(dir, SELF_ID);
		allowed.insert(ascii(peer.id), peer.keys[0]!, 7);
		const actor = { configDir: dir, agentId: SELF_ID, client: world.client() as never };

		await admitHistory(actor, allowed, peer.id, 3);

		expect(allowed.contains(ascii(peer.id), peer.keys[1]!)).toBe(true);
		expect(allowed.contains(ascii(peer.id), peer.keys[2]!)).toBe(true);
	});

	it("test_admit_history_when_the_insert_fails_for_any_other_reason_then_it_propagates", async () => {
		const peer = rotatedPeer();
		const allowed = allowedFor(dir, SELF_ID);
		const broken = {
			...allowed,
			insert: () => {
				throw new Error("store unreadable");
			},
		} as unknown as typeof allowed;
		const actor = { configDir: dir, agentId: SELF_ID, client: world.client() as never };

		await expect(admitHistory(actor, broken, peer.id, 3)).rejects.toThrow("store unreadable");
	});
});

describe("admitPeers", () => {
	it("test_admit_peers_when_the_current_pair_conflicts_then_the_conflict_is_thrown", async () => {
		const allowed = allowedFor(dir, SELF_ID);
		const peer = world.addAgent();
		world.save(dir, peer);
		allowed.insert(ascii(peer.id), peer.derived.mlsEd25519.publicKey, 9);
		const actor = { configDir: dir, agentId: SELF_ID, client: world.client() as never };

		const err = await admitPeers(actor, [peer.id]).catch((e: unknown) => e);

		expect(mlsErrorCode(err)).toBe(MLS_ERR_ALLOWED_GENERATION_CONFLICT);
	});
});
