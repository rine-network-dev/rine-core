/**
 * `admitPeers` and the agents whose keys already live on this device: an agent in
 * `alsoRead` that this device holds is never given a key the server serves for it.
 * Driven against the real native core, as `mls-allowed.test.ts` is.
 */

import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ascii } from "../src/crypto/bytes.js";
import { admitPeers, allowedFor } from "../src/mls-allowed.js";
import { World } from "./crypto/world.js";
import { SELF_ID, peerClient } from "./mls-allowed-world.js";

let dir: string;
let world: World;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-mlsallowed-alsoread-"));
	world = new World();
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("admitPeers alsoRead", () => {
	it("test_admit_peers_when_a_local_sibling_is_in_also_read_then_a_differing_served_key_is_not_inserted", async () => {
		world.save(dir, world.addAgent({ id: SELF_ID }));
		const agentId = SELF_ID;
		const siblingId = randomUUID();
		const onDisk = world.addAgent({ id: siblingId, gen: 0 });
		world.save(dir, onDisk);
		const servedOnly = world.addAgent({ id: siblingId, gen: 1 });
		const client = peerClient(world);

		const served = await admitPeers({ configDir: dir, agentId, client }, [], {
			alsoRead: [siblingId],
		});

		const allowed = allowedFor(dir, agentId);
		expect(served).toEqual([siblingId]);
		expect(
			allowed.contains(ascii(siblingId), onDisk.derived.mlsEd25519.publicKey),
		).toBe(true);
		expect(
			allowed.contains(
				ascii(siblingId),
				servedOnly.derived.mlsEd25519.publicKey,
			),
		).toBe(false);
	});
});
