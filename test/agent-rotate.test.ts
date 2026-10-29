/**
 * `performKeyRotation`: the key read it rotates from is chain-verified and checked
 * against what this host holds, so a server cannot steer the rotation with a
 * forged or rolled-back answer.
 */
import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { performKeyRotation } from "../src/agent-rotate.js";
import { KeyChainError, loadAgentKeys } from "../src/crypto/index.js";
import { saveRoot } from "../src/owner.js";
import { FIXTURE_ROOT } from "../src/testing.js";
import { World } from "./crypto/world.js";

let tmp: string;
let dirs: { configDir: string; ownerDir: string };

beforeEach(() => {
	tmp = fs.mkdtempSync(join(tmpdir(), "rine-rotate-"));
	dirs = { configDir: join(tmp, "config"), ownerDir: join(tmp, "owner") };
	fs.mkdirSync(dirs.configDir, { recursive: true });
	fs.mkdirSync(dirs.ownerDir, { recursive: true });
	saveRoot(dirs.ownerDir, FIXTURE_ROOT);
});

afterEach(() => {
	fs.rmSync(tmp, { recursive: true, force: true });
});

/** A client over `world` that records what the rotation POSTs. */
function rotationClient(world: World, agentId: string) {
	const posts: unknown[] = [];
	const served = world.client();
	return {
		posts,
		get: (path: string) => served.get(path),
		post: async (_path: string, body: unknown) => {
			posts.push(body);
			return { id: agentId, key_gen: 1 };
		},
	};
}

describe("performKeyRotation", () => {
	it("test_rotate_when_the_key_read_is_genuine_then_the_next_generation_is_posted_and_saved", async () => {
		const world = new World(FIXTURE_ROOT);
		const agent = world.addAgent({ gen: 3 });
		world.save(dirs.configDir, agent);
		const client = rotationClient(world, agent.id);

		await performKeyRotation(client, dirs, agent.id);

		expect(client.posts).toHaveLength(1);
		expect(client.posts[0]).toMatchObject({ key_gen: 4 });
		expect(loadAgentKeys(dirs.configDir, agent.id).keyGen).toBe(4);
	});

	it("test_rotate_when_the_key_read_has_a_broken_chain_then_nothing_is_posted", async () => {
		const world = new World(FIXTURE_ROOT);
		const agent = world.addAgent({ gen: 3 });
		world.save(dirs.configDir, agent);
		const forged = world.client((response) => ({
			...response,
			branch_certificate: response.agent_certificate,
		}));
		const client = { ...rotationClient(world, agent.id), get: forged.get };

		await expect(performKeyRotation(client, dirs, agent.id)).rejects.toThrow(
			KeyChainError,
		);

		expect(client.posts).toHaveLength(0);
		expect(loadAgentKeys(dirs.configDir, agent.id).keyGen).toBe(3);
	});

	it("test_rotate_when_the_server_reports_a_lower_generation_than_held_then_nothing_is_posted", async () => {
		const world = new World(FIXTURE_ROOT);
		const id = randomUUID();
		const held = world.addAgent({ id, gen: 3 });
		const stale = new World(FIXTURE_ROOT);
		stale.addAgent({ id, gen: 1 });
		world.save(dirs.configDir, held);
		const client = rotationClient(stale, id);

		await expect(performKeyRotation(client, dirs, id)).rejects.toMatchObject({
			fault: "key_gen_rollback",
		});

		expect(client.posts).toHaveLength(0);
	});

	it("test_rotate_when_the_key_read_belongs_to_another_org_then_nothing_is_posted", async () => {
		const foreign = new World();
		const agent = foreign.addAgent({ gen: 1 });
		const client = rotationClient(foreign, agent.id);

		await expect(performKeyRotation(client, dirs, agent.id)).rejects.toMatchObject({
			fault: "own_org_pin",
		});

		expect(client.posts).toHaveLength(0);
	});
});
