/**
 * The chain-verified MLS allowed set, driven against the REAL native core.
 *
 * Only the network is faked: `World` mints real org/branch/agent certificates
 * and real agent keys on disk, so every entry that lands in the set was
 * verified by the same code the SDK runs. A test here fails when a peer is
 * admitted without a chain, when a rotated-away leaf is dropped, or when a
 * client opened earlier cannot see a peer admitted later.
 */
import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ascii } from "../src/crypto/bytes.js";
import type { HttpClient } from "../src/http.js";
import { admitPeers, allowedFor, openPeerMlsClient } from "../src/mls-allowed.js";
import { admitGroupPeers } from "../src/mls-allowed-tree.js";
import { type ResponseMutator, World } from "./crypto/world.js";
import { SELF_ID, peerClient as peerClientOf } from "./mls-allowed-world.js";

const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

let dir: string;
let world: World;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-mlsallowed-"));
	world = new World();
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

function peerClient(mutate?: ResponseMutator) {
	return peerClientOf(world, mutate);
}

/** The acting agent, with its own keys on disk as onboarding would leave them. */
function self(): string {
	world.save(dir, world.addAgent({ id: SELF_ID }));
	return SELF_ID;
}

describe("admitPeers", () => {
	it("test_admit_peers_when_agent_was_created_locally_after_first_use_inserts_its_key", async () => {
		const agentId = self();
		allowedFor(dir, agentId);
		const sibling = world.addAgent();
		world.save(dir, sibling);

		await admitPeers(
			{ configDir: dir, agentId, client: peerClient() },
			[sibling.id],
		);

		expect(
			allowedFor(dir, agentId).contains(
				ascii(sibling.id),
				sibling.derived.mlsEd25519.publicKey,
			),
		).toBe(true);
	});

	it("test_admit_peers_when_chain_valid_inserts_current_leaf_key", async () => {
		const agentId = self();
		const peer = world.addAgent();
		const client = peerClient();

		const inserted = await admitPeers(
			{ configDir: dir, agentId, client },
			[peer.id],
		);

		expect(inserted).toEqual([peer.id.toLowerCase()]);
		expect(
			allowedFor(dir, agentId).contains(
				ascii(peer.id),
				peer.derived.mlsEd25519.publicKey,
			),
		).toBe(true);
	});

	it("test_admit_peers_when_chain_invalid_skips_the_peer", async () => {
		const agentId = self();
		const peer = world.addAgent();
		const sibling = world.addAgent();
		const client = peerClient((response) => ({
			...response,
			agent_certificate: sibling.response.agent_certificate,
		}));

		const inserted = await admitPeers(
			{ configDir: dir, agentId, client },
			[peer.id],
		);

		expect(inserted).toEqual([]);
		expect(
			allowedFor(dir, agentId).contains(
				ascii(peer.id),
				peer.derived.mlsEd25519.publicKey,
			),
		).toBe(false);
	});

	it("test_admit_peers_when_peer_rotated_inserts_every_generation", async () => {
		const agentId = self();
		const id = randomUUID();
		const gen0 = world.addAgent({ id, gen: 0 });
		const gen1 = world.addAgent({ id, gen: 1 });
		const client = peerClient();

		await admitPeers({ configDir: dir, agentId, client }, [id]);

		const allowed = allowedFor(dir, agentId);
		expect(allowed.contains(ascii(id), gen1.derived.mlsEd25519.publicKey)).toBe(
			true,
		);
		expect(allowed.contains(ascii(id), gen0.derived.mlsEd25519.publicKey)).toBe(
			true,
		);
		expect(client.served).toContain(`/agents/${id}/keys?gen=0`);
	});

	it("skips an agent whose keys already live on this device", async () => {
		const agentId = self();
		const client = peerClient();

		const inserted = await admitPeers(
			{ configDir: dir, agentId, client },
			[agentId],
		);

		expect(inserted).toEqual([]);
		expect(client.served).toEqual([]);
	});
});

describe("allowedFor", () => {
	it("test_allowed_for_when_called_twice_returns_same_set", () => {
		const agentId = self();

		expect(allowedFor(dir, agentId)).toBe(allowedFor(dir, agentId));
	});
});

describe("admitGroupPeers", () => {
	it("test_admit_group_peers_reads_members_and_outstanding", async () => {
		const agentId = self();
		const member = world.addAgent();
		const invited = world.addAgent();
		const pending = world.addAgent();
		const base = peerClient();
		const client = {
			...base,
			get: async (
				path: string,
				params?: Record<string, string | number | boolean>,
			) => {
				if (path === `/groups/${GROUP_ID}/members`) {
					return { items: [{ agent_id: member.id }] };
				}
				if (path === `/groups/${GROUP_ID}/requests`) {
					return {
						items: [
							{ agent_id: invited.id, status: "invited", invited_by: member.id },
							{ agent_id: pending.id, status: "pending", invited_by: member.id },
						],
					};
				}
				return base.get(path, params);
			},
		} as unknown as HttpClient;

		await admitGroupPeers({ configDir: dir, agentId, client }, GROUP_ID);

		const allowed = allowedFor(dir, agentId);
		for (const peer of [member, invited, pending]) {
			expect(
				allowed.contains(ascii(peer.id), peer.derived.mlsEd25519.publicKey),
			).toBe(true);
		}
	});
});

describe("openPeerMlsClient", () => {
	it("test_open_peer_mls_client_when_peer_added_after_open_sees_it", async () => {
		const agentId = self();
		const peer = world.addAgent();
		const client = peerClient();

		openPeerMlsClient({ configDir: dir, agentId, client });
		await admitPeers({ configDir: dir, agentId, client }, [peer.id]);

		expect(
			allowedFor(dir, agentId).contains(
				ascii(peer.id),
				peer.derived.mlsEd25519.publicKey,
			),
		).toBe(true);
	});
});
