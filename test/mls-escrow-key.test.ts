import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentKeysResponse } from "../src/api-types.js";
import { issueBranchCert } from "../src/crypto/certs.js";
import {
	type BranchEscrowKeyResponse,
	BranchEscrowKeyError,
} from "../src/crypto/escrow-key.js";
import { toBase64Url } from "../src/crypto/keys.js";
import { RineApiError } from "../src/errors.js";
import {
	BranchRevokedError,
	ESCROW_KEY_REVOKED,
	dropEscrowKeys,
	resolveEscrowKey,
} from "../src/mls-escrow-key.js";
import { saveProfiles } from "../src/profiles.js";
import { World } from "./crypto/world.js";

const IAT = 1_700_000_000;
const AGENT_A = "11111111-1111-4111-8111-111111111111";
const AGENT_B = "22222222-2222-4222-8222-222222222222";

let tmp: string;
let configDir: string;

beforeEach(() => {
	tmp = fs.mkdtempSync(join(tmpdir(), "rine-escrow-key-"));
	configDir = join(tmp, "config");
	fs.mkdirSync(configDir, { recursive: true });
});

afterEach(() => {
	dropEscrowKeys();
	fs.rmSync(tmp, { recursive: true, force: true });
});

/** The `GET /orgs/me/branches/{name}/escrow-key` body for `branchName`. */
function escrowResponse(
	world: World,
	branchName: string,
): BranchEscrowKeyResponse {
	const branch = world.branch(branchName);
	return {
		org_id: world.org.orgId,
		org_signing_public_key: toBase64Url(world.org.ed25519.publicKey),
		org_pq_signing_public_key: toBase64Url(world.org.mlDsa65.publicKey),
		branch: branchName,
		branch_certificate: issueBranchCert(world.org, branch, IAT),
		escrow_public_key: toBase64Url(branch.escrowX25519.publicKey),
		escrow_pq_public_key: toBase64Url(branch.escrowMlKem768.publicKey),
	};
}

/** A fake client serving `GET /agents/{id}/keys` and the branch escrow key. */
function clientFor(world: World, escrow: () => BranchEscrowKeyResponse) {
	const get = vi.fn(async (path: string) => {
		const agentId = /^\/agents\/([^/]+)\/keys$/.exec(path)?.[1];
		if (agentId !== undefined) {
			return structuredClone(world.published(agentId)) as AgentKeysResponse;
		}
		if (path.startsWith("/orgs/me/branches/")) return escrow();
		throw new Error(`unexpected path ${path}`);
	});
	return { client: { get } as never, get };
}

/** A world with `AGENT_A` and `AGENT_B` on `main`, both saved into `configDir`. */
function worldWithAgents(): World {
	const world = new World(new Uint8Array(32).fill(7));
	for (const id of [AGENT_A, AGENT_B]) {
		world.save(configDir, world.addAgent({ id, branch: "main" }));
	}
	saveProfiles(configDir, {
		default: {
			org_id: world.org.orgId,
			principal: `agent:${AGENT_A}`,
			agent_id: AGENT_A,
			branch: "main",
		},
	});
	return world;
}

function agentKeyReads(get: ReturnType<typeof vi.fn>, agentId: string): number {
	return get.mock.calls.filter(
		([path]) => path === `/agents/${agentId}/keys`,
	).length;
}

describe("resolveEscrowKey", () => {
	it("test_resolveEscrowKey_when_chain_valid_then_returns_key_and_caches", async () => {
		const world = worldWithAgents();
		const { client, get } = clientFor(world, () => escrowResponse(world, "main"));

		const first = await resolveEscrowKey({
			configDir,
			agentId: AGENT_A,
			client,
		});
		expect(first.orgId).toBe(world.org.orgId);
		expect(first.branch).toBe("main");
		expect(first.x25519).toEqual(world.branch("main").escrowX25519.publicKey);
		expect(first.mlKem).toEqual(world.branch("main").escrowMlKem768.publicKey);

		const reads = get.mock.calls.length;
		const second = await resolveEscrowKey({
			configDir,
			agentId: AGENT_A,
			client,
		});
		expect(second).toEqual(first);
		expect(get.mock.calls.length).toBe(reads);
	});

	it("test_resolveEscrowKey_when_the_cache_window_has_passed_then_the_key_is_read_and_verified_again", async () => {
		// The cache binds `Date.now` when its module loads, so the module is
		// loaded again under the fake clock.
		vi.useFakeTimers();
		vi.resetModules();
		try {
			const { resolveEscrowKey } = await import("../src/mls-escrow-key.js");
			const world = worldWithAgents();
			const { client, get } = clientFor(world, () => escrowResponse(world, "main"));
			const actor = { configDir, agentId: AGENT_A, client };
			await resolveEscrowKey(actor);
			const reads = get.mock.calls.length;

			vi.advanceTimersByTime(599_000);
			await resolveEscrowKey(actor);
			expect(get.mock.calls.length).toBe(reads);

			vi.advanceTimersByTime(2_000);
			await resolveEscrowKey(actor);
			expect(get.mock.calls.length).toBeGreaterThan(reads);
		} finally {
			vi.useRealTimers();
		}
	});

	it("test_resolveEscrowKey_when_410_then_throws_branch_revoked_and_drops_cache", async () => {
		const world = worldWithAgents();
		let revoked = false;
		const { client, get } = clientFor(world, () => {
			if (revoked) throw new RineApiError(410, ESCROW_KEY_REVOKED);
			return escrowResponse(world, "main");
		});

		await resolveEscrowKey({ configDir, agentId: AGENT_A, client });
		expect(agentKeyReads(get, AGENT_A)).toBe(1);

		revoked = true;
		await expect(
			resolveEscrowKey({ configDir, agentId: AGENT_B, client }),
		).rejects.toBeInstanceOf(BranchRevokedError);
		await expect(
			resolveEscrowKey({ configDir, agentId: AGENT_B, client }),
		).rejects.toThrow(ESCROW_KEY_REVOKED);

		// The 410 dropped AGENT_A's cached entry too: its next read hits the wire.
		await expect(
			resolveEscrowKey({ configDir, agentId: AGENT_A, client }),
		).rejects.toBeInstanceOf(BranchRevokedError);
		expect(agentKeyReads(get, AGENT_A)).toBe(2);
	});

	it("test_resolveEscrowKey_when_key_substituted_then_throws_invalid_and_caches_nothing", async () => {
		const world = worldWithAgents();
		const { client, get } = clientFor(world, () =>
			escrowResponse(world, "fleet"),
		);

		await expect(
			resolveEscrowKey({ configDir, agentId: AGENT_A, client }),
		).rejects.toBeInstanceOf(BranchEscrowKeyError);
		await expect(
			resolveEscrowKey({ configDir, agentId: AGENT_A, client }),
		).rejects.toThrow("branch escrow key invalid");
		expect(agentKeyReads(get, AGENT_A)).toBe(2);
	});

	it("test_resolveEscrowKey_when_wrong_org_then_throws_invalid_and_caches_nothing", async () => {
		const world = worldWithAgents();
		const foreign = new World(new Uint8Array(32).fill(9));
		const { client, get } = clientFor(world, () => ({
			...escrowResponse(world, "main"),
			org_id: foreign.org.orgId,
			org_signing_public_key: toBase64Url(foreign.org.ed25519.publicKey),
			org_pq_signing_public_key: toBase64Url(foreign.org.mlDsa65.publicKey),
		}));

		await expect(
			resolveEscrowKey({ configDir, agentId: AGENT_A, client }),
		).rejects.toBeInstanceOf(BranchEscrowKeyError);
		expect(agentKeyReads(get, AGENT_A)).toBe(1);
	});

	it("test_resolveEscrowKey_when_no_org_id_then_throws", async () => {
		const world = new World(new Uint8Array(32).fill(7));
		world.save(configDir, world.addAgent({ id: AGENT_A, branch: "main" }));
		const { client } = clientFor(world, () => escrowResponse(world, "main"));

		await expect(
			resolveEscrowKey({ configDir, agentId: AGENT_A, client }),
		).rejects.toThrow(
			`no own org id for agent ${AGENT_A}: cannot verify the branch escrow key`,
		);
	});
});
