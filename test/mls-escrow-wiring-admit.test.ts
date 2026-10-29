/**
 * The escrow drain and the peer admission, wired into the admission path, driven
 * against the REAL native core.
 *
 * Only the network and the branch escrow key read are faked (see
 * `mls-escrow-harness.ts`): every commit, Welcome and ratchet-tree fact is
 * genuine, so a test here fails when an accepted commit uploads no escrow, when
 * a REJECTED one leaves a pending file behind, or when a
 * KeyPackage whose leaf key is not the chain-verified one is admitted anyway.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-escrow-key.js", async () =>
	(await import("./mls-escrow-harness.js")).escrowKeyModule(),
);

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/crypto/mls-api.js")
	>("../src/crypto/mls-api.js");
	return {
		...actual,
		uploadKeyPackages: vi.fn(async (_c: unknown, _a: unknown, p: string[]) => ({
			stored: p.length,
		})),
		claimKeyPackages: vi.fn(async () => ({ packages: [], agent_id: "" })),
		claimKeyPackagesBatch: vi.fn(async () => ({ claims: [] })),
		mlsFromBase64: vi.fn(actual.mlsFromBase64),
		mlsInit: vi.fn(async () => ({ mls_pending: true, members: [] })),
		mlsCommit: vi.fn(async () => ({ epoch: null, delivered_to: 1 })),
		mlsAck: vi.fn(async () => ({ confirmed: true, acks: 1, needed: 1 })),
		mlsNack: vi.fn(async () => ({ quarantined: true })),
		fetchHandshakes: vi.fn(async () => ({ handshakes: [] })),
		fetchWelcomes: vi.fn(async () => ({ welcomes: [] })),
		fetchGroupInfo: vi.fn(async () => ({ group_info: null, epoch: null })),
	};
});

import { World } from "./crypto/world.js";
import { type PeerReads, withPeerReads } from "./mls-escrow-harness.js";
import { saveAgentKeys } from "../src/crypto/keys.js";
import { generateAgentKeys } from "./helpers/keys.js";
import {
	claimKeyPackagesBatch,
	mlsCommit,
	mlsInit,
	mlsToBase64,
} from "../src/crypto/mls-api.js";
import type { MlsCommitBody } from "../src/crypto/mls-api.js";
import {
	mlsGroupIdBytes,
	openMlsClient,
	openMlsGroup,
} from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import { listPending } from "../src/mls-escrow-pending.js";
import { addMlsGroupMembers, initMlsGroup } from "../src/mls-ops.js";

const SELF_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const MEMBER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const THIRD_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

let dir: string;
let world: World;
/** Every commit body the code posted, in order. */
let posted: MlsCommitBody[];
let client: never;
/** Config dirs holding a "foreign device"'s keys, removed after each test. */
const foreignDirs: string[] = [];

/**
 * The reads the admission path makes outside `crypto/mls-api.js` and outside the
 * harness: the group's size and its outstanding vouchers. The roster and the
 * published keys come from the world, so every peer admitted here carries a
 * chain the batch consumers verify.
 */
const fakeClient = {
	get: async (path: string) => {
		if (path === `/groups/${GROUP_ID}`) return { member_count: 1 };
		if (path === `/groups/${GROUP_ID}/requests`) return { items: [] };
		throw new Error(`unexpected GET ${path}`);
	},
};

/** The escrow uploads the client received, as `[path, body]`. */
function puts(): [string, unknown][] {
	return (client as unknown as PeerReads).puts;
}

/** An agent whose keys live on this device, as onboarding would leave them. */
function agent(agentId: string): void {
	world.save(dir, world.addAgent({ id: agentId }));
}

/** One claimable KeyPackage for `agentId`, minted by that agent's own client. */
function offerKeyPackage(agentId: string): void {
	const pkg = mlsToBase64(openMlsClient(dir, agentId).generateKeyPackage());
	vi.mocked(claimKeyPackagesBatch).mockResolvedValue({
		claims: [{ agent_id: agentId, packages: [pkg] }],
	});
}

/**
 * A KeyPackage for `agentId` minted on a DIFFERENT device, under a leaf key the
 * server's chain for that agent never certified.
 *
 * The agent's own keys are deliberately absent from `dir`: were they present,
 * `admitPeers` would insert the on-disk pair without a chain check and the
 * KeyPackage would be admitted on its own say-so.
 */
function foreignKeyPackage(agentId: string): string {
	const foreign = fs.mkdtempSync(join(tmpdir(), "rine-escrow-wiring-foreign-"));
	foreignDirs.push(foreign);
	saveAgentKeys(foreign, agentId, generateAgentKeys());
	return mlsToBase64(openMlsClient(foreign, agentId).generateKeyPackage());
}

/** SELF's own group state, founded locally — no HTTP, so no replenishment. */
function seedGroupState(): void {
	openMlsClient(dir, SELF_ID).createGroup(mlsGroupIdBytes(GROUP_ID)).save();
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-escrow-wiring-"));
	world = new World();
	client = withPeerReads(world, fakeClient) as never;
	posted = [];
	vi.clearAllMocks();
	vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => {
		posted.push(body);
		return { epoch: body.epoch ?? null, delivered_to: 1 };
	});
	agent(SELF_ID);
	agent(MEMBER_ID);
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
	for (const foreign of foreignDirs.splice(0)) {
		fs.rmSync(foreign, { recursive: true, force: true });
	}
});

describe("initMlsGroup", () => {
	it("test_found_group_when_commit_accepted_seals_and_uploads_escrow_for_the_new_epoch", async () => {
		offerKeyPackage(MEMBER_ID);
		vi.mocked(mlsInit).mockResolvedValue({
			mls_pending: true,
			members: [
				{ agent_id: SELF_ID, has_key_package: true },
				{ agent_id: MEMBER_ID, has_key_package: true },
			],
		});

		const result = await initMlsGroup(dir, SELF_ID, GROUP_ID, client);

		expect(result.epoch).toBe(1);
		expect(puts().map(([path]) => path)).toContain(
			`/groups/${GROUP_ID}/mls/escrow/1`,
		);
		// The drain uploaded everything it sealed, so nothing is left waiting.
		expect(listPending(dir, SELF_ID)).toEqual([]);
	});
});

describe("addMlsGroupMembers", () => {
	it("test_add_member_when_server_rejects_commit_leaves_no_pending_escrow_and_uploads_nothing", async () => {
		seedGroupState();
		agent(THIRD_ID);
		offerKeyPackage(THIRD_ID);
		// Every attempt loses the epoch CAS, including the one rebuild the
		// admission is allowed.
		vi.mocked(mlsCommit).mockRejectedValue(
			new RineApiError(409, "stale epoch", undefined, "epoch_conflict"),
		);

		await expect(
			addMlsGroupMembers(dir, SELF_ID, GROUP_ID, [THIRD_ID], client),
		).rejects.toThrow("stale epoch");

		// A commit the server never accepted must leave no
		// pending file and no upload behind.
		expect(puts()).toEqual([]);
		expect(listPending(dir, SELF_ID)).toEqual([]);
		expect(openMlsGroup(dir, SELF_ID, GROUP_ID).epoch()).toBe(1);
	});

	it("test_add_member_when_key_package_leaf_key_is_not_the_certified_one_is_skipped_and_nothing_is_posted", async () => {
		seedGroupState();
		// THIRD_ID is a world agent — the server publishes a chain-verified mls key
		// for it — but its keys are NOT on this device. The KeyPackage claimed for
		// it was minted elsewhere, under a different leaf key, so its signing key
		// is not the one the chain certified. The claim check binds the KeyPackage
		// to the certificate and leaves the member out before any commit is built.
		world.addAgent({ id: THIRD_ID });
		vi.mocked(claimKeyPackagesBatch).mockResolvedValue({
			claims: [{ agent_id: THIRD_ID, packages: [foreignKeyPackage(THIRD_ID)] }],
		});

		const result = await addMlsGroupMembers(dir, SELF_ID, GROUP_ID, [THIRD_ID], client);

		expect(result.added).toBe(0);
		expect(result.outcomes).toEqual([
			{ agentId: THIRD_ID, status: "skipped", reason: "key_package_not_current" },
		]);
		expect(posted).toEqual([]);
	});
});
