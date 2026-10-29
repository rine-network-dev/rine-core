/**
 * Three agents on three devices, one group, and a stand-in server, for the tests
 * that drive the REAL native core through a peer that is in the ratchet tree but
 * in no roster.
 *
 * A founds the group with B and adds C. B is offline from there on, so B can only
 * learn C's leaf key through a chain-verified key read, and `cKeys` chooses how
 * the server answers that read. The calling test file mocks `crypto/mls-api.js`
 * and `mls-escrow-key.js`; this module drives those mocks.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { vi } from "vitest";
import {
	claimKeyPackages,
	claimKeyPackagesBatch,
	fetchGroupInfo,
	fetchHandshakes,
	fetchWelcomes,
	mlsAck,
	mlsCommit,
	mlsInit,
	mlsNack,
	mlsToBase64,
} from "../src/crypto/mls-api.js";
import type { MlsCommitBody } from "../src/crypto/mls-api.js";
import { mlsGroupIdBytes, openMlsClient } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import {
	addMlsGroupMember,
	initMlsGroup,
	processMlsWelcomes,
	removeMlsGroupMember,
} from "../src/mls-ops.js";
import { World } from "./crypto/world.js";
import { withPeerReads } from "./mls-escrow-harness.js";

export const A_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
export const B_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
export const C_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";
export const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

/** How the server answers a read of C's published keys. */
export type CKeys = "served" | "tampered" | "foreign" | "absent" | "outage";

/** The most key reads a test lets a runaway retry make before it fails loudly. */
export const READ_CEILING = 8;

export interface Scene {
	root: string;
	dirA: string;
	dirB: string;
	dirC: string;
	world: World;
	foreign: World;
	/** Every commit A posted, in order. */
	posted: MlsCommitBody[];
	cKeys: CKeys;
	/** Every `GET /agents/keys` batch, as the ids it named. */
	keyReads: string[][];
	roster: string[];
	client: never;
}

/** Set by {@link setUpScene}; the tests read and steer the scene through it. */
export const scene = {} as Scene;

export function groupOf(dir: string, id: string) {
	return openMlsClient(dir, id).loadGroup(mlsGroupIdBytes(GROUP_ID));
}

export function agent(dir: string, id: string): void {
	scene.world.save(dir, scene.world.addAgent({ id }));
}

/** The fake server: roster reads, and a key read whose answer for C is `cKeys`. */
function serverClient() {
	const { world, foreign } = scene;
	const base = withPeerReads(world, { get: async () => ({ items: [] }) }, () => scene.roster);
	return {
		...base,
		get: async (path: string, params?: Record<string, string>, headers?: unknown) => {
			if (path !== "/agents/keys") return (base.get as Function)(path, params, headers);
			const ids = String(params?.["ids"] ?? "").split(",").filter(Boolean);
			scene.keyReads.push(ids);
			if (scene.keyReads.length > READ_CEILING) throw new Error("the retry is not bounded");
			const { keys } = (await (base.get as Function)(path, params, headers)) as {
				keys: Record<string, ReturnType<World["published"]>>;
			};
			if (!keys[C_ID]) return { keys };
			if (scene.cKeys === "outage") throw new RineApiError(503, "unavailable");
			if (scene.cKeys === "absent") delete keys[C_ID];
			if (scene.cKeys === "foreign") keys[C_ID] = foreign.published(C_ID);
			if (scene.cKeys === "tampered") {
				keys[C_ID] = {
					...keys[C_ID]!,
					agent_certificate: world.addAgent({ id: A_ID }).response.agent_certificate,
				};
			}
			return { keys };
		},
	};
}

export function offerKeyPackage(id: string, dir: string): void {
	const pkg = mlsToBase64(openMlsClient(dir, id).generateKeyPackage());
	vi.mocked(claimKeyPackages).mockResolvedValue({ packages: [pkg], agent_id: id });
	vi.mocked(claimKeyPackagesBatch).mockResolvedValue({
		claims: [{ agent_id: id, packages: [pkg] }],
	});
}

/** A founds the group with B, then adds C; the commit posted for the Add is `posted[1]`. */
async function foundAndAddC(): Promise<void> {
	const { dirA, dirB, dirC, client } = scene;
	offerKeyPackage(B_ID, dirB);
	vi.mocked(mlsInit).mockResolvedValue({
		mls_pending: true,
		members: [
			{ agent_id: A_ID, has_key_package: true },
			{ agent_id: B_ID, has_key_package: true },
		],
	});
	await initMlsGroup(dirA, A_ID, GROUP_ID, client);
	vi.mocked(fetchWelcomes).mockResolvedValue({
		welcomes: [
			{
				id: "w1",
				group_id: GROUP_ID,
				blob: scene.posted[0]!.welcomes![0]!.welcome,
				created_at: "2026-01-01T00:00:00Z",
			},
		],
	});
	await processMlsWelcomes(dirB, B_ID, client);
	vi.mocked(fetchWelcomes).mockResolvedValue({ welcomes: [] });
	// The server seats a member before the client adds its leaf, and B is offline
	// from here on.
	offerKeyPackage(C_ID, dirC);
	scene.roster = [A_ID, B_ID, C_ID];
	await addMlsGroupMember(dirA, A_ID, GROUP_ID, C_ID, client);
}

/** The commits A posted from epoch 1 on, as the handshakes B has not yet read. */
export function serveHandshakes(): void {
	const handshakes = scene.posted.slice(1).map((body, i) => ({
		id: `h${i + 1}`,
		epoch: body.epoch ?? null,
		blob: body.commit,
		created_at: "2026-01-01T00:00:00Z",
	}));
	vi.mocked(fetchHandshakes).mockImplementation(async (_c, _g, since) => ({
		handshakes: handshakes.filter((h) => (h.epoch ?? 0) > (since ?? 0)),
	}));
}

/**
 * Found the group and add C, with B offline. `removeC` also takes C out again, so
 * the Add is in B's replay but C is in neither the tree nor the roster; without it
 * the tree still holds C and only the roster lacks it.
 */
export async function setUpScene(options: { removeC: boolean }): Promise<void> {
	scene.root = fs.mkdtempSync(join(tmpdir(), "rine-admission-scene-"));
	[scene.dirA, scene.dirB, scene.dirC] = ["a", "b", "c"].map((name) =>
		join(scene.root, name),
	) as [string, string, string];
	for (const dir of [scene.dirA, scene.dirB, scene.dirC]) fs.mkdirSync(dir);
	scene.world = new World();
	scene.foreign = new World();
	scene.foreign.addAgent({ id: C_ID });
	scene.posted = [];
	scene.keyReads = [];
	scene.cKeys = "served";
	scene.roster = [A_ID, B_ID];
	vi.clearAllMocks();
	vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => {
		scene.posted.push(body);
		return { epoch: body.epoch ?? null, delivered_to: 1 };
	});
	vi.mocked(mlsAck).mockResolvedValue({ confirmed: true, acks: 1, needed: 1 });
	vi.mocked(mlsNack).mockResolvedValue({ quarantined: true });
	vi.mocked(fetchGroupInfo).mockResolvedValue({ group_info: null, epoch: 1 });
	agent(scene.dirA, A_ID);
	agent(scene.dirB, B_ID);
	agent(scene.dirC, C_ID);
	scene.client = serverClient() as never;
	await foundAndAddC();
	if (options.removeC) {
		await removeMlsGroupMember(scene.dirA, A_ID, GROUP_ID, C_ID, scene.client);
	}
	scene.roster = [A_ID, B_ID];
	serveHandshakes();
	scene.keyReads.length = 0;
}

export function tearDownScene(): void {
	fs.rmSync(scene.root, { recursive: true, force: true });
}
