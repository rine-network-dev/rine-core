/**
 * A rotated agent that tries to resync, against the REAL native core.
 *
 * A rotation leaves the agent's leaf in every group under the key it was seated
 * with. A resync replaces the agent's own leaf and signs with its current key,
 * which the core refuses for a leaf of another generation. The agent gets a typed
 * outcome naming the remedy that exists, not the core's sentence about an
 * unadmitted peer.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-escrow-key.js", async () =>
	(await import("./mls-escrow-harness.js")).escrowKeyModule(),
);

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<typeof import("../src/crypto/mls-api.js")>(
		"../src/crypto/mls-api.js",
	);
	return {
		...actual,
		uploadKeyPackages: vi.fn(async (_c: unknown, _a: unknown, p: string[]) => ({ stored: p.length })),
		claimKeyPackages: vi.fn(),
		claimKeyPackagesBatch: vi.fn(),
		mlsInit: vi.fn(),
		mlsCommit: vi.fn(),
		mlsAck: vi.fn(),
		mlsNack: vi.fn(),
		fetchHandshakes: vi.fn(),
		fetchWelcomes: vi.fn(),
		fetchGroupInfo: vi.fn(),
	};
});

import { fetchHandshakes } from "../src/crypto/mls-api.js";
import { MLS_ERR_ROTATED_LEAF } from "../src/crypto/mls-errors.js";
import { RineApiError } from "../src/errors.js";
import { MLS_RESYNC_REQUIRED_CODE, recoverMlsGroup } from "../src/mls-ops-resync.js";
import { MlsRotatedLeafError, isMlsRotatedLeaf } from "../src/mls-rotated-leaf.js";
import { ReseatStatus, reseatClosedGroups } from "../src/recover-reseat.js";
import {
	A,
	B,
	G1,
	R,
	found,
	joinGroup,
	proc,
	rotate,
	scene,
	setUpRotationScene,
	tearDownRotationScene,
} from "./mls-rotation-scene.js";

const MESSAGE =
	`Agent ${A}'s leaf in group ${G1} still carries a key it has since rotated away from, ` +
	"and this device holds no group state that can move it; a member must remove the agent and invite it again before it can resync.";

beforeEach(async () => {
	setUpRotationScene();
	await found(scene.dr, R, G1, [A, B]);
	await joinGroup(scene.d1, A, G1);
	await joinGroup(scene.d1, B, G1);
	vi.mocked(fetchHandshakes).mockRejectedValue(
		new RineApiError(409, "replay cannot help", undefined, MLS_RESYNC_REQUIRED_CODE),
	);
});
afterEach(tearDownRotationScene);

/** The group list a reseat reads: the one MLS group, with `ids` seated. */
function listingClient(ids: string[]) {
	const base = scene.client as { get: (...a: unknown[]) => Promise<unknown> };
	return {
		...base,
		get: async (path: string, ...rest: unknown[]) =>
			path === "/groups"
				? { items: [{ id: G1, mls_group_id: "latched", member_agent_ids: ids }] }
				: base.get(path, ...rest),
	} as never;
}

describe("a rotated agent that resyncs", () => {
	it("test_recover_when_the_agent_rotated_then_it_throws_the_typed_rotated_leaf_error", async () => {
		rotate(A, scene.d1);

		const err = await recoverMlsGroup(proc(scene.d1, 1), A, G1, scene.client).catch((e: unknown) => e);

		expect(err).toBeInstanceOf(MlsRotatedLeafError);
		expect(isMlsRotatedLeaf(err)).toBe(true);
		expect(err).toMatchObject({ code: MLS_ERR_ROTATED_LEAF, agentId: A, groupId: G1, message: MESSAGE });
		expect((err as Error).cause).toBeUndefined();
	});

	it("test_reseat_when_the_agent_rotated_then_the_status_is_needs_readd_with_the_message", async () => {
		rotate(A, scene.d1);

		const [outcome] = await reseatClosedGroups(listingClient([A]), proc(scene.d1, 2), [A]);

		expect(outcome).toMatchObject({
			agent_id: A,
			group_id: G1,
			status: ReseatStatus.NeedsReAdd,
			reason: MESSAGE,
		});
		expect(ReseatStatus.NeedsReAdd).toBe("needs_readd");
	});

	it("test_recover_when_the_agent_never_rotated_then_it_resyncs", async () => {
		const result = await recoverMlsGroup(proc(scene.d1, 3), A, G1, scene.client);

		expect(result).toMatchObject({ rung: "resync" });
	});

	it("test_reseat_when_the_agent_never_rotated_then_it_is_reseated", async () => {
		const [outcome] = await reseatClosedGroups(listingClient([A]), proc(scene.d1, 4), [A]);

		expect(outcome?.status).toBe(ReseatStatus.Reseated);
	});

});
