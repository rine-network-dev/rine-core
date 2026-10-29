/**
 * `postMlsCommitBundle`: what the server's answer means, and the settlement
 * hold the post-accept heartbeat runs inside.
 *
 * Only the network (`crypto/mls-api.js`) and the heartbeat are faked. The bundle
 * is a plain object because the function reads four fields off it and nothing
 * else; the group handle is never touched.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<typeof import("../src/crypto/mls-api.js")>(
		"../src/crypto/mls-api.js",
	);
	return { ...actual, mlsCommit: vi.fn() };
});

vi.mock("../src/mls-heartbeat.js", () => ({ mlsHeartbeat: vi.fn(async () => {}) }));

import { mlsCommit, mlsToBase64 } from "../src/crypto/mls-api.js";
import { postMlsCommit, postMlsCommitBundle } from "../src/mls-commit.js";
import { mlsHeartbeat } from "../src/mls-heartbeat.js";
import { isSettling } from "../src/mls-settle-guard.js";

const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const JOINER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const actor = {
	configDir: "/tmp/rine-commit-bundle",
	agentId: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
	client: {} as never,
};

/** A bundle carrying only the fields the function reads. */
function bundle(overrides: Record<string, unknown> = {}) {
	return {
		commit: new Uint8Array([1, 2, 3]),
		groupInfo: new Uint8Array([4, 5, 6]),
		welcomes: [],
		epoch: 3,
		...overrides,
	} as never;
}

/** The commit body the code posted, from the mocked `mlsCommit`. */
function postedBody() {
	return vi.mocked(mlsCommit).mock.calls[0]![2];
}

beforeEach(() => {
	vi.clearAllMocks();
	vi.mocked(mlsHeartbeat).mockImplementation(async () => {});
	vi.mocked(mlsCommit).mockResolvedValue({ epoch: 7, delivered_to: 1 });
});

describe("postMlsCommitBundle", () => {
	it("test_postMlsCommitBundle_when_the_server_omits_confirmed_then_it_defaults_to_true", async () => {
		await expect(
			postMlsCommitBundle(actor, GROUP_ID, bundle()),
		).resolves.toEqual({ epoch: 7, confirmed: true });
	});

	it("test_postMlsCommitBundle_when_the_server_holds_the_commit_tentatively_then_confirmed_is_false", async () => {
		vi.mocked(mlsCommit).mockResolvedValue({ epoch: 7, delivered_to: 1, confirmed: false });

		await expect(
			postMlsCommitBundle(actor, GROUP_ID, bundle()),
		).resolves.toEqual({ epoch: 7, confirmed: false });
	});

	it("test_postMlsCommitBundle_when_the_server_records_no_epoch_then_the_bundle_epoch_is_returned", async () => {
		vi.mocked(mlsCommit).mockResolvedValue({ epoch: null, delivered_to: 0 });

		await expect(
			postMlsCommitBundle(actor, GROUP_ID, bundle({ epoch: 3 })),
		).resolves.toEqual({ epoch: 3, confirmed: true });
	});

	it("test_postMlsCommit_when_the_server_accepts_then_only_the_epoch_number_is_returned", async () => {
		await expect(postMlsCommit(actor, GROUP_ID, bundle())).resolves.toBe(7);
	});

	it("test_postMlsCommitBundle_when_the_commit_is_accepted_then_the_gated_beat_runs_inside_the_settlement_hold", async () => {
		const order: string[] = [];
		let settlingDuringBeat = false;
		vi.mocked(mlsCommit).mockImplementation(async () => {
			order.push("commit");
			return { epoch: 7, delivered_to: 1 };
		});
		vi.mocked(mlsHeartbeat).mockImplementation(async (_actor, pace) => {
			order.push(`heartbeat:${pace}`);
			settlingDuringBeat = isSettling(actor);
		});

		await postMlsCommitBundle(actor, GROUP_ID, bundle());

		expect(order).toEqual(["commit", "heartbeat:gated"]);
		expect(settlingDuringBeat).toBe(true);
		expect(isSettling(actor)).toBe(false);
	});

	it("test_postMlsCommitBundle_when_the_commit_is_rejected_then_the_failure_propagates_and_no_beat_runs", async () => {
		const failure = new Error("epoch_conflict");
		vi.mocked(mlsCommit).mockRejectedValue(failure);

		await expect(
			postMlsCommitBundle(actor, GROUP_ID, bundle()),
		).rejects.toBe(failure);
		expect(mlsHeartbeat).not.toHaveBeenCalled();
	});

	it("test_postMlsCommitBundle_when_a_joiner_has_a_welcome_then_the_body_pairs_them_by_agent_id", async () => {
		const welcome = new Uint8Array([9, 8, 7]);

		await postMlsCommitBundle(
			actor,
			GROUP_ID,
			bundle({ welcomes: [welcome] }),
			[{ agentId: JOINER_ID, keyPackage: new Uint8Array([1]) }],
		);

		expect(postedBody().welcomes).toEqual([
			{ agent_id: JOINER_ID, welcome: mlsToBase64(welcome) },
		]);
	});

	it("test_postMlsCommitBundle_when_a_joiner_has_no_welcome_then_it_throws_naming_the_agent", async () => {
		await expect(
			postMlsCommitBundle(
				actor,
				GROUP_ID,
				bundle({ welcomes: [] }),
				[{ agentId: JOINER_ID, keyPackage: new Uint8Array([1]) }],
			),
		).rejects.toThrow(`produced no welcome for ${JOINER_ID}`);
		expect(mlsCommit).not.toHaveBeenCalled();
	});
});
