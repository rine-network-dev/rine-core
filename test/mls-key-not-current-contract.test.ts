/**
 * The server's refusal of a key package signed by an earlier key generation, pinned against the
 * golden the server contract suite records from the real router
 * (`rine-sdk/tests/contract/fixtures/`).
 *
 * The client matches the 422's `error` code and never its sentence, so a server that renamed the
 * code would turn the typed outcome back into a generic failure while a hand-built
 * `RineApiError` still mapped. The golden body goes through the real error parser, and a refusal
 * that lands after the drain's pre-check passed is settled as `key_not_current`, not `pending`.
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

import { uploadKeyPackages } from "../src/crypto/mls-api.js";
import {
	MLS_ERR_KEY_NOT_CURRENT,
	MlsKeyNotCurrentError,
} from "../src/crypto/mls-key-not-current.js";
import { rineErrorFromResponse } from "../src/errors.js";
import { readRotationMarker } from "../src/mls-rotation-marker.js";
import { settleRotation } from "../src/mls-seat-sweep.js";
import { golden } from "./helpers/golden.js";
import { setUpSweepScene, sweptActor } from "./mls-seat-sweep-scene.js";
import { A, tearDownRotationScene } from "./mls-rotation-scene.js";

const realApi = await vi.importActual<typeof import("../src/crypto/mls-api.js")>(
	"../src/crypto/mls-api.js",
);
const { status, body } = golden<{ error: string; detail: string }>(
	"mls_key_packages_422_not_current.json",
);

/** A client whose key-package route answers the golden, parsed by the client's own error path. */
const refusingClient = {
	post: async () => {
		throw await rineErrorFromResponse(new Response(JSON.stringify(body), { status }));
	},
} as never;

beforeEach(setUpSweepScene);
afterEach(tearDownRotationScene);

describe("the stale-key refusal", () => {
	it("test_golden_when_the_server_refuses_a_stale_key_then_its_error_is_the_shared_code", () => {
		expect(status).toBe(422);
		expect(body.error).toBe(MLS_ERR_KEY_NOT_CURRENT);
	});

	it("test_upload_when_the_server_golden_is_replayed_then_it_throws_the_typed_error", async () => {
		const err = await realApi.uploadKeyPackages(refusingClient, A, ["p"]).catch((e: unknown) => e);

		expect(err).toBeInstanceOf(MlsKeyNotCurrentError);
	});

	it("test_settle_when_the_upload_is_refused_after_the_pre_check_then_it_reports_key_not_current", async () => {
		const actor = sweptActor(21);
		vi.mocked(uploadKeyPackages).mockImplementationOnce((_c, agentId, packages) =>
			realApi.uploadKeyPackages(refusingClient, agentId, packages),
		);

		const settled = await settleRotation(actor);

		expect(vi.mocked(uploadKeyPackages)).toHaveBeenCalled();
		expect(settled.key_packages).toBe("key_not_current");
		expect(readRotationMarker(actor.configDir, A).key_packages).toBe(0);
	});
});
