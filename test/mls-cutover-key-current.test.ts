/**
 * The key-package drain refuses to start from a device holding an earlier key
 * generation than the agent's current one: it would replace the published pool
 * with packages the server refuses, leaving the agent un-addable.
 *
 * Only the network is mocked; the predicate itself is pinned against the real
 * stand-in server in `mls-seat-sweep.test.ts`.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<typeof import("../src/crypto/mls-api.js")>(
		"../src/crypto/mls-api.js",
	);
	return { ...actual, uploadKeyPackages: vi.fn(), claimKeyPackages: vi.fn() };
});
vi.mock("../src/mls-key-current.js", () => ({ diskKeyIsCurrent: vi.fn() }));

import { saveAgentKeys } from "../src/crypto/keys.js";
import { claimKeyPackages, uploadKeyPackages } from "../src/crypto/mls-api.js";
import { MlsKeyNotCurrentError } from "../src/crypto/mls-key-not-current.js";
import { diskKeyIsCurrent } from "../src/mls-key-current.js";
import { drainAndRepublishMlsKeyPackages } from "../src/mls-cutover.js";
import { generateAgentKeys } from "./helpers/keys.js";

const SELF_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const client = {} as never;

let dir: string;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-mls-key-current-"));
	saveAgentKeys(dir, SELF_ID, generateAgentKeys());
});
afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
	vi.clearAllMocks();
});

describe("drainAndRepublishMlsKeyPackages key check", () => {
	it("test_drain_when_the_disk_key_is_not_current_then_it_throws_and_claims_and_uploads_nothing", async () => {
		vi.mocked(diskKeyIsCurrent).mockResolvedValue(false);

		await expect(drainAndRepublishMlsKeyPackages(dir, SELF_ID, client)).rejects.toBeInstanceOf(
			MlsKeyNotCurrentError,
		);

		expect(claimKeyPackages).not.toHaveBeenCalled();
		expect(uploadKeyPackages).not.toHaveBeenCalled();
	});

	it("test_drain_when_the_key_read_fails_then_the_failure_propagates_and_nothing_is_claimed", async () => {
		vi.mocked(diskKeyIsCurrent).mockRejectedValue(new Error("keys down"));

		await expect(drainAndRepublishMlsKeyPackages(dir, SELF_ID, client)).rejects.toThrow("keys down");

		expect(claimKeyPackages).not.toHaveBeenCalled();
	});
});
