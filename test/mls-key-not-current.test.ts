/**
 * The server's refusal of a key package signed by an earlier key generation,
 * as a typed error, and what a recovery's key-package top-up reports for it.
 *
 * The refusal is a 422 coded `mls_key_not_current`; the server's real body is replayed in
 * `mls-key-not-current-contract.test.ts`, and the code string is shared byte-for-byte with the
 * Python SDK.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const recoverMlsGroupSpy = vi.fn();

vi.mock("../src/mls-ops-resync.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../src/mls-ops-resync.js")>();
	return { ...actual, recoverMlsGroup: (...args: unknown[]) => recoverMlsGroupSpy(...args) };
});

import { saveAgentKeys } from "../src/crypto/keys.js";
import { uploadKeyPackages } from "../src/crypto/mls-api.js";
import {
	KEY_NOT_CURRENT_MESSAGE,
	MlsKeyNotCurrentError,
	isMlsKeyNotCurrent,
} from "../src/crypto/mls-key-not-current.js";
import { RineApiError } from "../src/errors.js";
import { recoverGroup } from "../src/group-recovery.js";
import { resetProcessGates } from "../src/process-gate.js";
import { MlsResyncUnavailableError } from "../src/mls-ops-resync.js";
import { generateAgentKeys } from "./helpers/keys.js";

const AGENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const MLS_ROW = {
	id: GROUP_ID,
	enrollment_policy: "closed",
	mls_enabled: true,
	mls_group_id: "latched",
	mls_pending: false,
};

const refusal = () => new RineApiError(422, "not current", undefined, "mls_key_not_current");
const clientRefusing = (err: Error) =>
	({ post: async () => { throw err; }, get: async () => { throw err; } }) as never;

describe("uploadKeyPackages", () => {
	it("test_upload_when_the_server_answers_mls_key_not_current_then_it_throws_the_typed_error", async () => {
		const err = await uploadKeyPackages(clientRefusing(refusal()), AGENT_ID, ["p"]).catch(
			(e: unknown) => e,
		);

		expect(err).toBeInstanceOf(MlsKeyNotCurrentError);
		expect(isMlsKeyNotCurrent(err)).toBe(true);
		expect((err as Error).message).toBe(KEY_NOT_CURRENT_MESSAGE);
	});

	it("test_upload_when_the_server_refuses_with_another_code_then_the_error_passes_through", async () => {
		const other = new RineApiError(422, "full", undefined, "inventory_full");

		const err = await uploadKeyPackages(clientRefusing(other), AGENT_ID, ["p"]).catch(
			(e: unknown) => e,
		);

		expect(err).toBe(other);
		expect(isMlsKeyNotCurrent(err)).toBe(false);
	});

	it("test_is_mls_key_not_current_when_only_the_sentence_matches_then_it_is_false", () => {
		expect(isMlsKeyNotCurrent(new Error(KEY_NOT_CURRENT_MESSAGE))).toBe(false);
	});
});

describe("the recovery top-up", () => {
	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-key-not-current-"));
		resetProcessGates();
		saveAgentKeys(dir, AGENT_ID, generateAgentKeys());
		recoverMlsGroupSpy.mockRejectedValue(new MlsResyncUnavailableError(GROUP_ID));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("test_recovery_when_the_server_refuses_the_packages_as_not_current_then_the_top_up_failed_with_the_sentence", async () => {
		const err = await recoverGroup(dir, AGENT_ID, MLS_ROW, clientRefusing(refusal())).catch(
			(e: unknown) => e,
		);

		expect((err as MlsResyncUnavailableError).keyPackages).toEqual({
			outcome: "failed",
			published: 0,
			detail: KEY_NOT_CURRENT_MESSAGE,
		});
	});
});
