/**
 * The key-package top-up that rides on `group sync` — driven for real.
 *
 * `group-recovery.test.ts` stubs the top-up, because its subject is which
 * recovery a group gets. This file is the other half, and the half the defect
 * lives in: that the top-up runs AHEAD of the regime branch, that it really
 * reaches the wire, and that it rides on the REFUSAL as well as on the result.
 *
 * The ordering is the whole point. An agent whose published key packages have
 * run out is un-addable — no member can mint it a Welcome, so a carried vote
 * seats it on the roster with no leaf in the ratchet tree — and `recoverMlsGroup`
 * answers exactly that agent by THROWING, because its local state never existed.
 * A top-up attached to the returned result would therefore run for every group
 * except the one it exists to fix, and a suite that mocked the top-up away could
 * not tell the two orders apart.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const recoverMlsGroupSpy = vi.fn();

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/crypto/mls-api.js")
	>("../src/crypto/mls-api.js");
	return {
		...actual,
		uploadKeyPackages: vi.fn(async (_c: unknown, _a: unknown, p: string[]) => ({
			stored: p.length,
		})),
	};
});

vi.mock("../src/mls-ops-resync.js", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("../src/mls-ops-resync.js")>();
	return {
		...actual,
		recoverMlsGroup: (...args: unknown[]) => recoverMlsGroupSpy(...args),
	};
});

import { saveAgentKeys } from "../src/crypto/keys.js";
import { generateAgentKeys } from "./helpers/keys.js";
import { uploadKeyPackages } from "../src/crypto/mls-api.js";
import { formatError } from "../src/errors.js";
import { recoverGroup } from "../src/group-recovery.js";
import { resetProcessGates } from "../src/process-gate.js";
import {
	MlsResyncUnavailableError,
	isMlsResyncUnavailable,
} from "../src/mls-ops-resync.js";

const AGENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

/** Latched: the group runs MLS, which is what puts the top-up in the path. */
const MLS_ROW = {
	id: GROUP_ID,
	enrollment_policy: "closed",
	mls_enabled: true,
	mls_group_id: "latched",
	mls_pending: false,
};

/** Nothing here is allowed to reach the network by any other route. */
const client = {
	get: async (path: string) => {
		throw new Error(`unexpected GET ${path}`);
	},
} as never;

let dir: string;

/** Every agent id an upload was posted for, in order. */
function uploadedFor(): string[] {
	return vi.mocked(uploadKeyPackages).mock.calls.map((call) => String(call[1]));
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-recovery-topup-"));
	vi.clearAllMocks();
	// Per process by design, so a test inheriting the previous test's stamp would
	// measure the gate rather than the rescue.
	resetProcessGates();
	vi.mocked(uploadKeyPackages).mockImplementation(async (_c, _a, p) => ({
		stored: p.length,
	}));
	saveAgentKeys(dir, AGENT_ID, generateAgentKeys());
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("the top-up rides ahead of the regime branch", () => {
	it("publishes for the agent whose state will not load, and says so on the refusal", async () => {
		// The un-addable agent, exactly: no local MLS state, so the ladder refuses.
		// Its pool is the thing that has to be refilled before any member can mint
		// it a Welcome, and this is the one call in the product that refills it.
		recoverMlsGroupSpy.mockRejectedValue(
			new MlsResyncUnavailableError(GROUP_ID),
		);

		const err = await recoverGroup(dir, AGENT_ID, MLS_ROW, client).then(
			() => undefined,
			(e: unknown) => e,
		);

		// Reached the wire, for the acting agent. Not "a helper was called": a
		// mocked helper would have passed against the build that shipped this.
		expect(uploadedFor()).toEqual([AGENT_ID]);
		expect(isMlsResyncUnavailable(err)).toBe(true);
		expect((err as MlsResyncUnavailableError).keyPackages).toMatchObject({
			outcome: "topped-up",
		});
	});

	it("says the refusal once, with the top-up inside it and not in front of it", async () => {
		// `formatError` renders an error WITH ITS CAUSE — `${message}: ${cause}` —
		// and this refusal is a replacement for the one it caught, not a wrapper
		// around a different failure: its message is that one's message plus the
		// top-up line. Carried as a cause, the operator got the admin-remedy
		// paragraph, then the top-up sentence terminated by `: `, then the
		// paragraph again — the top-up report reading as a prefix to a duplicate.
		recoverMlsGroupSpy.mockRejectedValue(
			new MlsResyncUnavailableError(GROUP_ID),
		);

		const err = await recoverGroup(dir, AGENT_ID, MLS_ROW, client).then(
			() => undefined,
			(e: unknown) => e,
		);

		const rendered = formatError(err);
		expect(rendered).toBe((err as Error).message);
		expect(rendered).toContain("Published");
		// The remedy paragraph opens the sentence exactly once.
		expect(rendered.split("Cannot resync MLS group")).toHaveLength(2);
	});

	it("publishes for the agent whose recovery succeeded, and reports it on the result", async () => {
		recoverMlsGroupSpy.mockResolvedValue({
			regime: "mls",
			rung: "replay",
			fromEpoch: 4,
			epoch: 9,
			behind: 5,
			processed: 5,
			evicted: false,
		});

		const result = await recoverGroup(dir, AGENT_ID, MLS_ROW, client);

		expect(uploadedFor()).toEqual([AGENT_ID]);
		expect(result.keyPackages).toMatchObject({ outcome: "topped-up" });
	});

	it("stops minting however many syncs ask, once the pool is up and the rescue is spent", async () => {
		// The server's inventory cap is enforced over a whole batch and the native
		// core writes every private half to disk BEFORE the blobs go up, so a
		// refused batch un-mints nothing. Without a floor, a long-lived client
		// looping `groups.sync()` mints ten more ML-KEM-768 private halves per
		// call, into a directory whose only removal path is a Welcome consuming
		// one.
		//
		// Two uploads and not one, and both are bounded: the first sync finds this
		// agent's pool below its low-water mark and tops it up, the second finds
		// the pool full and spends the process's one additive rescue on it. Every
		// sync after that publishes nothing at all — which is the property, and
		// the count staying put as the loop grows is what states it.
		recoverMlsGroupSpy.mockRejectedValue(
			new MlsResyncUnavailableError(GROUP_ID),
		);

		for (let i = 0; i < 6; i++) {
			await recoverGroup(dir, AGENT_ID, MLS_ROW, client).catch(() => undefined);
		}

		expect(uploadedFor()).toEqual([AGENT_ID, AGENT_ID]);
	});

	it("does not spend the rescue on a turn the server never answered", async () => {
		// A refused upload published nothing, so the next recovery in this process
		// may try again: the floor is a brake on MINTING, not a quota on attempts.
		// Refused on the second upload, which is the rescue's own — the first is
		// the low-water top-up of a pool that starts empty here.
		recoverMlsGroupSpy.mockRejectedValue(
			new MlsResyncUnavailableError(GROUP_ID),
		);
		let uploads = 0;
		vi.mocked(uploadKeyPackages).mockImplementation(async (_c, _a, p) => {
			uploads += 1;
			if (uploads === 2) throw new Error("503 from the key package endpoint");
			return { stored: p.length };
		});

		await recoverGroup(dir, AGENT_ID, MLS_ROW, client).catch(() => undefined);
		const refused = await recoverGroup(dir, AGENT_ID, MLS_ROW, client).catch(
			(e: unknown) => e,
		);
		const retried = await recoverGroup(dir, AGENT_ID, MLS_ROW, client).catch(
			(e: unknown) => e,
		);

		expect((refused as MlsResyncUnavailableError).keyPackages).toMatchObject({
			outcome: "failed",
		});
		expect((retried as MlsResyncUnavailableError).keyPackages).toMatchObject({
			outcome: "topped-up",
		});
		expect(uploadedFor()).toEqual([AGENT_ID, AGENT_ID, AGENT_ID]);
	});
});
