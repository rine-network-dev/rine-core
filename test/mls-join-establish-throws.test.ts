/**
 * A step of the join's local MLS setup that throws for a reason that is not a
 * refusal, against the REAL native core with one failure injected at a time: the
 * setup reports it as outcome `failed`, and only a Welcome refusal is thrown,
 * whichever group it names.
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
		uploadKeyPackages: vi.fn(async (_c: unknown, _a: unknown, p: string[]) => ({
			stored: p.length,
		})),
		claimKeyPackages: vi.fn(async () => ({ packages: [], agent_id: "" })),
		claimKeyPackagesBatch: vi.fn(async () => ({ claims: [] })),
		mlsInit: vi.fn(async () => ({ mls_pending: true, members: [] })),
		mlsCommit: vi.fn(async () => ({ epoch: null, delivered_to: 1 })),
		mlsAck: vi.fn(async () => ({ confirmed: true, acks: 1, needed: 1 })),
		mlsNack: vi.fn(async () => ({ quarantined: true })),
		fetchHandshakes: vi.fn(async () => ({ handshakes: [] })),
		fetchWelcomes: vi.fn(async () => ({ welcomes: [] })),
		fetchGroupInfo: vi.fn(async () => ({ group_info: null, epoch: null })),
	};
});

vi.mock("../src/crypto/mls-state.js", async () => {
	const actual = await vi.importActual<typeof import("../src/crypto/mls-state.js")>(
		"../src/crypto/mls-state.js",
	);
	return { ...actual, loadMlsState: vi.fn(actual.loadMlsState) };
});

vi.mock("../src/mls-stranded-seat.js", async () => {
	const actual = await vi.importActual<typeof import("../src/mls-stranded-seat.js")>(
		"../src/mls-stranded-seat.js",
	);
	return { ...actual, welcomeKept: vi.fn(actual.welcomeKept) };
});

vi.mock("../src/mls-ops-join.js", async () => {
	const actual = await vi.importActual<typeof import("../src/mls-ops-join.js")>(
		"../src/mls-ops-join.js",
	);
	return { ...actual, processMlsWelcomes: vi.fn(actual.processMlsWelcomes) };
});

import { loadMlsState } from "../src/crypto/mls-state.js";
import {
	MlsEstablishStep,
	MlsMembershipOutcome,
	establishMlsMembership,
} from "../src/mls-join-establish.js";
import { processMlsWelcomes } from "../src/mls-ops-join.js";
import { welcomeKept } from "../src/mls-stranded-seat.js";
import { MlsWelcomeRefusedError } from "../src/mls-welcome-guard.js";
import { GROUP_ID, scene, setUpScene, tearDownScene } from "./mls-admission-scene.js";
import { D_ID, OTHER_GROUP_ID, addD, joiner } from "./mls-welcome-catchup-scene.js";

beforeEach(async () => {
	await setUpScene({ removeC: false });
	await addD();
	const client = scene.client as unknown as { get: (path: string, ...rest: unknown[]) => unknown };
	const real = client.get;
	client.get = (path, ...rest) =>
		path === `/groups/${GROUP_ID}` ? { id: GROUP_ID, mls_group_id: GROUP_ID } : real(path, ...rest);
});
afterEach(tearDownScene);

const establish = () => establishMlsMembership(joiner.dir, D_ID, GROUP_ID, scene.client);

describe("a non-refusal throw inside the join's local MLS setup", () => {
	it("test_establish_when_the_spool_read_throws_then_the_setup_is_failed_not_thrown", async () => {
		vi.mocked(welcomeKept).mockImplementationOnce(() => {
			throw new Error("spool unreadable");
		});

		const result = await establish();

		expect(result).toMatchObject({
			outcome: MlsMembershipOutcome.Failed,
			failure: { step: MlsEstablishStep.WelcomeInstall },
		});
		expect(result.reason).toContain("spool unreadable");
	});

	it("test_establish_when_the_state_read_throws_then_the_setup_is_failed_not_thrown", async () => {
		vi.mocked(loadMlsState).mockImplementationOnce(() => {
			throw new Error("state unreadable");
		});

		const result = await establish();

		expect(result).toMatchObject({
			outcome: MlsMembershipOutcome.Failed,
			failure: { step: MlsEstablishStep.WelcomeInstall },
		});
		expect(result.reason).toContain("state unreadable");
	});

	it("test_establish_when_a_refusal_names_another_group_then_it_is_still_thrown", async () => {
		const refusal = new MlsWelcomeRefusedError(OTHER_GROUP_ID, "peer_not_admitted", "refused");
		vi.mocked(processMlsWelcomes).mockRejectedValueOnce(refusal);

		await expect(establish()).rejects.toBe(refusal);
	});
});
