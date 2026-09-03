/**
 * The rescue's bound: how many private halves a LOOP of syncs is allowed to mint.
 *
 * `group-recovery-topup.test.ts` is the other half of this subject and stays the
 * other half: its question is whether the top-up runs at all, and where in
 * `recoverGroup` it runs. This file's question is what it costs when it runs
 * again, and again — and it drives `topUpKeyPackages` directly, because the
 * defect is inside the top-up and nothing about the recovery ladder changes it.
 *
 * 🔴 **Why the process boundary is the whole test.** `rine group sync` is a
 * one-shot process, so the module-level rescue gate is fresh on every
 * invocation, and a suite that loops inside one process measures the gate rather
 * than the bound. `resetKeyPackageRescueGate()` between iterations IS the
 * simulated process exit, and it is the only thing here standing in for real
 * life. Every other participant is real: a real native core opening a real store
 * under a real temp dir, and `keyPackageCount()` read off the disk it wrote.
 *
 * The harm that bound is for is not disk. `key_package_shortfall` returns 0 at
 * or above the low-water mark, so after *k* unbounded rescues the local mirror
 * reads `C + 10k` and low-water replenishment cannot fire again until `C + 10k
 * − 2` Welcomes have been processed. Each loop pushes the heartbeat's automatic
 * maintenance path ten Welcomes further out of reach, monotonically and
 * permanently — so "the count stopped growing" is the assertion that matters
 * here, not "the uploads stopped".
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/crypto/mls-api.js", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("../src/crypto/mls-api.js")>();
	return { ...actual, uploadKeyPackages: vi.fn() };
});

import { generateAgentKeys, saveAgentKeys } from "../src/crypto/keys.js";
import { openMlsClient } from "../src/crypto/mls.js";
import { uploadKeyPackages } from "../src/crypto/mls-api.js";
import { RineApiError } from "../src/errors.js";
import type { MlsActor } from "../src/mls-heartbeat.js";
import {
	resetKeyPackageRescueGate,
	topUpKeyPackages,
} from "../src/mls-keypackage-topup.js";
import { MLS_KEY_PACKAGE_TARGET } from "../src/mls-keypackages.js";

const AGENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const COUNT_PATH = `/agents/${AGENT_ID}/mls/key-packages/count`;

/**
 * A stand-in server that HOLDS a pool, rather than a stub that answers a number.
 *
 * The bound is arithmetic against what the server holds, so a fixture whose
 * count does not move when an upload lands cannot tell a bounded rescue from an
 * unbounded one: both would read the same number forever.
 */
function serverHolding(initial: number) {
	let available = initial;
	const gets: string[] = [];
	/** `null` is the un-upgraded server: it does not serve the route at all. */
	let answersCount: "yes" | "404" | "no-field" = "yes";

	vi.mocked(uploadKeyPackages).mockImplementation(async (_c, _a, packages) => {
		available += packages.length;
		return { stored: packages.length };
	});

	return {
		gets,
		get available() {
			return available;
		},
		/** Peers claimed the whole published pool; the private halves stay on disk. */
		drainedByPeers() {
			available = 0;
		},
		stopsServingTheCountRoute() {
			answersCount = "404";
		},
		answersTheCountRouteWithoutTheField() {
			answersCount = "no-field";
		},
		actor: {
			configDir: "",
			agentId: AGENT_ID,
			client: {
				get: async (path: string) => {
					gets.push(path);
					if (path !== COUNT_PATH) throw new Error(`unexpected GET ${path}`);
					if (answersCount === "404") {
						throw new RineApiError(404, "Not Found");
					}
					return answersCount === "no-field" ? {} : { available };
				},
			},
		} as unknown as MlsActor,
	};
}

/** Every batch size an upload carried, in order. */
function batchSizes(): number[] {
	return vi.mocked(uploadKeyPackages).mock.calls.map((call) => call[2].length);
}

/** Private halves this agent is holding on disk, read from the real store. */
function localHalves(dir: string): number {
	return openMlsClient(dir, AGENT_ID).keyPackageCount();
}

let dir: string;

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-topup-bound-"));
	vi.clearAllMocks();
	resetKeyPackageRescueGate();
	saveAgentKeys(dir, AGENT_ID, generateAgentKeys());
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
	resetKeyPackageRescueGate();
});

describe("the rescue is bounded by what the server says it holds", () => {
	it("mints one pool across a loop of one-shot syncs, and nothing after it", async () => {
		// The shape the defect lives in: six `rine group sync` invocations, each
		// its own process, each starting with a fresh module-level gate. Before
		// the server count they cost ten private halves apiece, forever.
		const server = serverHolding(0);
		server.actor.configDir = dir;

		const outcomes = [];
		for (let i = 0; i < 6; i++) {
			resetKeyPackageRescueGate(); // the process boundary, and the only fake here
			outcomes.push(await topUpKeyPackages(server.actor));
		}

		// One upload, and it is the low-water replenishment of an empty pool.
		expect(batchSizes()).toEqual([MLS_KEY_PACKAGE_TARGET]);
		expect(outcomes[0]).toMatchObject({ outcome: "topped-up" });
		expect(outcomes.slice(1)).toEqual(
			Array(5).fill({ outcome: "healthy", published: 0 }),
		);
		// The assertion the harm is stated in: the mirror stopped growing, so the
		// low-water heartbeat is still one Welcome away from firing rather than
		// fifty.
		expect(localHalves(dir)).toBe(MLS_KEY_PACKAGE_TARGET);
	});

	it("asks the server, at the path the server serves", async () => {
		// Named rather than implied. A fix that computes the bound from anything
		// local passes every count assertion above by accident on a fixture whose
		// pool happens to be full, and this is the one thing that cannot.
		const server = serverHolding(MLS_KEY_PACKAGE_TARGET);
		server.actor.configDir = dir;
		// Locally at target too, so `ensure` publishes nothing and the rescue arm
		// is the one under test.
		openMlsClient(dir, AGENT_ID).replenishKeyPackages();

		await topUpKeyPackages(server.actor);

		expect(server.gets).toEqual([COUNT_PATH]);
		expect(batchSizes()).toEqual([]);
	});

	it("rescues the agent whose mirror is full and whose server pool is empty", async () => {
		// The wedged agent, exactly, and the reason a local ceiling was rejected:
		// its mirror reads ten while the server holds none, because every peer
		// claimed a package to mint a Welcome that never arrived. It is un-addable
		// and only the server can say so.
		const server = serverHolding(0);
		server.actor.configDir = dir;
		await topUpKeyPackages(server.actor); // first sync fills both
		server.drainedByPeers();

		resetKeyPackageRescueGate();
		const rescued = await topUpKeyPackages(server.actor);
		resetKeyPackageRescueGate();
		const after = await topUpKeyPackages(server.actor);

		expect(rescued).toMatchObject({
			outcome: "topped-up",
			published: MLS_KEY_PACKAGE_TARGET,
		});
		// And then it STOPS — which is the whole residual. The old code rescued
		// this agent again on every invocation for as long as the loop ran.
		expect(after).toMatchObject({ outcome: "healthy", published: 0 });
		expect(localHalves(dir)).toBe(2 * MLS_KEY_PACKAGE_TARGET);
	});

	it("mints the shortfall and not a batch", async () => {
		// Three, not ten. The server holding seven is the ordinary case after a
		// few peers have added this agent to groups.
		const server = serverHolding(MLS_KEY_PACKAGE_TARGET - 3);
		server.actor.configDir = dir;
		openMlsClient(dir, AGENT_ID).replenishKeyPackages();

		const result = await topUpKeyPackages(server.actor);

		expect(batchSizes()).toEqual([3]);
		expect(result).toMatchObject({ outcome: "topped-up", published: 3 });
	});
});

describe("a server that will not say what it holds", () => {
	// 🔴 Every server deployed at the time this shipped is in this state: the
	// count route is a server change, and the release order deploys it before the
	// clients are published. These two tests are what makes the client publishable
	// against the server that is running right now.

	it("falls back to publishing a full batch, rather than deciding there is nothing to mint", async () => {
		// The first wrong reading of a missing answer: treat it as a zero
		// SHORTFALL. The rescue would then be a no-op against the whole installed
		// base, and the agent it exists for — seated by a vote, holding no
		// claimable key package — would stay un-addable with the sync reporting
		// success.
		const server = serverHolding(0);
		server.actor.configDir = dir;
		openMlsClient(dir, AGENT_ID).replenishKeyPackages(); // mirror at target
		vi.mocked(uploadKeyPackages).mockClear();
		server.stopsServingTheCountRoute();

		const result = await topUpKeyPackages(server.actor);

		expect(batchSizes()).toEqual([MLS_KEY_PACKAGE_TARGET]);
		expect(result).toMatchObject({ outcome: "topped-up" });
	});

	it("keeps the per-process floor in front of that batch", async () => {
		// The second wrong reading: treat the missing answer as a zero POOL. The
		// arithmetic then says "mint a full batch" on every single call, with
		// nothing in front of it — the unbounded loop, restored by the fix meant
		// to close it. The floor is what the fallback must route through.
		const server = serverHolding(0);
		server.actor.configDir = dir;
		openMlsClient(dir, AGENT_ID).replenishKeyPackages();
		vi.mocked(uploadKeyPackages).mockClear();
		server.stopsServingTheCountRoute();

		const first = await topUpKeyPackages(server.actor);
		const second = await topUpKeyPackages(server.actor);
		const third = await topUpKeyPackages(server.actor);

		expect(batchSizes()).toEqual([MLS_KEY_PACKAGE_TARGET]);
		expect(first).toMatchObject({ outcome: "topped-up" });
		expect(second).toMatchObject({ outcome: "healthy" });
		expect(third).toMatchObject({ outcome: "healthy" });
	});

	it("treats a 200 that carries no count as no answer at all", async () => {
		// A 200 is not an answer either. A body without the field reaches the
		// arithmetic as `undefined`, and `TARGET − undefined` is `NaN`, which the
		// core would be asked to mint.
		const server = serverHolding(0);
		server.actor.configDir = dir;
		openMlsClient(dir, AGENT_ID).replenishKeyPackages();
		vi.mocked(uploadKeyPackages).mockClear();
		server.answersTheCountRouteWithoutTheField();

		const result = await topUpKeyPackages(server.actor);

		expect(batchSizes()).toEqual([MLS_KEY_PACKAGE_TARGET]);
		expect(result).toMatchObject({ outcome: "topped-up" });
	});
});
