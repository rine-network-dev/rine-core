/**
 * The spool's own rules, which are the rules for bytes a hostile server chose.
 *
 * Four things here are not about MLS at all, and all four were found by
 * measurement rather than by reading:
 *
 * 1. The delivery id becomes the file NAME. Unvalidated, a server that answers
 *    a path fragment writes wherever it likes — MEASURED — and the throw that
 *    produced took the rest of the batch with it.
 * 2. Retention makes a refusal non-terminal, and an uncorroboratable Welcome's
 *    refusal never clears, so unbounded retention is a permanent tax the server
 *    chooses the size of.
 * 3. A count bound over the whole spool then loses honest Welcomes with no
 *    adversary in the room — MEASURED, 4 of 36 — because a pass that aborts
 *    after the fetch carries its entire batch into the next one. Spooling is
 *    not the same event as having had a chance.
 * 4. A join failure that is THIS process failing (a store write, a contained
 *    panic) must never be reported as an install: that replenishes key packages
 *    and hands the caller a group id it does not hold.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-escrow-key.js", () => escrowKeyModule());

vi.mock("../src/crypto/mls.js", async () => {
	const actual = await vi.importActual<typeof import("../src/crypto/mls.js")>(
		"../src/crypto/mls.js",
	);
	return { ...actual, openMlsClient: vi.fn(), loadMlsGroup: vi.fn() };
});
vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/crypto/mls-api.js")
	>("../src/crypto/mls-api.js");
	return { ...actual, fetchWelcomes: vi.fn(async () => ({ welcomes: [] })) };
});
vi.mock("../src/mls-welcome-guard.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/mls-welcome-guard.js")
	>("../src/mls-welcome-guard.js");
	return { ...actual, welcomeRefusal: vi.fn(async () => null) };
});
vi.mock("../src/mls-heartbeat.js", () => ({
	mlsHeartbeat: vi.fn(async () => undefined),
}));

import { escrowKeyModule, withPeerReads } from "./mls-escrow-harness.js";
import { World } from "./crypto/world.js";
import { fetchWelcomes } from "../src/crypto/mls-api.js";
import { loadMlsGroup, openMlsClient } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import { processMlsWelcomes } from "../src/mls-ops-join.js";
import { mlsHeartbeat } from "../src/mls-heartbeat.js";
import { welcomeRefusal } from "../src/mls-welcome-guard.js";
import {
	WelcomeSpool,
	isSpoolableId,
	welcomeSpoolDir,
} from "../src/mls-welcome-spool.js";

const AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const DELIVERY = "d4e5f6a7-b8c9-0123-def1-234567890123";
/**
 * A traversal whose target directory does not exist.
 *
 * From `<configDir>/keys/<agent>/mls_welcomes` this resolves to
 * `<root>/OUTSIDE_CONFIG_DIR/nested/pwned.json`, and `writeAtomic` does not
 * create directories — so without the id check the write throws ENOENT out of
 * the fetch loop, which is the original destruction. A traversal onto an
 * EXISTING directory succeeds silently instead, which is why a fixture aimed at
 * one cannot reproduce the loss.
 */
const POISON = "../../../../OUTSIDE_CONFIG_DIR/nested/pwned";
const DAY_MS = 24 * 60 * 60 * 1000;

let root: string;
let dir: string;
let world: World;
let client: never;
const release = vi.fn();

/**
 * The reads the admission path makes outside the mocked `crypto/mls-api.js`:
 * the group roster and the world's published keys. Every other path is a bug in
 * this fixture.
 */
const fakeClient = {
	get: async (path: string) => {
		// The admission path reads the group's outstanding vouchers; this fixture
		// has none, so the roster is the world's own agents.
		if (/^\/groups\/[^/]+\/requests$/.test(path)) return { items: [] };
		throw new Error(`unexpected GET ${path}`);
	},
};

/** The group a mocked `joinFromWelcome` hands back, with the drain's own seam. */
function fakeGroup() {
	return { save: () => undefined, takeEscrowExports: () => ({ exports: [], gaps: [] }) };
}

beforeEach(() => {
	// The config dir is nested inside an observable root so a traversal out of it
	// lands somewhere this test can assert about, rather than in $TMPDIR at large.
	root = fs.mkdtempSync(join(tmpdir(), "rine-welcome-spool-"));
	dir = join(root, "config");
	fs.mkdirSync(dir);
	world = new World();
	world.save(dir, world.addAgent({ id: AGENT }));
	client = withPeerReads(world, fakeClient) as never;
	vi.clearAllMocks();
	// `clearAllMocks` clears recorded calls, not implementations, so the fetch is
	// re-armed empty here rather than leaking one case's batch into the next.
	vi.mocked(fetchWelcomes).mockResolvedValue({ welcomes: [] });
	vi.mocked(welcomeRefusal).mockResolvedValue(null);
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

/** A delivery the server would file under `GROUP_ID`, named `id`. */
function delivery(id: string) {
	return { id, group_id: GROUP_ID, blob: "AQI=" };
}

/** `count` distinct spool ids, in write order. */
function ids(count: number, prefix = "w"): string[] {
	return Array.from(
		{ length: count },
		(_, i) => `${prefix}${String(i).padStart(3, "0")}`,
	);
}

/** The path a spooled welcome is filed at. */
function spoolPath(id: string): string {
	return join(welcomeSpoolDir(dir, AGENT), `${id}.json`);
}

/**
 * Write one spooled welcome per id, `ageMs` old, in the order given.
 *
 * `refused` is what a pass that tried the entry and refused it retryably
 * leaves behind, and it is the population the count bound holds — so a
 * fixture that means "retained refusals" has to say so.
 */
function fill(names: string[], { ageMs = 0, refused = true } = {}): string[] {
	const spool = new WelcomeSpool(dir, AGENT);
	names.forEach((id, i) => {
		spool.store(delivery(id));
		if (refused) spool.markRefused(spoolPath(id));
		const when = new Date(Date.now() - ageMs - (names.length - i));
		fs.utimesSync(spoolPath(id), when, when);
	});
	return names;
}

describe("the name a spooled welcome is filed under", () => {
	it("test_spoolable_id_when_it_is_not_a_plain_file_name_then_it_is_refused", () => {
		expect(isSpoolableId(DELIVERY)).toBe(true);
		// The fixtures both stacks ship use ids like this, and an honest server
		// is free to reformat its own column, so the rule is "can be a file
		// name", not "is a UUID".
		expect(isSpoolableId("welcome-0")).toBe(true);

		expect(isSpoolableId("../../../profiles")).toBe(false);
		expect(isSpoolableId(POISON)).toBe(false);
		expect(isSpoolableId("a/b")).toBe(false);
		expect(isSpoolableId("a\\b")).toBe(false);
		expect(isSpoolableId("..")).toBe(false);
		expect(isSpoolableId(".hidden")).toBe(false);
		expect(isSpoolableId("")).toBe(false);
		expect(isSpoolableId("a".repeat(129))).toBe(false);
	});

	it("test_store_when_the_id_escapes_the_spool_dir_then_nothing_is_written", () => {
		// MEASURED before the check existed: this exact id overwrote
		// `<configDir>/profiles.json`, which is both the profile store and the
		// file `resolveConfigDir` locates the config dir by.
		const profiles = join(dir, "profiles.json");
		fs.writeFileSync(profiles, '{"default":{"org_id":"real"}}');

		expect(() =>
			new WelcomeSpool(dir, AGENT).store(delivery("../../../profiles")),
		).toThrow(/plain file name/);

		expect(fs.readFileSync(profiles, "utf-8")).toBe(
			'{"default":{"org_id":"real"}}',
		);
	});

	it("test_fetch_when_one_delivery_is_named_a_path_then_the_rest_of_the_batch_survives", async () => {
		// The loss half of the same defect, and the worse one: the throw came out
		// of the fetch loop, so welcomes 2 and 3 were never written — and the
		// server had already marked all three consumed. All three were gone.
		vi.mocked(fetchWelcomes).mockResolvedValue({
			welcomes: [
				{ ...delivery(POISON), created_at: "2026-01-01T00:00:00Z" },
				{ ...delivery("second"), created_at: "2026-01-01T00:00:01Z" },
				{ ...delivery("third"), created_at: "2026-01-01T00:00:02Z" },
			],
		} as never);
		// The join is irrelevant here; what is under test is what reached disk.
		vi.mocked(openMlsClient).mockImplementation(() => {
			throw new Error("stop after spooling");
		});

		await expect(processMlsWelcomes(dir, AGENT, client)).rejects.toThrow(
			"stop after spooling",
		);

		expect(
			fs
				.readdirSync(welcomeSpoolDir(dir, AGENT))
				.sort()
				.map((n) => n.replace(".json", "")),
		).toEqual(["second", "third"]);
		// Nothing was placed outside the spool dir, which is the half the batch
		// assertion above cannot see.
		expect(fs.existsSync(join(root, "OUTSIDE_CONFIG_DIR"))).toBe(false);
	});

	it("test_spool_dir_when_the_agent_id_is_a_path_then_it_is_refused", () => {
		// Defence in depth — the agent id is local, not server-chosen — but it is
		// the other half of the path this module builds, and the Python twin
		// asserts it too.
		expect(() => welcomeSpoolDir(dir, "../../../elsewhere")).toThrow(
			/agent ID/,
		);
		expect(() => new WelcomeSpool(dir, "not-a-uuid")).toThrow(/agent ID/);
	});
});

describe("what the spool keeps", () => {
	it("test_prune_when_more_refusals_than_the_cap_are_retained_then_the_oldest_go", () => {
		const names = fill(ids(36));

		expect(new WelcomeSpool(dir, AGENT).prune(release)).toBe(4);

		// A refusal for a genuinely substituted Welcome can never clear, so
		// retention without a bound is a permanent, linearly growing tax the
		// server chooses the size of. The newest survive: their refusal is the
		// one most likely still to clear.
		const kept = new WelcomeSpool(dir, AGENT)
			.pending()
			.map((e) => e.delivery.id);
		expect(kept).toEqual(names.slice(4));
	});

	it("test_prune_when_a_carried_over_batch_has_never_been_tried_then_none_of_it_goes", () => {
		// 🔴 The regression, at the bound itself. A pass that aborts after
		// spooling carries its whole batch forward, so the next pass's prune sees
		// 36 entries no pass has processed. Counting those is silent data loss:
		// MEASURED against the real native core, 4 of 36 honest Welcomes gone, and
		// a Welcome is the only copy of itself.
		const names = fill(ids(36), { refused: false });

		expect(new WelcomeSpool(dir, AGENT).prune(release)).toBe(0);

		const kept = new WelcomeSpool(dir, AGENT)
			.pending()
			.map((e) => e.delivery.id);
		expect(kept).toEqual(names);
	});

	it("test_prune_when_untried_entries_pad_the_spool_then_only_the_refusals_are_counted", () => {
		// The two populations in one spool: the count bound must see 33 refusals
		// and evict one, and must not see the 20 entries waiting for their first
		// attempt at all.
		fill(ids(33, "refused"));
		const untried = fill(ids(20, "untried"), { refused: false });

		expect(new WelcomeSpool(dir, AGENT).prune(release)).toBe(1);

		const kept = new WelcomeSpool(dir, AGENT)
			.pending()
			.map((e) => e.delivery.id);
		expect(kept).toHaveLength(52);
		expect(kept).not.toContain("refused000");
		for (const id of untried) expect(kept).toContain(id);
	});

	it("test_prune_when_a_retained_welcome_is_older_than_the_bound_then_it_goes", () => {
		fill(ids(2, "old"), { ageMs: 8 * DAY_MS });
		fill(ids(1, "new"));

		expect(new WelcomeSpool(dir, AGENT).prune(release)).toBe(2);

		// 🔴 What the bound costs, stated as a test: an honest Welcome whose
		// refusal has not cleared in a week is dropped and only a re-invitation
		// replaces it. Seven days is the server's own invitation lifetime.
		expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(1);
	});

	it("test_prune_when_an_untried_welcome_is_older_than_the_bound_then_it_still_goes", () => {
		// The age bound reaches everything: a week is past the invitation that
		// would corroborate the Welcome, tried or not.
		fill(ids(1, "stale"), { ageMs: 8 * DAY_MS, refused: false });

		expect(new WelcomeSpool(dir, AGENT).prune(release)).toBe(1);
		expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(0);
	});

	it("test_prune_when_nothing_is_past_the_bound_then_it_keeps_everything", () => {
		fill(ids(5));

		expect(new WelcomeSpool(dir, AGENT).prune(release)).toBe(0);
		expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(5);
	});

	it("test_mark_refused_when_it_runs_twice_then_the_entry_is_written_once", () => {
		const spool = new WelcomeSpool(dir, AGENT);
		spool.store(delivery("once"));
		spool.markRefused(spoolPath("once"));
		const first = fs.statSync(spoolPath("once")).mtimeMs;

		spool.markRefused(spoolPath("once"));

		// The mtime is both the queue order and the age clock, so a mark that
		// rewrote on every refusal would reset the seven days on every pass.
		expect(fs.statSync(spoolPath("once")).mtimeMs).toBe(first);
		expect(spool.pending().map((e) => e.delivery.id)).toEqual(["once"]);
	});

	it("test_pending_when_the_entry_predates_the_refused_flag_then_it_is_still_read", () => {
		// The format changed under files that are the only copy of themselves, so
		// the previous shape reads as "not yet tried" rather than as unreadable.
		const spool = new WelcomeSpool(dir, AGENT);
		spool.store(delivery("legacy"));
		fs.writeFileSync(
			spoolPath("legacy"),
			JSON.stringify({ id: "legacy", group_id: GROUP_ID, welcome: "AQI=" }),
		);

		expect(spool.pending().map((e) => e.delivery)).toEqual([
			{ id: "legacy", group_id: GROUP_ID, blob: "AQI=" },
		]);
		expect(spool.prune(release)).toBe(0);
	});

	it("test_pending_when_names_disagree_with_write_order_then_write_order_wins", () => {
		const spool = new WelcomeSpool(dir, AGENT);
		spool.store(delivery("zzz"));
		spool.store(delivery("aaa"));
		const older = new Date(Date.now() - 60_000);
		fs.utimesSync(spoolPath("zzz"), older, older);

		// The name is the server-chosen delivery id, so a name-ordered queue lets
		// the server decide which Welcome is processed first.
		expect(spool.pending().map((e) => e.delivery.id)).toEqual(["zzz", "aaa"]);
	});
});

describe("what leaves the spool unopened", () => {
	const BLOB = Uint8Array.from([1, 2]);

	it("test_prune_when_entries_are_evicted_or_aged_out_then_each_gives_its_key_package_back", () => {
		fill(ids(36));
		fill(ids(2, "old"), { ageMs: 8 * DAY_MS });

		const dropped = new WelcomeSpool(dir, AGENT).prune(release);

		expect(dropped).toBe(6);
		expect(release).toHaveBeenCalledTimes(6);
		expect(release).toHaveBeenCalledWith(BLOB);
		expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(32);
	});

	it("test_prune_when_nothing_is_past_the_bound_then_nothing_is_given_back", () => {
		fill(ids(5));

		new WelcomeSpool(dir, AGENT).prune(release);

		expect(release).not.toHaveBeenCalled();
	});

	it("test_drop_when_the_entry_is_readable_then_the_key_package_goes_back_before_the_file_goes", () => {
		const spool = new WelcomeSpool(dir, AGENT);
		spool.store(delivery("gone"));
		const stillThere: boolean[] = [];
		const checking = vi.fn(() => stillThere.push(fs.existsSync(spoolPath("gone"))));

		spool.drop(spoolPath("gone"), checking);

		expect(stillThere).toEqual([true]);
		expect(fs.existsSync(spoolPath("gone"))).toBe(false);
	});

	it("test_drop_when_the_release_fails_then_the_entry_stays_for_the_next_pass", () => {
		const spool = new WelcomeSpool(dir, AGENT);
		spool.store(delivery("kept"));
		const failing = vi.fn(() => {
			throw new Error("store write failed");
		});

		expect(() => spool.drop(spoolPath("kept"), failing)).toThrow("store write failed");

		expect(fs.existsSync(spoolPath("kept"))).toBe(true);
	});

	it("test_drop_when_the_entry_is_torn_then_it_is_discarded_without_a_release", () => {
		fs.mkdirSync(welcomeSpoolDir(dir, AGENT), { recursive: true });
		fs.writeFileSync(spoolPath("torn"), "{");

		new WelcomeSpool(dir, AGENT).drop(spoolPath("torn"), release);

		expect(release).not.toHaveBeenCalled();
		expect(fs.existsSync(spoolPath("torn"))).toBe(false);
	});
});

describe("what a pass does with the spool", () => {
	it("test_process_when_the_spool_holds_an_aged_entry_then_the_pass_prunes_it", () => {
		// The bound is only real if somebody calls it, and nothing pinned that: the
		// method had two tests and its call site had none, so deleting the call
		// passed every gate.
		const spool = new WelcomeSpool(dir, AGENT);
		for (const id of ids(2, "aged")) {
			spool.store(delivery(id));
			const when = new Date(Date.now() - 8 * DAY_MS);
			fs.utimesSync(spoolPath(id), when, when);
		}

		const discardWelcomeKeyPackage = vi.fn();
		vi.mocked(openMlsClient).mockReset();
		vi.mocked(openMlsClient).mockReturnValue({ discardWelcomeKeyPackage } as never);

		return processMlsWelcomes(dir, AGENT, client).then((result) => {
			expect(result).toEqual({
				processed: 0,
				groupIds: [],
				discarded: 2,
				escrow: { gaps: [], queued: 0, dropped: 0, backlogged: 0 },
			});
			// Pruned before the fetch, and each pruned Welcome gave its key package
			// back through one client opened for the purpose.
			expect(openMlsClient).toHaveBeenCalledTimes(1);
			expect(discardWelcomeKeyPackage).toHaveBeenCalledTimes(2);
			expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(0);
		});
	});

	it("test_process_when_a_pass_aborted_after_spooling_then_the_next_pass_installs_every_welcome", async () => {
		// 🔴 The same thing end to end. The abort is the ordinary rethrow path: any
		// local failure that is not an unprocessable commit leaves the pass and
		// carries the whole batch into the next one, whose fetch is empty because
		// the server already handed the bytes over. MEASURED against the real core
		// with a whole-spool count bound: 32 installed, 4 permanently lost.
		const batch = ids(36).map((id, i) => ({
			...delivery(id),
			group_id: `c3d4e5f6-a7b8-9012-cdef-${String(i).padStart(12, "0")}`,
			created_at: "2026-01-01T00:00:00Z",
		}));
		vi.mocked(fetchWelcomes).mockResolvedValueOnce({
			welcomes: batch,
		} as never);
		vi.mocked(openMlsClient).mockImplementationOnce(() => {
			throw new Error("the store went away mid-pass");
		});

		await expect(processMlsWelcomes(dir, AGENT, client)).rejects.toThrow(
			"the store went away mid-pass",
		);
		expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(36);

		vi.mocked(openMlsClient).mockReturnValue({
			joinFromWelcome: () => fakeGroup(),
		} as never);
		const result = await processMlsWelcomes(dir, AGENT, client);

		expect(result.groupIds).toHaveLength(36);
		expect(result.groupIds).toEqual(batch.map((w) => w.group_id));
		expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(0);
	});

	it("test_process_when_a_welcome_is_refused_retryably_then_the_entry_joins_the_counted_set", async () => {
		// The mark is what makes the count bound reach a retained refusal at all,
		// and it is written by the pass, not by the spool.
		new WelcomeSpool(dir, AGENT).store(delivery(DELIVERY));
		vi.mocked(openMlsClient).mockReturnValue({
			joinFromWelcome: () => fakeGroup(),
		} as never);
		vi.mocked(welcomeRefusal).mockResolvedValue({
			groupId: GROUP_ID,
			reason: "roster_uncorroborated",
			code: "RINE_WELCOME_REFUSED",
		} as never);

		await expect(
			processMlsWelcomes(dir, AGENT, client, { forGroup: GROUP_ID }),
		).rejects.toMatchObject({ reason: "roster_uncorroborated" });

		// Kept — the bytes are the only copy — and now carrying the flag, so a
		// spool full of these is what the cap actually caps.
		expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(1);
		expect(
			JSON.parse(fs.readFileSync(spoolPath(DELIVERY), "utf-8")).refused,
		).toBe(true);
	});

	it("test_process_when_a_welcome_installs_then_its_key_package_is_not_given_back", async () => {
		new WelcomeSpool(dir, AGENT).store(delivery(DELIVERY));
		const discardWelcomeKeyPackage = vi.fn();
		vi.mocked(openMlsClient).mockReset();
		vi.mocked(openMlsClient).mockReturnValue({
			joinFromWelcome: () => fakeGroup(),
			discardWelcomeKeyPackage,
		} as never);

		const result = await processMlsWelcomes(dir, AGENT, client);

		expect(result.groupIds).toEqual([GROUP_ID]);
		expect(discardWelcomeKeyPackage).not.toHaveBeenCalled();
	});

	it("test_process_when_the_group_is_gone_then_the_welcome_gives_its_key_package_back", async () => {
		new WelcomeSpool(dir, AGENT).store(delivery(DELIVERY));
		const discardWelcomeKeyPackage = vi.fn();
		vi.mocked(openMlsClient).mockReset();
		vi.mocked(openMlsClient).mockReturnValue({ discardWelcomeKeyPackage } as never);
		const goneClient = {
			get: async () => {
				throw new RineApiError(404, "group not found");
			},
		} as never;

		const result = await processMlsWelcomes(dir, AGENT, goneClient);

		expect(result.discarded).toBe(1);
		expect(discardWelcomeKeyPackage).toHaveBeenCalledTimes(1);
		expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(0);
	});

	it("test_process_when_the_release_fails_then_the_pass_fails_and_the_welcome_stays", async () => {
		new WelcomeSpool(dir, AGENT).store(delivery(DELIVERY));
		vi.mocked(openMlsClient).mockReset();
		vi.mocked(openMlsClient).mockReturnValue({
			discardWelcomeKeyPackage: () => {
				throw Object.assign(new Error("store write failed"), { code: "RINE_MLS_STORE" });
			},
		} as never);
		const goneClient = {
			get: async () => {
				throw new RineApiError(404, "group not found");
			},
		} as never;

		await expect(processMlsWelcomes(dir, AGENT, goneClient)).rejects.toThrow(
			"store write failed",
		);

		expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(1);
	});

	it("test_process_when_a_blob_has_nothing_to_release_then_it_is_dropped_anyway", async () => {
		new WelcomeSpool(dir, AGENT).store(delivery(DELIVERY));
		vi.mocked(openMlsClient).mockReset();
		vi.mocked(openMlsClient).mockReturnValue({
			discardWelcomeKeyPackage: () => {
				throw Object.assign(new Error("not a welcome"), { code: "RINE_MLS_PROTOCOL" });
			},
		} as never);
		const goneClient = {
			get: async () => {
				throw new RineApiError(404, "group not found");
			},
		} as never;

		const result = await processMlsWelcomes(dir, AGENT, goneClient);

		expect(result.discarded).toBe(1);
		expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(0);
	});
});

describe("a join failure that is this process failing", () => {
	it("test_join_when_the_local_store_fails_then_it_is_not_reported_as_an_install", async () => {
		// The split `isUnprocessableCommit` exists for. A store write failure, a
		// contained panic and a poisoned handle are all THIS process failing, and
		// reporting one as an install replenishes key packages and hands the
		// caller a group id it does not hold — the more so because local state for
		// the group already exists, which is the branch that would swallow it.
		new WelcomeSpool(dir, AGENT).store(delivery(DELIVERY));
		vi.mocked(openMlsClient).mockReturnValue({
			joinFromWelcome: () => {
				throw Object.assign(new Error("store write failed"), {
					code: "RINE_MLS_STORE",
				});
			},
		} as never);
		vi.mocked(loadMlsGroup).mockReturnValue({} as never);

		await expect(processMlsWelcomes(dir, AGENT, client)).rejects.toThrow(
			"store write failed",
		);

		expect(mlsHeartbeat).not.toHaveBeenCalled();
		// Nothing final happened, so the bytes stay: the fetch was destructive and
		// the next attempt is the only way this Welcome ever installs.
		expect(new WelcomeSpool(dir, AGENT).pending()).toHaveLength(1);
	});
});
