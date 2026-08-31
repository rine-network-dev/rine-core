/**
 * The recovery ladder, driven against the REAL native core.
 *
 * Only `crypto/mls-api.js` — the network — is mocked; every commit, Welcome and
 * GroupInfo here is a genuine blob the core produced, relayed between two real
 * agents. So a test fails when the resync names the wrong leaf, admits somebody,
 * or escalates to an O(N) commit a replay would have covered.
 *
 * The wedged agent is a Welcome joiner the group left behind — the stranded
 * cohort of a batched founding, which is the case the server's own refusal names
 * first. It is deliberately not the founder: the two differ in what their local
 * store holds, and that difference exposes a MEASURED limit in the native
 * core.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/crypto/mls-api.js")
	>("../src/crypto/mls-api.js");
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

import { generateAgentKeys, saveAgentKeys } from "../src/crypto/keys.js";
import {
	claimKeyPackages,
	claimKeyPackagesBatch,
	fetchGroupInfo,
	fetchHandshakes,
	fetchWelcomes,
	mlsCommit,
	mlsFromBase64,
	mlsInit,
	mlsToBase64,
} from "../src/crypto/mls-api.js";
import type { MlsCommitBody } from "../src/crypto/mls-api.js";
import { mlsGroupIdBytes, openMlsClient } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import {
	MLS_RESYNC_REQUIRED_CODE,
	MlsResyncUnavailableError,
	recoverMlsGroup,
} from "../src/mls-ops-resync.js";
import { initMlsGroup, processMlsWelcomes } from "../src/mls-ops.js";

/** The group's admin, and the only agent that commits on its behalf here. */
const FOUNDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
/** The agent that falls behind and runs the verb. */
const SELF_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const THIRD_ID = "d4e5f6a7-b8c9-0123-def1-234567890123";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

let dir: string;
/** Every commit body the code posted, in order. */
let posted: MlsCommitBody[];

const client = {
	get: async (path: string) => {
		if (path === "/agents/keys") return { keys: {} };
		if (path === `/groups/${GROUP_ID}`) return { member_count: 2 };
		if (path === `/groups/${GROUP_ID}/requests`) return { items: [] };
		throw new Error(`unexpected GET ${path}`);
	},
} as never;

function loadGroup(agentId: string) {
	return openMlsClient(dir, agentId).loadGroup(mlsGroupIdBytes(GROUP_ID));
}

/** Found GROUP_ID with FOUNDER as admin and SELF welcomed into it. */
async function foundGroup(): Promise<void> {
	const pkg = mlsToBase64(openMlsClient(dir, SELF_ID).generateKeyPackage());
	vi.mocked(claimKeyPackages).mockResolvedValue({
		packages: [pkg],
		agent_id: SELF_ID,
	});
	vi.mocked(claimKeyPackagesBatch).mockResolvedValue({
		claims: [{ agent_id: SELF_ID, packages: [pkg] }],
	});
	vi.mocked(mlsInit).mockResolvedValue({
		mls_pending: true,
		members: [
			{ agent_id: FOUNDER_ID, has_key_package: true },
			{ agent_id: SELF_ID, has_key_package: true },
		],
	});
	await initMlsGroup(dir, FOUNDER_ID, GROUP_ID, client);

	const welcome = posted.at(-1)?.welcomes?.[0]?.welcome;
	if (!welcome) throw new Error("founding commit carried no welcome");
	vi.mocked(fetchWelcomes).mockResolvedValue({
		welcomes: [
			{
				id: "w1",
				group_id: GROUP_ID,
				blob: welcome,
				created_at: "2026-01-01T00:00:00Z",
			},
		],
	});
	await processMlsWelcomes(dir, SELF_ID, client);
	vi.mocked(fetchWelcomes).mockResolvedValue({ welcomes: [] });
	posted = [];
}

/**
 * The admin advances the group by one real commit (adding THIRD), and the server
 * publishes the GroupInfo it produced. SELF is never told, so it is now stale.
 */
function adminAdvancesGroup(): { epoch: number; commit: string } {
	const third = openMlsClient(dir, THIRD_ID).generateKeyPackage();
	const admin = loadGroup(FOUNDER_ID);
	const bundle = admin.addMember(third);
	admin.save();
	const commit = mlsToBase64(bundle.commit);
	vi.mocked(fetchGroupInfo).mockResolvedValue({
		group_info: mlsToBase64(bundle.groupInfo),
		epoch: bundle.epoch,
	});
	return { epoch: bundle.epoch, commit };
}

/** Serve `commit` to the replay rung as the one handshake SELF is missing. */
function serveHandshake(commit: string, epoch: number): void {
	vi.mocked(fetchHandshakes).mockResolvedValue({
		handshakes: [
			{ id: "h1", epoch, blob: commit, created_at: "2026-01-01T00:00:00Z" },
		],
	});
}

/** The server's escalation signal: replay found nothing it could deliver. */
function refuseReplay(): void {
	vi.mocked(fetchHandshakes).mockRejectedValue(
		new RineApiError(
			409,
			"replay cannot help",
			undefined,
			MLS_RESYNC_REQUIRED_CODE,
		),
	);
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-mlsresync-"));
	posted = [];
	vi.clearAllMocks();
	vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => {
		posted.push(body);
		return { epoch: body.epoch ?? null, delivered_to: 1 };
	});
	vi.mocked(fetchHandshakes).mockResolvedValue({ handshakes: [] });
	vi.mocked(fetchWelcomes).mockResolvedValue({ welcomes: [] });
	vi.mocked(fetchGroupInfo).mockResolvedValue({
		group_info: null,
		epoch: null,
	});
	for (const id of [FOUNDER_ID, SELF_ID, THIRD_ID]) {
		saveAgentKeys(dir, id, generateAgentKeys());
	}
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("recoverMlsGroup — the cheap rung", () => {
	it("replays the commits it is behind on without posting one", async () => {
		await foundGroup();
		const staleEpoch = loadGroup(SELF_ID).epoch();
		const { epoch, commit } = adminAdvancesGroup();
		serveHandshake(commit, epoch);

		const result = await recoverMlsGroup(dir, SELF_ID, GROUP_ID, client);

		// The discriminant every consumer branches on. It is set on the rung's own
		// return and nowhere else, so a rung that forgot it would type-check at the
		// call site and reach a renderer as an unmatched arm.
		expect(result.regime).toBe("mls");
		expect(result.rung).toBe("replay");
		expect(result.processed).toBe(1);
		expect(result.fromEpoch).toBe(staleEpoch);
		expect(result.behind).toBe(epoch - staleEpoch);
		expect(result.epoch).toBe(epoch);
		expect(posted).toHaveLength(0);
	});

	it("does not escalate when the group advances while the replay runs", async () => {
		await foundGroup();
		const { epoch, commit } = adminAdvancesGroup();
		serveHandshake(commit, epoch);
		// The measurement read happens first and sees the epoch the replay can
		// actually reach; every later read reports a group that has moved on.
		vi.mocked(fetchGroupInfo).mockResolvedValueOnce({
			group_info: null,
			epoch,
		});
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: null,
			epoch: epoch + 5,
		});

		const result = await recoverMlsGroup(dir, SELF_ID, GROUP_ID, client);

		expect(result.rung).toBe("replay");
		expect(posted).toHaveLength(0);
	});
});

describe("recoverMlsGroup — the expensive rung", () => {
	it("resyncs on the server's refusal, in one commit that admits nobody", async () => {
		await foundGroup();
		const staleEpoch = loadGroup(SELF_ID).epoch();
		const staleLeaf = loadGroup(SELF_ID).currentMemberIndex();
		const { epoch } = adminAdvancesGroup();
		refuseReplay();

		const result = await recoverMlsGroup(dir, SELF_ID, GROUP_ID, client);

		expect(result.regime).toBe("mls");
		expect(result.rung).toBe("resync");
		expect(result.fromEpoch).toBe(staleEpoch);
		expect(result.behind).toBe(epoch - staleEpoch);
		expect(result.epoch).toBe(epoch + 1);
		// An external commit adds nobody, so it carries no Welcome.
		expect(posted).toHaveLength(1);
		expect(posted[0]?.welcomes).toEqual([]);
		expect(posted[0]?.group_info).toBeTruthy();
		// The same leaf, still seated exactly once.
		expect(loadGroup(SELF_ID).currentMemberIndex()).toBe(staleLeaf);
	});

	it("leaves the group's membership and this agent's leaf unchanged", async () => {
		await foundGroup();
		const staleLeaf = loadGroup(SELF_ID).currentMemberIndex();
		adminAdvancesGroup();
		const seatedBefore = loadGroup(FOUNDER_ID).memberIdentities().length;
		refuseReplay();

		await recoverMlsGroup(dir, SELF_ID, GROUP_ID, client);

		// The admin applies the resync commit like any other, and sees the same
		// tree it had: one identity, one leaf, and the count unmoved.
		const admin = loadGroup(FOUNDER_ID);
		const commit = posted[0]?.commit;
		if (!commit) throw new Error("the resync posted no commit");
		admin.applyCommit(mlsFromBase64(commit));
		const seats = admin.memberIdentities();
		expect(seats).toHaveLength(seatedBefore);
		expect(seats.filter((s) => s.index === staleLeaf)).toHaveLength(1);
	});

	it("escalates when a replay ran and left this agent short", async () => {
		await foundGroup();
		const staleEpoch = loadGroup(SELF_ID).epoch();
		const { epoch } = adminAdvancesGroup();
		// A 200 with nothing in it: the server answered, and the gap is still there.
		vi.mocked(fetchHandshakes).mockResolvedValue({ handshakes: [] });

		const result = await recoverMlsGroup(dir, SELF_ID, GROUP_ID, client);

		expect(result.rung).toBe("resync");
		expect(result.processed).toBe(0);
		expect(result.behind).toBe(epoch - staleEpoch);
		expect(posted).toHaveLength(1);
	});

	it("refuses when the group has published no GroupInfo to commit against", async () => {
		await foundGroup();
		refuseReplay();
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: null,
			epoch: 9,
		});

		await expect(
			recoverMlsGroup(dir, SELF_ID, GROUP_ID, client),
		).rejects.toThrow("published no GroupInfo");
		expect(posted).toHaveLength(0);
	});
});

describe("recoverMlsGroup — what it refuses", () => {
	it("refuses by name when local state will not load, and never joins instead", async () => {
		await expect(
			recoverMlsGroup(dir, SELF_ID, GROUP_ID, client),
		).rejects.toBeInstanceOf(MlsResyncUnavailableError);
		expect(posted).toHaveLength(0);
	});

	it("names the remedy an agent with no state actually has", async () => {
		const err = await recoverMlsGroup(dir, SELF_ID, GROUP_ID, client).catch(
			(e: unknown) => e,
		);
		expect((err as Error).message).toContain("remove this agent");
		expect((err as { code?: string }).code).toBe("mls_resync_unavailable");
	});

	it("surfaces a failure that is not the ladder's escalation signal", async () => {
		await foundGroup();
		vi.mocked(fetchHandshakes).mockRejectedValue(
			new RineApiError(503, "upstream down"),
		);

		await expect(
			recoverMlsGroup(dir, SELF_ID, GROUP_ID, client),
		).rejects.toThrow("upstream down");
		expect(posted).toHaveLength(0);
	});

	it("test_recovery_when_the_replay_hits_a_protocol_refusal_then_it_escalates", async () => {
		await foundGroup();
		adminAdvancesGroup();
		// The shape `syncMlsGroup`'s own orphan reconciliation produces for a
		// SEATED agent: it re-bootstraps with a plain external join, and MLS
		// refuses that for an agent the tree already holds (MEASURED).
		// Rethrown, the operator saw a protocol error naming a leaf they never
		// asked about; the rung that actually fixes it is the resync.
		vi.mocked(fetchHandshakes).mockRejectedValue(
			Object.assign(
				new Error(
					"duplicate signature key, hpke key or identity found at index 1",
				),
				{ code: "RINE_MLS_PROTOCOL" },
			),
		);

		const result = await recoverMlsGroup(dir, SELF_ID, GROUP_ID, client);

		expect(result.rung).toBe("resync");
		expect(posted).toHaveLength(1);
	});

	it("test_recovery_when_the_replay_fails_locally_then_nothing_is_committed", async () => {
		await foundGroup();
		adminAdvancesGroup();
		// A store failure is THIS process's problem. Billing every member an O(N)
		// commit for an unwritable disk would be a self-inflicted denial of
		// service, so it is surfaced rather than escalated.
		vi.mocked(fetchHandshakes).mockRejectedValue(
			Object.assign(new Error("state store is unwritable"), {
				code: "RINE_MLS_STORE",
			}),
		);

		await expect(
			recoverMlsGroup(dir, SELF_ID, GROUP_ID, client),
		).rejects.toThrow("state store is unwritable");
		expect(posted).toHaveLength(0);
	});

	it("test_recovery_when_the_resync_is_refused_then_the_message_names_the_remedy", async () => {
		await foundGroup();
		refuseReplay();
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: null,
			epoch: 9,
		});

		const err = await recoverMlsGroup(dir, SELF_ID, GROUP_ID, client).catch(
			(e: unknown) => e,
		);

		// The operator gets the group, the rung and the remedy, not an
		// mls-rs sentence about a protocol state.
		const message = (err as Error).message;
		expect(message).toContain(GROUP_ID);
		expect(message).toContain("resync rung");
		expect(message).toContain("invite it again");
		// The core's own text is kept, last, so a bug report still carries it.
		expect(message).toContain("published no GroupInfo");
	});
});
