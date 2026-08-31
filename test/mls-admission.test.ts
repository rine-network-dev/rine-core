/**
 * Batched admission, driven against the REAL native core.
 *
 * Only the server is faked: `crypto/mls-api.js` stands in for the MLS routes and
 * a stub `HttpClient` answers the three reads the admission path makes on its
 * own — who already holds a leaf (`GET /agents/keys`), how many members the
 * group has, and which invitations are still outstanding. Every commit, Welcome
 * and ratchet-tree fact is genuine, so a test here fails when a batch is sized
 * wrong, a KeyPackage is spent that should not have been, or a resume re-seats
 * somebody who is already in the tree.
 */
import * as fs from "node:fs";
import { randomUUID } from "node:crypto";
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
		claimKeyPackagesBatch: vi.fn(async () => ({ claims: [] })),
		mlsInit: vi.fn(async () => ({ mls_pending: true, members: [] })),
		mlsCommit: vi.fn(async () => ({ epoch: null, delivered_to: 1 })),
		mlsAck: vi.fn(async () => ({ confirmed: true, acks: 1, needed: 1 })),
		mlsNack: vi.fn(async () => ({ quarantined: true })),
		fetchHandshakes: vi.fn(async () => ({ handshakes: [] })),
		fetchGroupInfo: vi.fn(async () => ({ group_info: null, epoch: null })),
	};
});

import {
	agentKeysExist,
	generateAgentKeys,
	saveAgentKeys,
	signingPublicKeyToJWK,
} from "../src/crypto/keys.js";
import {
	claimKeyPackagesBatch,
	fetchHandshakes,
	mlsCommit,
	mlsInit,
	mlsToBase64,
} from "../src/crypto/mls-api.js";
import type { MlsCommitBody } from "../src/crypto/mls-api.js";
import {
	mlsGroupIdBytes,
	openMlsClient,
	openMlsGroup,
} from "../src/crypto/mls.js";
import { RineApiError, rineErrorFromResponse } from "../src/errors.js";
import type { MlsAdmissionResult } from "../src/mls-ops.js";
import {
	addMlsGroupMembers,
	fetchMlsIdentities,
	initMlsGroup,
	isSeated,
	processMlsWelcomes,
	removeMlsGroupMember,
	resumeMlsGroupAdmission,
} from "../src/mls-ops.js";

const SELF_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

/** Welcome entries one commit may carry — `MLS_WELCOMES_PER_COMMIT_MAX`. */
const SERVER_WELCOMES_PER_COMMIT_MAX = 32;

let dir: string;
/** Every commit body the server accepted, in order. */
let posted: MlsCommitBody[];
/** Agents holding a claimable KeyPackage. */
let pool: Set<string>;
/** What `GET /groups/{id}/requests?outstanding=live` reports. */
let invited: string[];
let pending: string[];
/**
 * Agents a member nominated: `pending` like a self-application, and carrying an
 * inviter. On `majority` and `unanimity` an invite files one of these instead of
 * minting a voucher, so `invited_by` no longer tells an invitation from a
 * request awaiting a vote.
 */
let nominated: string[];
let members: string[];
let client: never;

/** An agent with keys on disk and one claimable KeyPackage. */
function agent(): string {
	const agentId = randomUUID();
	saveAgentKeys(dir, agentId, generateAgentKeys());
	pool.add(agentId);
	return agentId;
}

function agents(count: number): string[] {
	return Array.from({ length: count }, () => agent());
}

/** The published signing keys `GET /agents/keys` would return for `ids`. */
function publishedKeys(ids: string[]) {
	const keys: Record<string, unknown> = {};
	for (const id of ids) {
		if (!agentKeysExist(dir, id)) continue;
		// The MLS basic-credential identity is the agent's raw Ed25519 key.
		const jwk = signingPublicKeyToJWK(openMlsClient(dir, id).publicKey());
		keys[id] = { signing_public_key: jwk, encryption_public_key: jwk };
	}
	return keys;
}

/** The Welcomes an admission minted for `agentId`, as the server would hold them. */
function welcomesFor(agentId: string) {
	return posted.flatMap((body, commit) =>
		(body.welcomes ?? [])
			.filter((entry) => entry.agent_id.toLowerCase() === agentId.toLowerCase())
			.map((entry) => ({
				id: `w${commit}`,
				group_id: GROUP_ID,
				blob: entry.welcome,
				created_at: "2026-01-01T00:00:00Z",
			})),
	);
}

/** SELF's own group state, founded locally — no HTTP, so no replenishment. */
function seedGroup(): void {
	openMlsClient(dir, SELF_ID).createGroup(mlsGroupIdBytes(GROUP_ID)).save();
}

/** The 422 the server sends when a commit names recipients it may not address. */
async function recipientRejection(agentIds: string[]): Promise<RineApiError> {
	// Built from the wire body through the client's own error path, so this
	// covers the seam a hand-made `RineApiError` would hide: the `rejected`
	// array has to survive parsing before a batch can drop anybody.
	const body = {
		error: "welcome_recipient_rejected",
		detail: `${agentIds.length} of this commit's Welcome recipients cannot be addressed.`,
		rejected: agentIds.map((agent_id) => ({
			agent_id,
			reason: "not_enrolled",
		})),
	};
	return rineErrorFromResponse(
		new Response(JSON.stringify(body), {
			status: 422,
			headers: { "content-type": "application/json" },
		}),
	);
}

/** The stub client's reads, as `[path, params, headers]` tuples. */
function reads(): unknown[][] {
	return (client as unknown as { get: ReturnType<typeof vi.fn> }).get.mock
		.calls;
}

/** Every agent id a claim was made for, in claim order. */
function claimedIds(): string[] {
	return vi.mocked(claimKeyPackagesBatch).mock.calls.flatMap((call) => call[1]);
}

function outcomeFor(result: MlsAdmissionResult, agentId: string) {
	return result.outcomes.find((outcome) => outcome.agentId === agentId);
}

/** Accept every commit, recording its body. */
function acceptCommits(): void {
	vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => {
		posted.push(body);
		return { epoch: body.epoch ?? null, delivered_to: 1 };
	});
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-admission-"));
	posted = [];
	pool = new Set();
	invited = [];
	pending = [];
	nominated = [];
	members = [SELF_ID];
	vi.clearAllMocks();
	saveAgentKeys(dir, SELF_ID, generateAgentKeys());
	acceptCommits();
	vi.mocked(claimKeyPackagesBatch).mockImplementation(async (_c, ids) => ({
		claims: ids.map((agent_id) => ({
			agent_id,
			packages: pool.has(agent_id)
				? [mlsToBase64(openMlsClient(dir, agent_id).generateKeyPackage())]
				: [],
		})),
	}));
	client = {
		get: vi.fn(async (path: string, params?: Record<string, string>) => {
			if (path === "/agents/keys") {
				return { keys: publishedKeys(String(params?.ids).split(",")) };
			}
			// An invitee's own Welcome inbox, so a test can turn one of them into a
			// real peer that holds real state and can post a real commit.
			const joiner = /^\/agents\/([^/]+)\/mls\/welcomes$/.exec(path);
			if (joiner) return { welcomes: welcomesFor(joiner[1] as string) };
			if (path === `/groups/${GROUP_ID}/members`) {
				// The server answers with the member ROWS. A resume needs the ids,
				// not just a count: a member can hold no leaf (their add commit was
				// refused, then they joined on the voucher), and no other verb can
				// seat them.
				return { items: members.map((agent_id) => ({ agent_id })) };
			}
			if (path === `/groups/${GROUP_ID}/requests`) {
				// `?outstanding=live` is ("pending", "invited"), and the rows carry
				// the `status`/`invited_by` that tell an admin's invitation from a
				// stranger's self-application. Emitting `agent_id` alone cannot
				// express the difference the client has to act on.
				//
				// Three row kinds, because the server writes three: on a majority or
				// unanimity group an invite files a `pending` row that carries an
				// inviter, so the inviter alone no longer says whether a row may be
				// admitted. A fixture that emits only the first two agrees with a
				// client keying the admit set off `invited_by`.
				return {
					items: [
						...invited.map((agent_id) => ({
							agent_id,
							status: "invited",
							invited_by: SELF_ID,
						})),
						...pending.map((agent_id) => ({
							agent_id,
							status: "pending",
							invited_by: null,
						})),
						...nominated.map((agent_id) => ({
							agent_id,
							status: "pending",
							invited_by: SELF_ID,
						})),
					],
				};
			}
			throw new Error(`unexpected GET ${path}`);
		}),
	} as never;
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("initMlsGroup", () => {
	it("founds through the batched loop and reports one outcome per member, in order", async () => {
		const [ready, unready] = agents(2);
		pool.delete(unready!);
		vi.mocked(mlsInit).mockResolvedValue({
			mls_pending: true,
			members: [
				{ agent_id: SELF_ID, has_key_package: true },
				{ agent_id: unready!, has_key_package: false },
				{ agent_id: ready!, has_key_package: true },
			],
		});

		const result = await initMlsGroup(dir, SELF_ID, GROUP_ID, client);

		expect(result).toMatchObject({ epoch: 1, commits: 1, added: 1 });
		expect(result.outcomes).toEqual([
			{ agentId: SELF_ID, status: "skipped", reason: "already_in_group" },
			{ agentId: unready!, status: "skipped", reason: "no_key_package" },
			{ agentId: ready!, status: "added" },
		]);
		// An agent the server already said has no key package is never claimed for.
		expect(claimedIds()).toEqual([ready!]);
	});

	it("re-mints the founding commit without a recipient the server rejected", async () => {
		const [first, bad] = agents(2);
		vi.mocked(mlsInit).mockResolvedValue({
			mls_pending: true,
			members: [
				{ agent_id: SELF_ID, has_key_package: true },
				{ agent_id: first!, has_key_package: true },
				{ agent_id: bad!, has_key_package: true },
			],
		});
		vi.mocked(mlsCommit).mockRejectedValueOnce(
			await recipientRejection([bad!]),
		);

		const result = await initMlsGroup(dir, SELF_ID, GROUP_ID, client);

		expect(result).toMatchObject({ commits: 1, added: 1, epoch: 1 });
		expect(outcomeFor(result, bad!)?.reason).toBe("rejected_by_server");
		expect(posted[0]?.welcomes?.map((w) => w.agent_id)).toEqual([first!]);
	});
});

describe("addMlsGroupMembers", () => {
	it("claims key packages one batch at a time, so a refused commit does not burn the whole roster", async () => {
		seedGroup();
		const roster = agents(20);
		// A tree this size takes two members per commit, so the refusal below is
		// the fifth commit of ten rather than the only one. The occupancy comes
		// from the member ROWS, not from `member_count`: these ids are only ever
		// counted here, never resolved to an identity, because this call names
		// the agents it is seating rather than reading them from the tree.
		members = Array.from({ length: 900 }, () => randomUUID());
		let commits = 0;
		vi.mocked(mlsCommit).mockImplementation(async (_c, _g, body) => {
			commits += 1;
			if (commits === 5) throw new RineApiError(500, "server exploded");
			posted.push(body);
			return { epoch: body.epoch ?? null, delivered_to: 1 };
		});

		await expect(
			addMlsGroupMembers(dir, SELF_ID, GROUP_ID, roster, client),
		).rejects.toThrow("server exploded");

		expect(claimedIds()).toEqual(roster.slice(0, 10));
		// The ten roster entries past the refused batch still hold their
		// one-time key packages.
		expect(claimedIds().length).toBeLessThanOrEqual(
			8 + SERVER_WELCOMES_PER_COMMIT_MAX,
		);
	});

	it("drops the recipient a 422 names, retries the batch once, and adds the rest", async () => {
		seedGroup();
		const [first, bad, last] = agents(3);
		vi.mocked(mlsCommit).mockRejectedValueOnce(
			await recipientRejection([bad!]),
		);

		const result = await addMlsGroupMembers(
			dir,
			SELF_ID,
			GROUP_ID,
			[first!, bad!, last!],
			client,
		);

		expect(result.added).toBe(2);
		expect(outcomeFor(result, bad!)).toEqual({
			agentId: bad!,
			status: "skipped",
			reason: "rejected_by_server",
		});
		expect(mlsCommit).toHaveBeenCalledTimes(2);
		expect(posted[0]?.welcomes?.map((w) => w.agent_id)).toEqual([
			first!,
			last!,
		]);
	});

	it("retries at most once, and reports whoever is left rather than looping", async () => {
		seedGroup();
		const [first, bad, worse] = agents(3);
		vi.mocked(mlsCommit)
			.mockRejectedValueOnce(await recipientRejection([bad!]))
			.mockRejectedValueOnce(await recipientRejection([worse!]));

		const result = await addMlsGroupMembers(
			dir,
			SELF_ID,
			GROUP_ID,
			[first!, bad!, worse!],
			client,
		);

		expect(mlsCommit).toHaveBeenCalledTimes(2);
		expect(result).toMatchObject({ added: 0, commits: 0 });
		expect(result.outcomes.map((o) => o.reason)).toEqual([
			"rejected_by_server",
			"rejected_by_server",
			"rejected_by_server",
		]);
	});

	it("records the whole batch when the refusal names nobody it can read", async () => {
		seedGroup();
		const roster = agents(2);
		// What `parseError` produces before it retains the parsed body: the
		// rejection is unreadable, so no recipient can be singled out.
		vi.mocked(mlsCommit).mockRejectedValueOnce(
			new RineApiError(
				422,
				"recipients cannot be addressed",
				undefined,
				"welcome_recipient_rejected",
			),
		);

		const result = await addMlsGroupMembers(
			dir,
			SELF_ID,
			GROUP_ID,
			roster,
			client,
		);

		expect(mlsCommit).toHaveBeenCalledTimes(1);
		expect(
			result.outcomes.every((o) => o.reason === "rejected_by_server"),
		).toBe(true);
	});

	it("surfaces a failure that is not about recipients", async () => {
		seedGroup();
		vi.mocked(mlsCommit).mockRejectedValue(
			new RineApiError(409, "stale epoch", undefined, "epoch_conflict"),
		);
		await expect(
			addMlsGroupMembers(dir, SELF_ID, GROUP_ID, agents(1), client),
		).rejects.toThrow("stale epoch");
	});

	it("prices the tree only when there is more than one member to seat", async () => {
		seedGroup();
		await addMlsGroupMembers(dir, SELF_ID, GROUP_ID, agents(1), client);

		expect(reads().map((call) => call[0])).toEqual(["/agents/keys"]);
	});
});

describe("resumeMlsGroupAdmission", () => {
	it("seats every outstanding invitation, and seats nobody the second time", async () => {
		seedGroup();
		invited = agents(3);

		const first = await resumeMlsGroupAdmission(dir, SELF_ID, GROUP_ID, client);

		expect(first).toMatchObject({ added: 3, commits: 1 });
		// The invited set is read from the server, and only ever as `live`.
		expect(reads()).toContainEqual([
			`/groups/${GROUP_ID}/requests`,
			{ outstanding: "live" },
			undefined,
		]);

		const second = await resumeMlsGroupAdmission(
			dir,
			SELF_ID,
			GROUP_ID,
			client,
		);

		expect(second).toMatchObject({ added: 0, commits: 0 });
		// Four, not three: the acting admin is a member, so a resume names it
		// among the candidates and reports it like any already-seated id. The
		// contract promises one outcome per requested id.
		expect(second.outcomes).toHaveLength(4);
		expect(outcomeFor(second, SELF_ID)?.reason).toBe("already_in_group");
		expect(second.outcomes.every((o) => o.reason === "already_in_group")).toBe(
			true,
		);
		// The second pass spends no one-time key packages either.
		expect(claimedIds()).toEqual(invited);
	});

	it("seats the invitees who published a key package and names the ones who did not", async () => {
		seedGroup();
		const ready = agent();
		const unready = agent();
		pool.delete(unready);
		invited = [ready, unready];

		const result = await resumeMlsGroupAdmission(
			dir,
			SELF_ID,
			GROUP_ID,
			client,
		);

		expect(result.added).toBe(1);
		expect(outcomeFor(result, unready)?.reason).toBe("no_key_package");
	});

	it("refuses to resume a group this agent holds no state for", async () => {
		await expect(
			resumeMlsGroupAdmission(dir, SELF_ID, GROUP_ID, client),
		).rejects.toThrow(`No MLS state for group ${GROUP_ID}`);
	});

	it("never seats a pending applicant who is still awaiting a vote", async () => {
		// `?outstanding=live` is ("pending", "invited"), so the set that SIZES
		// the tree is wider than the set that may be ADMITTED. A pending row is
		// a stranger's self-application (`invited_by` null); Welcoming one hands
		// the group's epoch secret to an agent the vote may then deny, and no
		// route ever seats a denied applicant, so nothing would reclaim the leaf
		// it consumed. The server refuses to offer them to `/mls/init` for
		// exactly this reason — a client must not re-open it from the far end.
		seedGroup();
		const invitee = agent();
		const stranger = agent();
		invited = [invitee];
		pending = [stranger];

		const result = await resumeMlsGroupAdmission(
			dir,
			SELF_ID,
			GROUP_ID,
			client,
		);

		expect(result.added).toBe(1);
		expect(outcomeFor(result, invitee)?.status).toBe("added");
		expect(outcomeFor(result, stranger)).toBeUndefined();
		// And their one-time KeyPackage is not spent on the way past, either.
		expect(claimedIds()).not.toContain(stranger);
	});

	it("never seats an agent a member nominated, because the vote has not answered it", async () => {
		// The row an invite writes on a majority or unanimity group: still
		// `pending`, and now carrying an inviter. So `invited_by` no longer tells an
		// invitation from a request awaiting a vote, and a resume keying the admit
		// set off the inviter Welcomes a nominee into the ratchet tree before the
		// electorate has answered. The vote seats the member, and seating is what
		// grants the group's keys — so until it carries there is nothing here to
		// admit.
		seedGroup();
		const invitee = agent();
		const nominee = agent();
		invited = [invitee];
		nominated = [nominee];

		const result = await resumeMlsGroupAdmission(
			dir,
			SELF_ID,
			GROUP_ID,
			client,
		);

		expect(result.added).toBe(1);
		expect(outcomeFor(result, invitee)?.status).toBe("added");
		expect(outcomeFor(result, nominee)).toBeUndefined();
		expect(claimedIds()).not.toContain(nominee);
		// And no Welcome was minted for them: the commit that seated the invitee
		// names one recipient, not two.
		expect(posted.at(-1)?.welcomes?.map((w) => w.agent_id)).toEqual([invitee]);
	});

	it("seats a member who holds no leaf, which no other verb can reach", async () => {
		// An invitee whose add commit was refused still joins on their voucher,
		// which RESOLVES it — so they leave the invited set and enter the member
		// set having never been seated. `invite` refuses them as
		// `already_a_member`, so a resume that read invitations alone would
		// report `added: 0` and call that success.
		seedGroup();
		const stranded = agent();
		members = [SELF_ID, stranded];
		invited = [];

		const result = await resumeMlsGroupAdmission(
			dir,
			SELF_ID,
			GROUP_ID,
			client,
		);

		expect(result.added).toBe(1);
		expect(outcomeFor(result, stranded)?.status).toBe("added");
	});
});

describe("removeMlsGroupMember", () => {
	/** Found GROUP_ID with `count` members, seated in the order returned. */
	async function foundWithMembers(count: number): Promise<string[]> {
		const joiners = agents(count);
		vi.mocked(mlsInit).mockResolvedValue({
			mls_pending: true,
			members: [SELF_ID, ...joiners].map((agent_id) => ({
				agent_id,
				has_key_package: true,
			})),
		});
		await initMlsGroup(dir, SELF_ID, GROUP_ID, client);
		vi.mocked(mlsCommit).mockClear();
		return joiners;
	}

	/** An agent's MLS basic-credential identity, for asking whether it is seated.
	 * `removeMlsGroupMember` resolves its own — it names agents, never leaves. */
	async function identityOf(agentId: string): Promise<Uint8Array> {
		const identity = (await fetchMlsIdentities(client, [agentId])).get(
			agentId.toLowerCase(),
		);
		if (!identity) throw new Error(`no published identity for ${agentId}`);
		return identity;
	}

	/** Is this identity still in SELF's ratchet tree? */
	function seated(identity: Uint8Array): boolean {
		return isSeated(openMlsGroup(dir, SELF_ID, GROUP_ID), identity);
	}

	function conflict(): RineApiError {
		return new RineApiError(409, "stale epoch", undefined, "epoch_conflict");
	}

	it("takes the leaf of the agent it was given, and leaves every other leaf alone", async () => {
		const [first, second] = await foundWithMembers(2);
		const target = await identityOf(second as string);
		const bystander = await identityOf(first as string);

		await removeMlsGroupMember(
			dir,
			SELF_ID,
			GROUP_ID,
			second as string,
			client,
		);

		expect(seated(target)).toBe(false);
		expect(seated(bystander)).toBe(true);
	});

	it("declares the agent it was given on every commit it posts", async () => {
		const [member] = await foundWithMembers(1);

		await removeMlsGroupMember(
			dir,
			SELF_ID,
			GROUP_ID,
			member as string,
			client,
		);

		// The DELETE spends this declaration, and only this one. A
		// commit that names nobody authorises no removal at all.
		expect(posted.at(-1)?.removes).toEqual([member]);
	});

	it("commits a path-only rescue for an agent that holds no leaf", async () => {
		// The stranger stands in for the stranded case — a target whose
		// leaf the group no longer holds. It still earns a commit at the current
		// epoch declaring it, because that is the only thing that can unwedge a
		// member row whose Remove landed and whose DELETE did not.
		await foundWithMembers(1);
		const stranger = agent();

		const result = await removeMlsGroupMember(
			dir,
			SELF_ID,
			GROUP_ID,
			stranger,
			client,
		);

		expect(result).toEqual({ epoch: 2, removedLeaf: false });
		expect(posted.at(-1)?.removes).toEqual([stranger]);
		expect(posted.at(-1)?.welcomes).toEqual([]);
	});

	it("retries a Remove that lost the epoch CAS and reports the epoch it landed at", async () => {
		const [member] = await foundWithMembers(1);
		vi.mocked(mlsCommit).mockRejectedValueOnce(conflict());

		const result = await removeMlsGroupMember(
			dir,
			SELF_ID,
			GROUP_ID,
			member as string,
			client,
		);

		expect(result).toEqual({ epoch: 2, removedLeaf: true });
		expect(mlsCommit).toHaveBeenCalledTimes(2);
	});

	it("re-reads the leaf after a lost CAS, so the retry cannot evict whoever inherited it", async () => {
		// The race: the commit that won the CAS took the target's leaf,
		// and the retry rebuilt the Remove from the index resolved before it. A
		// leaf index is only true of the epoch it was read at.
		const [target, bystander] = await foundWithMembers(2);
		const targetIdentity = await identityOf(target as string);
		const bystanderIdentity = await identityOf(bystander as string);

		// A peer removes the target first — a real commit, applied for real by the
		// sync the retry runs. The bystander installs its Welcome so it holds
		// genuine state to commit from.
		await processMlsWelcomes(dir, bystander as string, client);
		const peer = openMlsGroup(dir, bystander as string, GROUP_ID);
		const peerRemove = peer.removeMember(peer.memberIndex(targetIdentity));
		peer.save();
		vi.mocked(fetchHandshakes).mockResolvedValueOnce({
			handshakes: [
				{
					id: randomUUID(),
					epoch: 2,
					blob: mlsToBase64(peerRemove.commit),
					created_at: new Date().toISOString(),
				},
			],
		});
		vi.mocked(mlsCommit).mockRejectedValueOnce(conflict());

		const result = await removeMlsGroupMember(
			dir,
			SELF_ID,
			GROUP_ID,
			target as string,
			client,
		);

		// Nothing left to remove: the peer's commit already took the leaf. So the
		// retry is the stranded-removal rescue — a path-only commit that declares the
		// target, which is what lets the admin's DELETE finally land. The
		// bystander, who now holds the highest leaf, keeps it.
		expect(result?.removedLeaf).toBe(false);
		expect(posted.at(-1)?.removes).toEqual([target]);
		expect(seated(targetIdentity)).toBe(false);
		expect(seated(bystanderIdentity)).toBe(true);
	});

	it("surfaces a second conflict rather than looping", async () => {
		const [member] = await foundWithMembers(1);
		vi.mocked(mlsCommit).mockRejectedValue(conflict());

		await expect(
			removeMlsGroupMember(dir, SELF_ID, GROUP_ID, member as string, client),
		).rejects.toThrow("after one");
		expect(mlsCommit).toHaveBeenCalledTimes(2);
	});

	it("does not retry a refusal that is not an epoch conflict", async () => {
		const [member] = await foundWithMembers(1);
		vi.mocked(mlsCommit).mockRejectedValue(
			new RineApiError(403, "not an admin", undefined, "forbidden"),
		);

		await expect(
			removeMlsGroupMember(dir, SELF_ID, GROUP_ID, member as string, client),
		).rejects.toThrow("not an admin");
		expect(mlsCommit).toHaveBeenCalledTimes(1);
	});
});
