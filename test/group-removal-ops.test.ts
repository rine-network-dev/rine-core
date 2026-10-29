/**
 * The removal mechanism, tested where it now lives.
 *
 * `deleteGroupMember` and `retireLocalGroupState` moved out of the CLI into
 * rine-core, and with them the assertions that used to live in
 * `rine-cli/test/group-wave2.test.ts`. They cannot stay there: the CLI consumes
 * rine-core as a bundle, so a spy on the package export binding no longer
 * reaches a call this module makes through its own relative import. Here the
 * primitives are `vi.mock`-able, and the CLI keeps only "the command calls the
 * core verb with these arguments and renders what it returns".
 *
 * The load-bearing one is `names the epoch as a QUERY parameter`:
 * `mls_removal_epoch` is a query parameter, and a body-encoded one binds `None`
 * server-side so every cross-org removal 409s claiming no commit was posted.
 * Spliced into the path it also becomes a literal no route matches, which is
 * invisible to the client⇄server contract gate. Nothing else in the TypeScript
 * stack asserts the placement.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-ops-removal.js", () => ({
	removeMlsGroupMember: vi.fn(),
}));
vi.mock("../src/crypto/keys.js", async () => {
	const actual = await vi.importActual<typeof import("../src/crypto/keys.js")>(
		"../src/crypto/keys.js",
	);
	return { ...actual, agentKeysExist: vi.fn(() => true) };
});
vi.mock("../src/crypto/mls-state.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/crypto/mls-state.js")
	>("../src/crypto/mls-state.js");
	return { ...actual, deleteMlsState: vi.fn() };
});
vi.mock("../src/sender-key-ops.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/sender-key-ops.js")
	>("../src/sender-key-ops.js");
	return { ...actual, deleteSenderKey: vi.fn() };
});
vi.mock("../src/crypto/group-read-cache.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/crypto/group-read-cache.js")
	>("../src/crypto/group-read-cache.js");
	return { ...actual, deleteGroupReadCache: vi.fn() };
});

import type { GroupRead } from "../src/api-types.js";
import { deleteGroupReadCache } from "../src/crypto/group-read-cache.js";
import { agentKeysExist } from "../src/crypto/keys.js";
import { deleteMlsState } from "../src/crypto/mls-state.js";
import { MLS_CIPHER_SUITE_XWING } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import {
	deleteGroupMember,
	evictionMessage,
	retireLocalGroupState,
	retirementMessage,
} from "../src/group-removal-ops.js";
import type { HttpClient } from "../src/http.js";
import { emptyReport } from "../src/mls-escrow-report.js";
import { removeMlsGroupMember } from "../src/mls-ops-removal.js";
import { deleteSenderKey } from "../src/sender-key-ops.js";

const CONFIG_DIR = "/tmp/test-rine-core-removal";
const GROUP_ID = "88888888-8888-8888-8888-888888888888";
const ADMIN_ID = "11111111-1111-1111-1111-111111111111";
const ALICE = "22222222-2222-2222-2222-222222222222";

function group(overrides: Partial<GroupRead> = {}): GroupRead {
	return {
		id: GROUP_ID,
		name: "standup",
		handle: "#standup@acme.rine.network",
		description: null,
		enrollment_policy: "closed",
		visibility: "private",
		isolated: false,
		vote_duration_hours: 24,
		member_count: 1,
		created_at: "2026-08-01T00:00:00Z",
		mls_enabled: true,
		mls_group_id: "mls-latch-abc",
		mls_pending: false,
		mls_cipher_suite: MLS_CIPHER_SUITE_XWING,
		...overrides,
	} as GroupRead;
}

const OPEN_GROUP = group({
	enrollment_policy: "open",
	visibility: "public",
	mls_enabled: false,
	mls_group_id: null,
	mls_cipher_suite: null,
});

/** Every DELETE the verb made, as `(path, extraHeaders, params)`. */
type DeleteCall = [
	string,
	Record<string, string> | undefined,
	Record<string, string | number | boolean> | undefined,
];

function stubClient(refusals: number): {
	client: HttpClient;
	deletes: DeleteCall[];
} {
	const deletes: DeleteCall[] = [];
	let refused = 0;
	const client = {
		delete: (
			path: string,
			extraHeaders?: Record<string, string>,
			params?: Record<string, string | number | boolean>,
		) => {
			deletes.push([path, extraHeaders, params]);
			if (refused < refusals) {
				refused += 1;
				return Promise.reject(
					new RineApiError(
						409,
						"refused",
						undefined,
						"mls_removal_commit_required",
					),
				);
			}
			return Promise.resolve(undefined);
		},
	} as unknown as HttpClient;
	return { client, deletes };
}

beforeEach(() => {
	vi.mocked(removeMlsGroupMember).mockReset();
	vi.mocked(agentKeysExist).mockReset().mockReturnValue(true);
	vi.mocked(deleteMlsState).mockReset();
	vi.mocked(deleteSenderKey).mockReset();
	vi.mocked(deleteGroupReadCache).mockReset();
});

describe("deleteGroupMember — the DELETE goes first, the commit only when asked", () => {
	it("posts no commit when the server accepts the removal", async () => {
		const { client, deletes } = stubClient(0);

		const removal = await deleteGroupMember(
			client,
			CONFIG_DIR,
			GROUP_ID,
			ALICE,
			async () => ADMIN_ID,
			{ "X-Rine-Agent": ADMIN_ID },
		);

		expect(removal).toBeNull();
		expect(removeMlsGroupMember).not.toHaveBeenCalled();
		expect(deletes).toEqual([
			[
				`/groups/${GROUP_ID}/members/${ALICE}`,
				{ "X-Rine-Agent": ADMIN_ID },
				undefined,
			],
		]);
	});

	it("posts the Remove commit and repeats the DELETE naming the epoch it landed at", async () => {
		vi.mocked(removeMlsGroupMember).mockResolvedValue({
			epoch: 7,
			removedLeaf: true,
			escrow: emptyReport(),
		});
		const { client, deletes } = stubClient(1);

		const removal = await deleteGroupMember(
			client,
			CONFIG_DIR,
			GROUP_ID,
			ALICE,
			async () => ADMIN_ID,
			{ "X-Rine-Agent": ADMIN_ID },
		);

		// The target is named by its AGENT ID: the core re-resolves the leaf on
		// every attempt, so a retry after a lost epoch CAS cannot evict whoever
		// inherited the seat, and the id it declares can never be a
		// different member from the leaf it takes.
		expect(removeMlsGroupMember).toHaveBeenCalledWith(
			CONFIG_DIR,
			ADMIN_ID,
			GROUP_ID,
			ALICE,
			client,
			{ "X-Rine-Agent": ADMIN_ID },
		);
		expect(removal).toEqual({
			epoch: 7,
			removedLeaf: true,
			escrow: emptyReport(),
		});
		expect(deletes).toHaveLength(2);
	});

	it("names the epoch as a QUERY parameter, never in the path and never in a body", async () => {
		vi.mocked(removeMlsGroupMember).mockResolvedValue({
			epoch: 7,
			removedLeaf: true,
			escrow: emptyReport(),
		});
		const { client, deletes } = stubClient(1);

		await deleteGroupMember(
			client,
			CONFIG_DIR,
			GROUP_ID,
			ALICE,
			async () => ADMIN_ID,
		);

		// 🔴 Body-encoded it binds None server-side and the removal is then
		// refused for want of the commit that was just posted; spliced into the
		// path it matches no route and hides from the contract gate.
		expect(deletes).toHaveLength(2);
		const [path, , params] = deletes[1] as DeleteCall;
		expect(path).toBe(`/groups/${GROUP_ID}/members/${ALICE}`);
		expect(path).not.toContain("?");
		expect(params).toEqual({ mls_removal_epoch: 7 });
	});

	it("completes a removal stranded by a failed DELETE, and never claims a leaf went", async () => {
		// The first attempt's Remove commit landed and its DELETE
		// did not, so the leaf is already out of the tree. Before the rescue the
		// client threw here — it could derive an epoch only from a commit it could
		// no longer make — and the member row was stuck for good.
		vi.mocked(removeMlsGroupMember).mockResolvedValue({
			epoch: 9,
			removedLeaf: false,
			escrow: emptyReport(),
		});
		const { client, deletes } = stubClient(1);

		const removal = await deleteGroupMember(
			client,
			CONFIG_DIR,
			GROUP_ID,
			ALICE,
			async () => ADMIN_ID,
		);

		expect(deletes).toHaveLength(2);
		expect((deletes[1] as DeleteCall)[2]).toEqual({ mls_removal_epoch: 9 });
		expect(removal).toEqual({
			epoch: 9,
			removedLeaf: false,
			escrow: emptyReport(),
		});
	});

	it("resolves the acting admin only on the path that needs a commit", async () => {
		const resolve = vi.fn(async () => ADMIN_ID);
		const { client } = stubClient(0);

		await deleteGroupMember(client, CONFIG_DIR, GROUP_ID, ALICE, resolve);

		// A kick from a multi-agent org without `--as` still works on every group
		// that does not need a commit.
		expect(resolve).not.toHaveBeenCalled();
	});

	it("rethrows a refusal that is not a request for a commit", async () => {
		const client = {
			delete: () =>
				Promise.reject(
					new RineApiError(403, "forbidden", undefined, "forbidden"),
				),
		} as unknown as HttpClient;

		await expect(
			deleteGroupMember(
				client,
				CONFIG_DIR,
				GROUP_ID,
				ALICE,
				async () => ADMIN_ID,
			),
		).rejects.toThrow("forbidden");
		expect(removeMlsGroupMember).not.toHaveBeenCalled();
	});

	it("rethrows the request for a commit when no admin resolver was given", async () => {
		// A self-leave passes none: MLS gives nobody a way to commit their own
		// removal, so the server's refusal is passed through unchanged.
		const { client } = stubClient(1);

		await expect(
			deleteGroupMember(client, CONFIG_DIR, GROUP_ID, ALICE, undefined, {
				"X-Rine-Agent": ALICE,
			}),
		).rejects.toThrow("refused");
		expect(removeMlsGroupMember).not.toHaveBeenCalled();
	});
});

describe("retireLocalGroupState — both retirements run, and a failure is reported", () => {
	it("retires MLS state, sender-key material and the read cache on every leave", async () => {
		const wipe = retireLocalGroupState(CONFIG_DIR, ADMIN_ID, GROUP_ID);

		expect(wipe).toEqual({ retired: true });
		expect(deleteMlsState).toHaveBeenCalledWith(CONFIG_DIR, ADMIN_ID, GROUP_ID);
		// The wipe that did not exist before, on the surface that
		// claimed for a year that it had happened.
		expect(deleteSenderKey).toHaveBeenCalledWith(
			CONFIG_DIR,
			ADMIN_ID,
			GROUP_ID,
		);
		// A re-read buffer that outlived the wipe would make "this group's
		// messages no longer open" false.
		expect(deleteGroupReadCache).toHaveBeenCalledWith(
			CONFIG_DIR,
			ADMIN_ID,
			GROUP_ID,
		);
	});

	it("does nothing when this agent holds no keys at all", () => {
		vi.mocked(agentKeysExist).mockReturnValue(false);

		expect(retireLocalGroupState(CONFIG_DIR, ADMIN_ID, GROUP_ID)).toEqual({
			retired: false,
		});
		expect(deleteMlsState).not.toHaveBeenCalled();
	});

	it("does not claim a wipe that failed", () => {
		vi.mocked(deleteMlsState).mockImplementation(() => {
			throw new Error("EACCES");
		});

		const wipe = retireLocalGroupState(CONFIG_DIR, ADMIN_ID, GROUP_ID);

		expect(wipe.retired).toBe(false);
		expect(wipe.error).toContain("NOT removed and is still on disk");
		expect(wipe.error).toContain("EACCES");
	});
});

describe("the sentences say what happened, per group type", () => {
	it("tells a closed group's leaver that MLS state is gone", () => {
		expect(retirementMessage(group(), false)).toContain(
			"Local MLS state for this group is gone",
		);
	});

	it("tells an open group's leaver what actually bounds their reach", () => {
		const text = retirementMessage(OPEN_GROUP, false);
		expect(text).toContain("Local sender-key material for this group is gone");
		expect(text).toContain("rotating on their next send");
		// The sentence this replaces was false in both halves on an open group.
		expect(text).not.toContain("rejoining the group is the only way back in");
	});

	it("tells a never-founded group's leaver about the keys they actually held", () => {
		// Closed, created to run MLS, tree never founded. It reads as an MLS group
		// in every column an operator sees, but nobody holds MLS state for a tree
		// nobody founded — what this agent had was sender keys, and the MLS
		// sentence would promise a wipe of state that was never there.
		const text = retirementMessage(
			group({ mls_group_id: null, mls_cipher_suite: null }),
			false,
		);

		expect(text).toContain("Local sender-key material for this group is gone");
		// The clause that had to move with this arm: it used to say "an open group
		// has none", and this group is not open.
		expect(text).toContain("a group with no ratchet tree has none");
		expect(text).not.toContain("Local MLS state");
	});

	it("keeps the MLS sentence for a group still founding its tree", () => {
		// 🔴 The neighbour that must NOT move. An init in flight has no latch
		// either, but the leaving agent may already hold MLS state for it, so the
		// wipe really did take MLS material and the MLS sentence is the true one.
		expect(
			retirementMessage(group({ mls_group_id: null, mls_pending: true }), false),
		).toContain("Local MLS state for this group is gone");
	});

	it("falls back to what the agent held when the group could not be read", () => {
		expect(retirementMessage(null, true)).toContain("Local MLS state");
		expect(retirementMessage(null, false)).toContain("sender-key material");
	});

	it("reports a leaf that went, and never claims one that did not", () => {
		expect(
			evictionMessage(group(), {
				epoch: 7,
				removedLeaf: true,
				escrow: emptyReport(),
			}),
		).toContain("took their leaf out");
		const stranded = evictionMessage(group(), {
			epoch: 9,
			removedLeaf: false,
			escrow: emptyReport(),
		});
		expect(stranded).toContain("no leaf in this group's ratchet tree is theirs");
		expect(stranded).not.toContain("rotated");
		expect(stranded).not.toContain("took their leaf out");
	});

	it("says a group with no ratchet tree has no cryptographic eviction", () => {
		// No page may imply parity between the two group types on removal.
		expect(evictionMessage(OPEN_GROUP, null)).toContain(
			"A group with no ratchet tree has no cryptographic eviction",
		);
	});

	it("does not tell a closed group's evictee that the group is open", () => {
		// 🔴 The sibling of the retirement sentence above, and it kept the wording
		// that one had already lost: `!groupIsMls` is true of a CLOSED group
		// created to run MLS whose tree was never founded, and of a closed group
		// created without MLS, and both were told "An open group has no
		// cryptographic eviction" — a false statement about who can join the
		// group, in front of the member being removed from it.
		const neverFounded = evictionMessage(
			group({ mls_group_id: null, mls_cipher_suite: null }),
			null,
		);

		expect(neverFounded).toContain("no cryptographic eviction");
		expect(neverFounded).not.toContain("An open group");
		expect(evictionMessage(OPEN_GROUP, null)).not.toContain("An open group");
	});

	it("keeps the ratchet-tree sentence for a group still founding one", () => {
		// The neighbour that must not move, on this verb too: an init in flight
		// has no latch, and the delivery-filter sentence would be wrong about how
		// removal works there. `regime` puts it on the MLS side; the latch alone
		// did not.
		expect(
			evictionMessage(group({ mls_group_id: null, mls_pending: true }), null),
		).toBe(
			"This group asked for no Remove commit, so nothing was taken out of its ratchet tree.",
		);
	});

	it("says nothing about a group it could not read", () => {
		expect(evictionMessage(null, null)).toBe("");
	});
});
