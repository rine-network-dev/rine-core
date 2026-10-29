/**
 * A refusal names ONE group, and a read of another group must survive it.
 *
 * `decryptGroupMessage`'s recovery installs pending Welcomes before it retries,
 * and the batch it installs is the whole queue — so a substituted Welcome for
 * some unrelated group used to abort the decrypt of a message in a group the
 * refusal had nothing to do with. The Python read path scoped that call; this
 * one did not, and the asymmetry is the finding.
 *
 * Real MLS on both sides: the honest group is founded by a real founder, the
 * substituted one by a second real client playing the server, and only HTTP is
 * faked. The message under test is a real `mls-v1` ciphertext the reader has no
 * state for until the recovery runs.
 */
import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentKeysResponse } from "../../src/api-types.js";
import { mlsToBase64 } from "../../src/crypto/mls-api.js";
import { decryptGroupMessage } from "../../src/message-group.js";
import { encryptMlsGroupMessage } from "../../src/message-mls.js";
import {
	loadMlsGroup,
	mlsGroupIdBytes,
	openMlsClient,
} from "../../src/crypto/mls.js";
import { resetProcessGates } from "../../src/process-gate.js";
import { World } from "./world.js";

const FOUNDER = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const READER = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
const IMPOSTOR = "cccccccc-3333-4333-8333-cccccccccccc";
const OTHER_FOUNDER = "dddddddd-4444-4444-8444-dddddddddddd";
/** The group the reader is honestly in, and whose message is being read. */
const READ_GROUP = "11111111-5555-4555-8555-111111111111";
/** The group a substituted Welcome claims to be, which this read is not about. */
const OTHER_GROUP = "22222222-6666-4666-8666-222222222222";
const TEXT = "a message in a group the refusal is not about";

let dir: string;
let world: World;
let welcomes: { id: string; group_id: string; blob: string }[];

/** Agent ids `GET /groups/{id}/members` reports, per group. */
const members = new Map<string, string[]>();

/** The batch `GET /agents/keys` serves, built from the world's own responses. */
function publishedKeys(ids: string[]) {
	const keys: Record<string, AgentKeysResponse> = {};
	for (const id of ids) {
		const generations = world.agents.get(id);
		const newest = generations?.[generations.length - 1];
		if (newest) keys[id] = newest.response;
	}
	return { keys };
}

function server() {
	const base = world.client();
	return {
		get: vi.fn(
			async (
				path: string,
				params?: Record<string, string | number | boolean>,
			) => {
				if (path === `/agents/${READER}/mls/welcomes`) {
					// The real route marks every welcome it returns consumed in the same
					// transaction, so the fetch is one-shot and the queue drains here too.
					const batch = welcomes;
					welcomes = [];
					return { welcomes: batch };
				}
				if (path === "/agents/keys") {
					return publishedKeys(String(params?.["ids"]).split(","));
				}
				if (path.endsWith("/mls/handshakes")) return { handshakes: [] };
				const groupId = path.split("/")[2] ?? "";
				if (path.endsWith("/members")) {
					return {
						items: (members.get(groupId) ?? []).map((agent_id) => ({
							agent_id,
						})),
					};
				}
				if (path.endsWith("/requests")) return { items: [] };
				return base.get(path, params);
			},
		),
		post: vi.fn(async () => ({ stored: 1 })),
	};
}

beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-welcome-scope-"));
	world = new World();
	welcomes = [];
	members.clear();
	for (const id of [FOUNDER, READER, IMPOSTOR, OTHER_FOUNDER]) {
		world.save(dir, world.addAgent({ id }));
	}
	resetProcessGates();
});
afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
	resetProcessGates();
});

/** Found `groupId` on `founderId`, seat the reader, and file the Welcome. */
function seat(founderId: string, groupId: string): void {
	const keyPackage = openMlsClient(dir, READER).generateKeyPackage();
	const group = openMlsClient(dir, founderId).createGroupWithMembers(
		mlsGroupIdBytes(groupId),
		[keyPackage],
	);
	const welcome = group.lastCommit()?.welcomes[0];
	if (!welcome) throw new Error(`founding ${groupId} minted no welcome`);
	group.save();
	welcomes.push({
		id: randomUUID(),
		group_id: groupId,
		blob: mlsToBase64(welcome),
	});
}

describe("recovering a read while another group's welcome is refused", () => {
	it("test_read_when_another_groups_welcome_is_refused_then_this_group_still_reads", async () => {
		// READ_GROUP is honest: its roster names the founder whose identity holds
		// a leaf in the tree, so its Welcome corroborates and installs.
		seat(FOUNDER, READ_GROUP);
		members.set(READ_GROUP, [FOUNDER, READER]);
		// OTHER_GROUP is the substitution: the server founded it, and the roster
		// names an agent no leaf in that tree belongs to.
		seat(IMPOSTOR, OTHER_GROUP);
		members.set(OTHER_GROUP, [OTHER_FOUNDER, READER]);
		const { encrypted_payload } = await encryptMlsGroupMessage(
			dir,
			FOUNDER,
			READ_GROUP,
			{ text: TEXT },
		);

		const result = await decryptGroupMessage(
			dir,
			READER,
			READ_GROUP,
			encrypted_payload,
			server() as never,
			FOUNDER,
		);

		expect(JSON.parse(result.plaintext)).toEqual({ text: TEXT });
		// The refusal did happen — it is not that the guard let the substitution
		// through — and the substituted group holds no state.
		expect(loadMlsGroup(openMlsClient(dir, READER), OTHER_GROUP)).toBeNull();
	});

	it("test_read_when_this_groups_welcome_is_refused_then_the_refusal_reaches_the_caller", async () => {
		// The other direction, and why the scoping is a filter rather than a
		// blanket catch: a refusal FOR the group being read must still surface.
		seat(IMPOSTOR, READ_GROUP);
		members.set(READ_GROUP, [FOUNDER, READER]);
		const { encrypted_payload } = await encryptMlsGroupMessage(
			dir,
			IMPOSTOR,
			READ_GROUP,
			{ text: TEXT },
		);

		await expect(
			decryptGroupMessage(
				dir,
				READER,
				READ_GROUP,
				encrypted_payload,
				server() as never,
				IMPOSTOR,
			),
		).rejects.toThrow(/Refusing the MLS welcome/);
	});
});
