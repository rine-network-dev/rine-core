import * as fs from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-escrow-key.js", () => escrowKeyModule());

import { World } from "./crypto/world.js";
import { escrowKeyModule, withPeerReads } from "./mls-escrow-harness.js";
import { initMlsGroup, externalJoinMlsGroup, syncMlsGroup } from "../src/mls-ops.js";
import { decryptGroupMessage } from "../src/message-group.js";
import { encryptMlsGroupMessage } from "../src/message-mls.js";

// ── A minimal, stateful in-memory MLS Delivery Service ───────────────────────
// Models exactly the endpoints the orchestrators touch: mls/init, mls/commit,
// mls/group-info (latest), mls/handshakes (since epoch), and the group roster
// reads the admission path makes. No mocking of the crypto — this is a real
// external-join round-trip.

interface StoredObj { epoch: number; blob: string; }

class FakeMls {
	private groupInfo: StoredObj | null = null;
	private handshakes: StoredObj[] = [];
	private mlsGroupId: string | null = null;
	/** Epoch sent on the most recent non-init commit (exposed for assertions). */
	lastCommitEpoch: number | undefined;

	get = async (path: string): Promise<unknown> => {
		if (path.endsWith("/mls/group-info")) {
			return this.groupInfo
				? { group_info: this.groupInfo.blob, epoch: this.groupInfo.epoch }
				: { group_info: null, epoch: null };
		}
		if (path.includes("/mls/handshakes")) {
			const m = path.match(/since_epoch=(\d+)/);
			const since = m ? Number(m[1]) : 0;
			const items = this.handshakes.filter((h) => h.epoch > since);
			return {
				handshakes: items.map((h, i) => ({
					id: `h${i}`, epoch: h.epoch, blob: h.blob, created_at: "2026-01-01T00:00:00Z",
				})),
			};
		}
		// The admission path's outstanding-voucher read. The roster itself is
		// answered by `withPeerReads` from the world.
		if (path.endsWith("/requests")) return { items: [] };
		throw new Error(`FakeMls: unhandled GET ${path}`);
	};

	post = async (path: string, body?: unknown): Promise<unknown> => {
		if (path.endsWith("/mls/init")) {
			// Single-creator group: no other members to add.
			return { mls_pending: true, members: [] };
		}
		if (path.endsWith("/mls/commit")) {
			const b = body as { commit: string; group_info?: string; epoch?: number };
			const epoch = this.mlsGroupId === null ? 0 : (b.epoch ?? 0);
			if (this.mlsGroupId !== null) this.lastCommitEpoch = b.epoch;
			if (this.mlsGroupId === null) this.mlsGroupId = "mls-internal-id";
			this.handshakes.push({ epoch, blob: b.commit });
			if (b.group_info) this.groupInfo = { epoch, blob: b.group_info };
			return { epoch, delivered_to: 0 };
		}
		throw new Error(`FakeMls: unhandled POST ${path}`);
	};
}

const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-mls-extjoin-"));
}

describe("external join — full orchestrator round-trip", () => {
	let dir: string;
	const creatorId = "11111111-1111-4111-8111-111111111111";
	const joinerId = "22222222-2222-4222-8222-222222222222";

	beforeEach(() => {
		dir = makeTmpDir();
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("creator inits, joiner self-joins, member syncs, joiner sends, member decrypts", async () => {
		const world = new World();
		const creator = world.addAgent({ id: creatorId });
		const joiner = world.addAgent({ id: joinerId });
		world.save(dir, creator);
		world.save(dir, joiner);

		const server = new FakeMls();
		const client = withPeerReads(world, server) as never;

		// 1. Creator initializes the MLS group (publishes epoch-1 GroupInfo).
		await initMlsGroup(dir, creatorId, GROUP_ID, client);

		// 2. Joiner self-joins via external commit (no Welcome was ever minted).
		const joinResult = await externalJoinMlsGroup(dir, joinerId, GROUP_ID, client);
		expect(joinResult.epoch).toBeGreaterThan(0);
		// The external-join commit carried the crypto-owned epoch (epoch 2: the
		// init commit left the group at epoch 1, the external join advances it).
		expect(server.lastCommitEpoch).toBe(2);

		// 3. Existing member advances by syncing the external commit handshake.
		const sync = await syncMlsGroup(dir, creatorId, GROUP_ID, client);
		expect(sync.processed).toBeGreaterThan(0);

		// 4. Joiner sends an MLS app message; the member decrypts + verifies it.
		const enc = await encryptMlsGroupMessage(dir, joinerId, GROUP_ID, { hi: "there" });
		expect(enc.encryption_version).toBe("mls-v1");

		const dec = await decryptGroupMessage(
			dir,
			creatorId,
			GROUP_ID,
			enc.encrypted_payload,
			client,
			joinerId,
		);
		expect(JSON.parse(dec.plaintext)).toEqual({ hi: "there" });
		expect(dec.verified).toBe(true);
	});
});
