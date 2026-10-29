/**
 * Reopening a parked snapshot ({@link ./mls-escrow-snapshots.js}) as a group, in
 * a scratch store that never touches the live one.
 */
import * as fs from "node:fs";
import { dirname, join } from "node:path";
import { type MlsGroup, loadMlsGroup, openMlsClient } from "./crypto/mls.js";
import { groupStatePathIn } from "./crypto/mls-store-probe.js";
import { type PeerActor, allowedFor } from "./mls-allowed.js";
import {
	type BacklogSnapshot,
	SCRATCH_PREFIX,
	backlogRoot,
} from "./mls-escrow-snapshots.js";

/** A parked snapshot whose state the native core cannot read. */
export class SnapshotUnreadableError extends Error {
	constructor(groupId: string) {
		super(`backlog snapshot for group ${groupId} holds no state`);
		this.name = "SnapshotUnreadableError";
	}
}

/**
 * Open a parked snapshot as a group in a scratch store and hand it to `use`.
 * The scratch store never touches the live one, and is removed whatever `use` does.
 */
export function withSnapshotGroup<T>(
	actor: PeerActor,
	snapshot: BacklogSnapshot,
	use: (group: MlsGroup) => T,
): T {
	const root = backlogRoot(actor.configDir, actor.agentId);
	fs.mkdirSync(root, { recursive: true, mode: 0o700 });
	const scratch = fs.mkdtempSync(join(root, SCRATCH_PREFIX));
	try {
		const state = groupStatePathIn(scratch, snapshot.groupId);
		fs.mkdirSync(dirname(state), { recursive: true, mode: 0o700 });
		fs.copyFileSync(snapshot.path, state);
		fs.chmodSync(state, 0o600);
		const client = openMlsClient(actor.configDir, actor.agentId, {
			allowed: allowedFor(actor.configDir, actor.agentId),
			storeRoot: scratch,
		});
		const group = loadMlsGroup(client, snapshot.groupId);
		if (group === null) {
			throw new SnapshotUnreadableError(snapshot.groupId);
		}
		return use(group);
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
}

/** Whether a failure is this machine's (disk full, permissions) and not the snapshot's. */
export function isLocalIoFailure(error: unknown): boolean {
	const code = (error as NodeJS.ErrnoException | undefined)?.code;
	return typeof code === "string" && /^E[A-Z0-9]+$/.test(code);
}
