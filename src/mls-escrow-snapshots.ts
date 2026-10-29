/**
 * The store of old-state snapshots a settle set aside for the sweep.
 *
 * A deferred drain leaves untaken exports only in the stored snapshot. When that
 * state is about to be wiped or replaced and no verified escrow key is at hand,
 * the settle cannot seal them (it may not wait on the network), so it copies the
 * snapshot here with the protection a live one has (a 0600 file in a 0700 dir):
 *   <mls store>/escrow-backlog/<group_id>/<epoch>.snapshot
 * A second state parked at an epoch that already has one is a different state
 * (a resync and a rejoin can land on the same epoch number), so it takes a
 * distinct name, `<epoch>-<8 hex>.snapshot`, rather than replace the first.
 * Beside each snapshot sits an advisory sidecar naming the epochs it held:
 *   <mls store>/escrow-backlog/<group_id>/<snapshot stem>.queued
 *
 * Reopening and sealing them is `mls-escrow-backlog.ts`. The Python twin is
 * `rine/_mls/escrow_backlog.py`.
 */
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { dirname, join } from "node:path";
import { linkExclusive } from "./config.js";
import { isPathSafeId, validatePathId } from "./crypto/keys.js";
import { mlsStoreRoot } from "./crypto/mls.js";
import { groupStatePath } from "./crypto/mls-store-probe.js";
import { fsyncDir, fsyncFile } from "./fsync.js";
import { clearQueued, writeQueued } from "./mls-escrow-queued.js";
import { clearAttempts } from "./mls-escrow-retry.js";

export const BACKLOG_DIR = "escrow-backlog";
const SNAPSHOT_SUFFIX = ".snapshot";
/** The prefix of a scratch store a reopened snapshot lives in. */
export const SCRATCH_PREFIX = ".open-";
/** The prefix of a snapshot copy that is not yet complete. */
const STAGE_PREFIX = ".stage-";
const SNAPSHOT_NAME_RE = /^(\d+)(?:-[0-9a-f]{8})?\.snapshot$/;

/** A scratch store or staged copy older than this belongs to a process that died. */
export const STALE_AFTER_S = 3600;

/** One parked snapshot: the group it belongs to, the epoch it was taken at, and where it is. */
export interface BacklogSnapshot {
	groupId: string;
	epoch: number;
	path: string;
}

export function backlogRoot(configDir: string, agentId: string): string {
	return join(mlsStoreRoot(configDir, agentId), BACKLOG_DIR);
}

/** Entries of a directory that are directories; empty when it cannot be read. */
function subdirs(path: string): fs.Dirent[] {
	try {
		return fs.readdirSync(path, { withFileTypes: true }).filter((e) => e.isDirectory());
	} catch {
		return [];
	}
}

function namesIn(path: string): string[] {
	try {
		return fs.readdirSync(path);
	} catch {
		return [];
	}
}

/**
 * Park the group's stored snapshot, taken at `epoch`, for the sweep, recording
 * how many exports were queued in it, how many were dropped and the fork
 * fingerprint of each queued export. The bytes go file to file, never through
 * this process's memory, and are on disk before this returns: the caller wipes
 * or replaces the stored state next.
 */
export function parkSnapshot(
	configDir: string,
	agentId: string,
	groupId: string,
	epoch: number,
	queued: number,
	dropped: number,
	forks: ReadonlyMap<number, Uint8Array> = new Map(),
): void {
	validatePathId(groupId, "group ID");
	const dir = join(backlogRoot(configDir, agentId), groupId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	const staged = join(dir, `${STAGE_PREFIX}${randomBytes(8).toString("hex")}`);
	try {
		fs.copyFileSync(
			groupStatePath(configDir, agentId, groupId),
			staged,
			fs.constants.COPYFILE_EXCL,
		);
		fs.chmodSync(staged, 0o600);
		fsyncFile(staged);
		const names = [
			`${epoch}${SNAPSHOT_SUFFIX}`,
			`${epoch}-${randomBytes(4).toString("hex")}${SNAPSHOT_SUFFIX}`,
		];
		const path = names.map((name) => join(dir, name)).find((candidate) => {
			return linkExclusive(staged, candidate);
		});
		if (path === undefined) {
			throw new Error(`no free snapshot name for group ${groupId} at epoch ${epoch}`);
		}
		try {
			writeQueued(path, epoch, queued, dropped, forks);
		} catch {
			// Advisory: a failed record must not undo the park.
		}
		fsyncDir(dir);
	} finally {
		fs.rmSync(staged, { force: true });
	}
}

/** Every parked snapshot of this agent, by (group, epoch). Scratch dirs and parked names are not listed. */
export function listSnapshots(configDir: string, agentId: string): BacklogSnapshot[] {
	const root = backlogRoot(configDir, agentId);
	const snapshots: BacklogSnapshot[] = [];
	for (const group of subdirs(root)) {
		if (!isPathSafeId(group.name)) continue;
		for (const name of namesIn(join(root, group.name))) {
			const match = SNAPSHOT_NAME_RE.exec(name);
			if (match === null) continue;
			snapshots.push({
				groupId: group.name,
				epoch: Number(match[1]),
				path: join(root, group.name, name),
			});
		}
	}
	return snapshots.sort(
		(a, b) =>
			a.groupId.localeCompare(b.groupId) ||
			a.epoch - b.epoch ||
			a.path.localeCompare(b.path),
	);
}

/** Delete a snapshot that was sealed, and its group dir once nothing else is in it. */
export function deleteSnapshot(snapshot: BacklogSnapshot): void {
	fs.rmSync(snapshot.path, { force: true });
	clearQueued(snapshot.path);
	clearAttempts(snapshot.path);
	try {
		fs.rmdirSync(dirname(snapshot.path));
	} catch {
		// Other snapshots, parked names or sidecars remain: the dir stays.
	}
}

function removeStale(path: string, nowS: number): void {
	try {
		if (nowS - fs.statSync(path).mtimeMs / 1000 >= STALE_AFTER_S) {
			fs.rmSync(path, { recursive: true, force: true });
		}
	} catch {
		// Gone already, or in use by a process that is still alive.
	}
}

/**
 * Remove the scratch stores and staged copies a killed process left behind, in
 * the backlog root and in every group dir. Only those older than
 * {@link STALE_AFTER_S}: a younger one may belong to a process that is working
 * on it now, and removing it would fail that process's pass.
 */
export function clearScratch(configDir: string, agentId: string, nowS: number): void {
	const root = backlogRoot(configDir, agentId);
	const dirs = [root, ...subdirs(root).map((d) => join(root, d.name))];
	for (const dir of dirs) {
		for (const name of namesIn(dir)) {
			if (name.startsWith(SCRATCH_PREFIX) || name.startsWith(STAGE_PREFIX)) {
				removeStale(join(dir, name), nowS);
			}
		}
	}
}
