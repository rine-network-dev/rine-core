/**
 * The escrow bytes an agent has sealed but not yet uploaded.
 *
 * The native group hands its escrow exports over exactly once —
 * `takeEscrowExports()` — and they survive only until the next `group.save()`,
 * so the sealed bytes are written here before anything else touches them: a
 * crash between the take and the save re-yields them, a crash after the save
 * would lose them.
 *
 * Only the sealed bytes are stored. The uploader signature is deliberately NOT
 * kept: the server answers 422 when `key_gen` is not the uploader's CURRENT
 * generation, so a signature minted before a key rotation is dead on arrival.
 * Recomputing it at upload time is what keeps a file sealed before a rotation
 * uploadable.
 *
 * A pending file stays until it is uploaded or given up for good: a give-up
 * files a gap marker naming the loss and deletes the file after it, through
 * `giveUpPending` in `mls-escrow-gap.ts`. The newest drained epoch is remembered
 * apart, in `mls-escrow-head.ts`.
 *
 * Layout under `mlsStoreRoot(configDir, agentId)`:
 *   escrow-pending/<group_id>/<epoch>-<fp hex>.bin   sealed bytes, 0600
 */

import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { join } from "node:path";
import { isPathSafeId, validatePathId } from "./crypto/keys.js";
import { linkExclusive } from "./config.js";
import { fsyncDir, fsyncFile } from "./fsync.js";
import { mlsStoreRoot } from "./crypto/mls.js";
import { clearAttempts } from "./mls-escrow-retry.js";

/** One sealed escrow waiting for upload, keyed by its slot. */
export interface PendingEscrow {
	groupId: string;
	epoch: number;
	fp: Uint8Array;
	sealed: Uint8Array;
}

export const PENDING_DIR = "escrow-pending";
const PENDING_SUFFIX = ".bin";
export const FP_HEX_LENGTH = 32;
/** A fork fingerprint as the disk names and sidecars record it: 32 lowercase hex. */
export const FP_HEX_RE = new RegExp(`^[0-9a-f]{${FP_HEX_LENGTH}}$`);
/**
 * An epoch as the escrow file names spell it: ASCII digits with no leading zero
 * and at most 15 of them, so every epoch is exact as a number and has exactly
 * one name. One capturing group, for embedding in a file-name pattern.
 */
export const EPOCH_NAME_PATTERN = "(0|[1-9][0-9]{0,14})";
/** `<epoch>-<32 hex>.bin` — the only name {@link listPending} will read back. */
const PENDING_NAME_RE = new RegExp(
	`^${EPOCH_NAME_PATTERN}-([0-9a-f]{${FP_HEX_LENGTH}})\\.bin$`,
);

/** `<mls store>/escrow-pending` — the parent of every group's pending dir. */
function pendingRoot(configDir: string, agentId: string): string {
	return join(mlsStoreRoot(configDir, agentId), PENDING_DIR);
}

/** The dir holding one group's pending escrows. Validates the id before joining. */
export function groupPendingDir(
	configDir: string,
	agentId: string,
	groupId: string,
): string {
	validatePathId(groupId, "group ID");
	return join(pendingRoot(configDir, agentId), groupId);
}

/** The file name a pending escrow is filed under. */
function pendingName(pending: PendingEscrow): string {
	return `${pending.epoch}-${bytesToHex(pending.fp)}${PENDING_SUFFIX}`;
}

/**
 * Persist one sealed escrow. A slot that already has a file is left untouched.
 *
 * The first sealing of a slot wins: sealing is randomised, so a second file for
 * the same slot would differ and the server answers 409 to a different row. The
 * file is put in place by `linkExclusive`, which never replaces an existing one,
 * so two processes sharing the config dir cannot overwrite each other's sealing.
 * It holds the sealed bytes alone; the signature is recomputed at upload time
 * under the uploader's current key generation. The data and the
 * entry are on disk before this returns, because the state the bytes came from
 * is deleted next.
 */
export function writePending(
	configDir: string,
	agentId: string,
	pending: PendingEscrow,
): void {
	const dir = groupPendingDir(configDir, agentId, pending.groupId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	const path = join(dir, pendingName(pending));
	const tmp = `${path}.${randomBytes(8).toString("hex")}.tmp`;
	fs.writeFileSync(tmp, pending.sealed, { mode: 0o600, flag: "wx" });
	try {
		fsyncFile(tmp);
		if (linkExclusive(tmp, path)) fsyncDir(dir);
	} finally {
		fs.rmSync(tmp, { force: true });
	}
}

/**
 * The group dirs under the pending root: only lower-case canonical UUIDs, which
 * are the names this module writes. A link to a directory is not one.
 */
function groupDirs(root: string): string[] {
	try {
		return fs
			.readdirSync(root, { withFileTypes: true })
			.filter(
				(entry) =>
					entry.isDirectory() &&
					isPathSafeId(entry.name) &&
					entry.name === entry.name.toLowerCase(),
			)
			.map((entry) => entry.name);
	} catch {
		return [];
	}
}

/** Every group dir the agent has under its pending root, whatever files it holds. */
export function pendingGroupDirs(configDir: string, agentId: string): string[] {
	return groupDirs(pendingRoot(configDir, agentId));
}

/**
 * The groups that hold at least one pending file, found from file names alone:
 * no file is read, so a sweep can ask this cheaply on every drain.
 */
export function pendingGroupIds(configDir: string, agentId: string): string[] {
	const root = pendingRoot(configDir, agentId);
	return groupDirs(root).filter((groupId) => {
		try {
			return fs
				.readdirSync(join(root, groupId))
				.some((name) => PENDING_NAME_RE.test(name));
		} catch {
			return false;
		}
	});
}

/**
 * Every pending escrow for this agent (or for one group), sorted by (groupId, epoch).
 *
 * A missing dir is `[]`. `*.tmp` files and names that do not parse as
 * `<epoch>-<32 hex>.bin`, the epoch spelled as {@link EPOCH_NAME_PATTERN} has
 * it, are ignored: the first is a write in flight, the second is not something
 * this module wrote.
 */
export function listPending(
	configDir: string,
	agentId: string,
	groupId?: string,
): PendingEscrow[] {
	const root = pendingRoot(configDir, agentId);
	let groupIds: string[];
	if (groupId !== undefined) {
		groupIds = [groupId];
		groupPendingDir(configDir, agentId, groupId);
	} else {
		groupIds = groupDirs(root);
	}

	const pending: PendingEscrow[] = [];
	for (const groupId of groupIds) {
		const dir = join(root, groupId);
		let names: string[];
		try {
			names = fs.readdirSync(dir);
		} catch {
			// Gone between the readdir and this one: nothing left to list.
			continue;
		}
		for (const name of names) {
			const match = PENDING_NAME_RE.exec(name);
			if (match === null) continue;
			try {
				pending.push({
					groupId,
					epoch: Number(match[1]),
					fp: hexToBytes(match[2] as string),
					// Copy out of the Buffer so callers get a plain Uint8Array view.
					sealed: new Uint8Array(fs.readFileSync(join(dir, name))),
				});
			} catch {
				// Unreadable between the readdir and the read: skip it rather than
				// fail the whole drain on one torn file.
			}
		}
	}

	return pending.sort(
		(a, b) =>
			a.groupId.localeCompare(b.groupId) ||
			a.epoch - b.epoch ||
			bytesToHex(a.fp).localeCompare(bytesToHex(b.fp)),
	);
}

/** The path one pending escrow is filed under. */
export function pendingPath(
	configDir: string,
	agentId: string,
	pending: PendingEscrow,
): string {
	return join(
		groupPendingDir(configDir, agentId, pending.groupId),
		pendingName(pending),
	);
}

/** Drop a pending escrow once its upload has a final outcome. Missing is success. */
export function deletePending(
	configDir: string,
	agentId: string,
	pending: PendingEscrow,
): void {
	const path = pendingPath(configDir, agentId, pending);
	fs.rmSync(path, { force: true });
	clearAttempts(path);
}
