/**
 * The epochs a parked snapshot was holding, recorded beside it.
 *
 * A parked snapshot ({@link ./mls-escrow-snapshots.js}) holds the exports the
 * settle could not seal. When the snapshot can never be reopened, the epochs it
 * held are lost, and only the snapshot's own epoch is left to name them. So the
 * settle writes a small sidecar next to the snapshot, at park time, holding the
 * snapshot's epoch, how many exports were queued in it and how many older ones
 * the native queue had already dropped; the epochs are the last `queued`, ending
 * at the snapshot's epoch, and the `dropped` run just below them:
 *   escrow-backlog/<group_id>/<snapshot stem>.queued
 *       {"epoch": 41, "queued": 3, "dropped": 0}
 *
 * The sidecar also carries the fork fingerprint of each queued export, under
 * `fps`, so a give-up can file each lost epoch under the fork it held:
 *       {"epoch": 43, "queued": 3, "dropped": 0,
 *        "fps": {"41": "<32 hex>", "42": "<hex>", "43": "<hex>"}}
 * The `fps` key is present only when at least one fork is recorded. A fork
 * fingerprint is a domain-separated hash of the epoch authenticator, so the
 * sidecar still holds no secret material.
 *
 * The sidecar is advisory, and it is not trusted: one whose epoch is not the
 * snapshot's, or whose counts exceed what the native queue can hold, is ignored.
 * Without a usable one, the lost epochs are the epochs after the group's escrow
 * head through the snapshot's epoch, never more than the queue could have held.
 * The Python twin is `rine/_mls/escrow_queued.py`, with the same name and keys.
 */
import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import * as fs from "node:fs";
import { writeAtomic } from "./config.js";
import { readHead } from "./mls-escrow-head.js";
import { FP_HEX_RE } from "./mls-escrow-pending.js";

export const QUEUED_SUFFIX = ".queued";

/**
 * The native queue's caps: exports it holds, and older epochs it remembers as
 * dropped (mls-rs `MAX_QUEUED_EPOCH_READ_EXPORTS` and
 * `MAX_DROPPED_EPOCH_READ_EPOCHS`).
 */
export const MAX_QUEUED_EXPORTS = 32;
export const MAX_DROPPED_EPOCHS = 1024;

/** The sidecar path of a snapshot: its stem, with the snapshot extension replaced. */
function sidecarPath(snapshotPath: string): string {
	return `${snapshotPath.replace(/\.[^./\\]+$/, "")}${QUEUED_SUFFIX}`;
}

/**
 * Record how many exports the snapshot at `snapshotPath` held at `epoch`, how
 * many it dropped, and the fork fingerprint of each queued export.
 */
export function writeQueued(
	snapshotPath: string,
	epoch: number,
	queued: number,
	dropped: number,
	forks: ReadonlyMap<number, Uint8Array> = new Map(),
): void {
	const fps: Record<string, string> = {};
	for (const [forkEpoch, fp] of forks) fps[forkEpoch] = bytesToHex(fp);
	const body = { epoch, queued, dropped, ...(forks.size === 0 ? {} : { fps }) };
	writeAtomic(sidecarPath(snapshotPath), JSON.stringify(body));
}

/** Remove a snapshot's sidecar; missing is success. */
export function clearQueued(snapshotPath: string): void {
	fs.rmSync(sidecarPath(snapshotPath), { force: true });
}

/** A safe non-negative integer no larger than `max`. */
function isCountUpTo(value: unknown, max: number): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max;
}

/** The forks a sidecar's `fps` records, keeping only entries that name an epoch and a fingerprint. */
function readForks(value: unknown, snapshotEpoch: number): Map<number, Uint8Array> {
	const forks = new Map<number, Uint8Array>();
	if (typeof value !== "object" || value === null) return forks;
	for (const [key, hex] of Object.entries(value as Record<string, unknown>)) {
		const epoch = Number(key);
		if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > snapshotEpoch) continue;
		if (typeof hex !== "string" || !FP_HEX_RE.test(hex)) continue;
		forks.set(epoch, hexToBytes(hex));
	}
	return forks;
}

/**
 * What a usable sidecar records: the first epoch it names and the forks it
 * holds. `undefined` when it is absent, malformed or out of bounds.
 */
function readSidecar(
	snapshotPath: string,
	snapshotEpoch: number,
): { first: number; forks: Map<number, Uint8Array> } | undefined {
	try {
		const data = JSON.parse(fs.readFileSync(sidecarPath(snapshotPath), "utf-8")) as unknown;
		if (typeof data !== "object" || data === null) return undefined;
		const { epoch, queued, dropped = 0, fps } = data as Record<string, unknown>;
		if (epoch !== snapshotEpoch) return undefined;
		if (!isCountUpTo(queued, MAX_QUEUED_EXPORTS)) return undefined;
		if (!isCountUpTo(dropped, MAX_DROPPED_EPOCHS)) return undefined;
		const first = Math.max(0, snapshotEpoch - Math.max(queued, 1) - dropped + 1);
		return { first, forks: readForks(fps, snapshotEpoch) };
	} catch {
		return undefined;
	}
}

/** Every epoch from `first` through `last` inclusive, ascending. */
function epochRange(first: number, last: number): number[] {
	const epochs: number[] = [];
	for (let epoch = first; epoch <= last; epoch++) epochs.push(epoch);
	return epochs;
}

/**
 * The forks a usable sidecar records for the snapshot at `snapshotPath`, or an
 * empty map when it is absent, unusable or records none.
 */
export function recordedForks(
	snapshotPath: string,
	snapshotEpoch: number,
): ReadonlyMap<number, Uint8Array> {
	return readSidecar(snapshotPath, snapshotEpoch)?.forks ?? new Map();
}

/**
 * Every epoch an unreadable snapshot may have held; always includes its own
 * epoch, and at most the queue's caps below it. The sidecar's range when there
 * is a usable one. Otherwise the epochs after the group's escrow head, or, when
 * the head is at or past the snapshot (a rejoin moved the group on) the last
 * export-queue's worth; the snapshot's own epoch when the group has no head.
 */
export function lostEpochs(
	configDir: string,
	agentId: string,
	groupId: string,
	snapshotPath: string,
	snapshotEpoch: number,
): number[] {
	const recorded = readSidecar(snapshotPath, snapshotEpoch)?.first;
	if (recorded !== undefined) return epochRange(recorded, snapshotEpoch);
	const head = readHead(configDir, agentId, groupId);
	if (head === undefined) return [snapshotEpoch];
	const floor = Math.max(0, snapshotEpoch - MAX_QUEUED_EXPORTS - MAX_DROPPED_EPOCHS + 1);
	const afterHead = head.epoch < snapshotEpoch ? head.epoch + 1 : snapshotEpoch - MAX_QUEUED_EXPORTS + 1;
	return epochRange(Math.max(floor, afterHead, 0), snapshotEpoch);
}
