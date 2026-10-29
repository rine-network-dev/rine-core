/**
 * Reading the gap markers ({@link ./mls-escrow-gap.js}) back: which of a group's
 * epochs have no escrow, and whether the fork a sender is on is one of them.
 */
import { bytesToHex } from "@noble/curves/utils.js";
import * as fs from "node:fs";
import { join } from "node:path";
import { type GapReason, asGapReason } from "./mls-escrow-gap.js";
import { parseGapName } from "./mls-escrow-gap-names.js";
import { groupPendingDir } from "./mls-escrow-pending.js";

/** A marker holds one reason, shorter than this, so a longer file names none and is never read past it. */
const MAX_MARKER_BYTES = 32;

/**
 * The reason a marker file holds. Only a regular file is read, and at most
 * {@link MAX_MARKER_BYTES} of it: a link, a pipe or a huge file planted under a
 * marker's name is skipped, never followed, waited on or loaded.
 */
function markerReason(path: string): GapReason | undefined {
	let fd: number;
	try {
		fd = fs.openSync(
			path,
			fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | fs.constants.O_NOFOLLOW,
		);
	} catch {
		return undefined;
	}
	try {
		if (!fs.fstatSync(fd).isFile()) return undefined;
		const buffer = Buffer.alloc(MAX_MARKER_BYTES);
		const length = fs.readSync(fd, buffer, 0, MAX_MARKER_BYTES, null);
		return asGapReason(buffer.toString("utf-8", 0, length));
	} catch {
		return undefined;
	} finally {
		fs.closeSync(fd);
	}
}

/** One readable marker of a group: the epoch and fork its name gives, and its reason. */
export interface GroupMarker {
	epoch: number;
	fork?: string;
	reason: GapReason;
}

/**
 * The readable markers in one group's pending dir, in name order. A torn file,
 * one whose text names no known reason and one whose name is not a marker's are
 * left out.
 */
export function groupMarkers(dir: string): GroupMarker[] {
	let names: string[];
	try {
		names = fs.readdirSync(dir).sort();
	} catch {
		return [];
	}
	const markers: GroupMarker[] = [];
	for (const name of names) {
		const parsed = parseGapName(name);
		const reason = parsed && markerReason(join(dir, name));
		if (parsed !== undefined && reason !== undefined) {
			markers.push({ ...parsed, reason });
		}
	}
	return markers;
}

/**
 * The recorded reason the fork `fp` of an epoch has no escrow, or `undefined`
 * when none is recorded or every marker that speaks for it holds text that is
 * not a reason.
 *
 * The fork's own marker and the fork-less one speak for it, the first in name
 * order; a marker of another fork never does. The native take files its gaps
 * fork-less, so dropping them would turn a permanent loss of the live epoch
 * into a retryable one.
 */
export function readGap(
	configDir: string,
	agentId: string,
	groupId: string,
	epoch: number,
	fp: Uint8Array,
): GapReason | undefined {
	const dir = groupPendingDir(configDir, agentId, groupId);
	const fork = bytesToHex(fp);
	return groupMarkers(dir).find(
		(marker) =>
			marker.epoch === epoch &&
			(marker.fork === undefined || marker.fork === fork),
	)?.reason;
}
