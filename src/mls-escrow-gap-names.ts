/**
 * The file names of the gap markers ({@link ./mls-escrow-gap.js}): one codec for
 * writing a name and reading one back.
 */
import { bytesToHex } from "@noble/curves/utils.js";
import { join } from "node:path";
import {
	EPOCH_NAME_PATTERN,
	FP_HEX_LENGTH,
	groupPendingDir,
} from "./mls-escrow-pending.js";

const GAP_SUFFIX = ".gap";

/**
 * `<epoch>.gap` (no known fork) or `<epoch>-<32 hex>.gap` (one fork). The epoch
 * grammar and the hex length are shared with the pending file names, so a
 * marker and the file it describes name the same epoch and fork the same way,
 * and an epoch reads the same as in the Python twin.
 */
export const GAP_NAME_RE = new RegExp(
	`^${EPOCH_NAME_PATTERN}(?:-([0-9a-f]{${FP_HEX_LENGTH}}))?\\.gap$`,
);

/** The epoch and fork (32 hex, when the name has one) a marker's file name stands for. */
export function parseGapName(
	name: string,
): { epoch: number; fork?: string } | undefined {
	const match = GAP_NAME_RE.exec(name);
	if (match === null) return undefined;
	const epoch = Number(match[1]);
	return match[2] === undefined ? { epoch } : { epoch, fork: match[2] };
}

/** The file name a marker is filed under: the fork-less one, or one fork's. */
function gapName(epoch: number, fp?: Uint8Array): string {
	return fp === undefined
		? `${epoch}${GAP_SUFFIX}`
		: `${epoch}-${bytesToHex(fp)}${GAP_SUFFIX}`;
}

export function gapPath(
	configDir: string,
	agentId: string,
	groupId: string,
	epoch: number,
	fp?: Uint8Array,
): string {
	return join(groupPendingDir(configDir, agentId, groupId), gapName(epoch, fp));
}
