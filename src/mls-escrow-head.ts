/**
 * The newest drained epoch of each group and its fork fingerprint.
 *
 * A sender that must carry `escrow_fp` needs the live fork's escrow to be sealed
 * before it sends. The drain remembers the newest drained epoch and its fp in a
 * tiny record per group, which the send gate compares with the group's live
 * fingerprint:
 *   <mls store>/escrow-head/<group_id>.json   {"epoch": n, "fp": "<hex>"}
 */
import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import * as fs from "node:fs";
import { join } from "node:path";
import { writeAtomic } from "./config.js";
import { validatePathId } from "./crypto/keys.js";
import { mlsStoreRoot } from "./crypto/mls.js";
import { FP_HEX_RE } from "./mls-escrow-pending.js";

/** The newest drained epoch of a group and the fork fingerprint it was drained at. */
export interface EscrowHead {
	epoch: number;
	fp: Uint8Array;
}

const HEAD_DIR = "escrow-head";
const HEAD_SUFFIX = ".json";

/** `<mls store>/escrow-head` — the parent of every group's head record. */
function headRoot(configDir: string, agentId: string): string {
	return join(mlsStoreRoot(configDir, agentId), HEAD_DIR);
}

/** The head record path for one group. Validates the id before joining. */
function headPath(configDir: string, agentId: string, groupId: string): string {
	validatePathId(groupId, "group ID");
	return join(headRoot(configDir, agentId), `${groupId}${HEAD_SUFFIX}`);
}

/**
 * Remember the newest drained epoch and its fork fingerprint.
 *
 * The head never moves to a LOWER epoch, except for a write the drain proved is
 * the live group's own current epoch: a resync or reseat can seat the member on
 * another fork at a lower epoch number than the old head, and the head must
 * follow that switch. A stale drain finishing after a newer one must not rewind
 * what a sender reads as the current fp. A corrupt existing head reads as
 * absent, so it is replaced rather than blocking the write.
 */
export function writeHead(
	configDir: string,
	agentId: string,
	groupId: string,
	head: EscrowHead,
	{ live = false }: { live?: boolean } = {},
): void {
	const existing = readHead(configDir, agentId, groupId);
	if (!live && existing !== undefined && existing.epoch > head.epoch) return;
	fs.mkdirSync(headRoot(configDir, agentId), { recursive: true, mode: 0o700 });
	writeAtomic(
		headPath(configDir, agentId, groupId),
		JSON.stringify({ epoch: head.epoch, fp: bytesToHex(head.fp) }),
	);
}

/** The remembered head, or `undefined` when it is absent or unreadable. */
export function readHead(
	configDir: string,
	agentId: string,
	groupId: string,
): EscrowHead | undefined {
	let raw: string;
	try {
		raw = fs.readFileSync(headPath(configDir, agentId, groupId), "utf-8");
	} catch {
		return undefined;
	}
	try {
		const { epoch, fp } = JSON.parse(raw) as Record<string, unknown>;
		if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 0) {
			return undefined;
		}
		if (typeof fp !== "string" || !FP_HEX_RE.test(fp)) return undefined;
		return { epoch, fp: hexToBytes(fp) };
	} catch {
		return undefined;
	}
}

/**
 * Forget the head when it is exactly the epoch and fork fingerprint of `pending`.
 * A head left naming an escrow that was given up would send under a fingerprint
 * the server can never hold. A head at another epoch or fork is a different
 * escrow and stays.
 */
export function clearHeadOf(
	configDir: string,
	agentId: string,
	pending: Pick<EscrowHead, "epoch" | "fp"> & { groupId: string },
): void {
	const head = readHead(configDir, agentId, pending.groupId);
	if (head?.epoch !== pending.epoch || bytesToHex(head.fp) !== bytesToHex(pending.fp)) {
		return;
	}
	fs.rmSync(headPath(configDir, agentId, pending.groupId), { force: true });
}
