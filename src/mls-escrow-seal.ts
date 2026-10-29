/**
 * Sealing the epochs a native group yielded into the pending store: the disk
 * half of the drain, with no network and no group in hand.
 */
import type { EscrowExport } from "@rine-network/mls";
import {
	type EscrowSlot,
	type EscrowUploader,
	type VerifiedEscrowKey,
	sealEscrow,
} from "./crypto/escrow.js";
import { type PendingEscrow, listPending, writePending } from "./mls-escrow-pending.js";

/** The pending file already holding this slot, if any. */
function existingFor(
	pending: PendingEscrow[],
	slot: EscrowSlot,
): PendingEscrow | undefined {
	return pending.find(
		(p) =>
			p.groupId === slot.groupId &&
			p.epoch === slot.epoch &&
			Buffer.from(p.fp).equals(Buffer.from(slot.fp)),
	);
}

/**
 * Seal every taken export into the pending store, reusing a file that already
 * holds the slot. Returns the number of NEW files written.
 *
 * Sealing is randomised, so a second file for one slot would be a different row
 * and the server answers 409 to it; the first sealing of a slot wins.
 */
export function sealTaken(
	configDir: string,
	agentId: string,
	groupId: string,
	key: VerifiedEscrowKey,
	uploader: EscrowUploader,
	taken: EscrowExport[],
): number {
	const pending = listPending(configDir, agentId, groupId);
	let sealed = 0;
	for (const export_ of taken) {
		const slot: EscrowSlot = {
			groupId,
			epoch: export_.epoch,
			fp: export_.fp,
		};
		if (existingFor(pending, slot) === undefined) {
			const { sealed: bytes } = sealEscrow(
				key,
				slot,
				uploader,
				export_.plaintext,
			);
			writePending(configDir, agentId, { ...slot, sealed: bytes });
			pending.push({ ...slot, sealed: bytes });
			sealed++;
		}
	}
	return sealed;
}

/** Zero the epochs' secrets: the plaintext lives only until it is on disk, or the drain gives up. */
export function zeroExports(taken: EscrowExport[]): void {
	for (const export_ of taken) export_.plaintext.fill(0);
}
