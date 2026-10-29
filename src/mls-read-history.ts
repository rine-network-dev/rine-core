import type { MlsGroup } from "@rine-network/mls";
import { mlsMessageEpoch } from "./crypto/mls-header.js";
import { type PeerActor, admitPeers } from "./mls-allowed.js";

/**
 * Admit the sender's chain-verified key generations before a prior-epoch
 * message is decrypted.
 *
 * A message from an epoch this handle has moved past opens only when the
 * sender's leaf at that epoch is a valid predecessor of the one it holds now,
 * and the allowed set is what decides that. A process that never synced holds
 * none of the sender's generations, so the read admits them itself.
 *
 * 🔴 Before the first decrypt, never as a retry after a refusal: opening a
 * prior-epoch message spends its ratchet key before the identity check, so a
 * refused attempt leaves nothing to open on the second. A failure here (the
 * network, a broken chain) propagates with the ratchet untouched.
 *
 * A message from the handle's own epoch, or one this client cannot place, needs
 * nothing: its sender's current leaf is already in the tree the set vetted.
 */
export async function admitSenderHistory(
	actor: PeerActor,
	group: MlsGroup,
	payload: Uint8Array,
	fromAgentId: string,
): Promise<void> {
	const epoch = mlsMessageEpoch(payload);
	if (epoch === null || epoch >= group.epoch()) return;
	await admitPeers(actor, [fromAgentId]);
}
