import {
	type EscrowSlot,
	type EscrowUploader,
	type VerifiedEscrowKey,
	assertEpochReadSecrets,
	escrowSealContext,
	verifyEscrowUploaderSig,
} from "./escrow.js";
import { openHybrid } from "./hybrid.js";
import { type VerifiedAgentKeys, signedWithinValidity } from "./key-chain.js";
import { type KeyPair, pqKeyPairFromSeed } from "./keys.js";

// The reader's half of MLS read escrow: verify the uploader's signature, then open one copy.
// Forged and invalid are different verdicts: a forged row names nobody, an invalid one is
// signed by its uploader and names it.

/** The uploader signature does not verify, or the uploader's keys do not vouch for the row. */
export class EscrowForgedError extends Error {}

/** A correctly signed escrow copy that does not open; it names its uploader. */
export class EscrowInvalidError extends Error {
	readonly uploaderAgentId: string;

	constructor(uploaderAgentId: string, detail: string, options?: ErrorOptions) {
		super(`escrow from ${uploaderAgentId} is invalid: ${detail}`, options);
		this.uploaderAgentId = uploaderAgentId;
	}
}

/** One escrow row as the server returned it, with the org it was read under. */
export interface EscrowRow extends Pick<VerifiedEscrowKey, "orgId" | "branch"> {
	slot: EscrowSlot;
	uploader: Pick<EscrowUploader, "agentId" | "keyGen">;
	/** The server's `created_at`, as sent. */
	storedAt: string;
	sealed: Uint8Array;
	uploaderSig: Uint8Array;
}

/** The branch escrow private keys, in the shape `deriveBranch` returns: the ML-KEM key is its 64-byte seed. */
export interface EscrowOpenKeys {
	escrowX25519: Pick<KeyPair, "privateKey">;
	escrowMlKem768: Pick<KeyPair, "privateKey">;
}

/**
 * Open one escrow copy and return its EpochReadSecrets v1 plaintext.
 *
 * `uploaderKeys` are the chain-verified keys of the generation the row signed under, read with
 * `?gen=` so a superseded one carries `supersededAt`. `currentKeyGen` is the uploader's current
 * generation: a row signed under a lower one has a window to check.
 *
 * The steps run in this order, and the first to fail names the error:
 * 1. the keys are the uploader's signing generation, else forged;
 * 2. the row was stored while that generation was valid, else forged;
 * 3. the strict Ed25519 signature over the slot verifies (an id, branch, epoch or key
 *    generation the signing input cannot be built from counts as a bad signature), else forged;
 * 4. the signed keys belong to the row's org and branch, else invalid;
 * 5. the copy opens under the escrow seal context to an EpochReadSecrets v1, else invalid.
 */
export function openEscrow(
	row: EscrowRow,
	uploaderKeys: VerifiedAgentKeys,
	escrowKeys: EscrowOpenKeys,
	currentKeyGen: number,
): Uint8Array {
	const { agentId, keyGen } = row.uploader;
	if (uploaderKeys.agentId !== agentId || uploaderKeys.keyGen !== keyGen) {
		throw new EscrowForgedError(
			"keys are not the uploader's signing generation",
		);
	}
	if (
		!signedWithinValidity(uploaderKeys, row.storedAt, keyGen < currentKeyGen)
	) {
		throw new EscrowForgedError(
			"escrow is not shown to be stored before its uploader key was superseded or revoked",
		);
	}
	let signed: boolean;
	try {
		signed = verifyEscrowUploaderSig(
			uploaderKeys.signing,
			row,
			row.slot,
			row.uploader,
			row.sealed,
			row.uploaderSig,
		);
	} catch (err) {
		throw new EscrowForgedError(
			"escrow uploader signature input is out of range",
			{
				cause: err,
			},
		);
	}
	if (!signed)
		throw new EscrowForgedError("escrow uploader signature does not verify");
	if (uploaderKeys.orgId !== row.orgId || uploaderKeys.branch !== row.branch) {
		throw new EscrowInvalidError(
			agentId,
			"uploader is not an agent of the branch the escrow names",
		);
	}
	const mlKem = pqKeyPairFromSeed(escrowKeys.escrowMlKem768.privateKey);
	try {
		const plaintext = openHybrid(
			escrowKeys.escrowX25519.privateKey,
			mlKem.privateKey,
			row.sealed,
			escrowSealContext(row, row.slot, agentId),
		);
		assertEpochReadSecrets(plaintext);
		return plaintext;
	} catch (err) {
		throw new EscrowInvalidError(
			agentId,
			err instanceof Error ? err.message : "copy does not open",
			{ cause: err },
		);
	} finally {
		mlKem.privateKey.fill(0);
	}
}
