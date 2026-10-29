/**
 * The upload half of the MLS read-escrow drain (its last step): send every
 * pending file of a group, oldest epoch first, and decide from the server's
 * answer what becomes of each file: a stored slot deletes it, a terminal code
 * gives it up, and any other refusal keeps it on the retry schedule of
 * `mls-escrow-retry.ts` (given up after 16 tries). A file whose next try is in
 * the future is skipped, unless the caller is a send that needs it NOW.
 *
 * The signature is computed HERE, not at seal time: the server answers 422 when
 * `key_gen` is not the uploader's current generation, so a file sealed before a
 * rotation must be signed under the current key. A `RineApiError` is the
 * server's answer about one file, so the next file is still tried; any other
 * error is the network and stops the loop. So does a 429 or a 5xx, which says
 * nothing about the file: the group's remaining files are not sent, and the
 * caller is told to stop, so an unavailable server is not hammered. A 401 naming
 * a revoked agent or branch gives the file up too, though it carries no escrow
 * code.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { ACTING_AGENT_HEADER } from "./actor.js";
import {
	type EscrowSlot,
	type EscrowUploader,
	type VerifiedEscrowKey,
	escrowSigningInput,
} from "./crypto/escrow.js";
import { loadAgentKeys, toBase64Url } from "./crypto/keys.js";
import { RineApiError } from "./errors.js";
import type { PeerActor } from "./mls-allowed.js";
import { uploadEscrow } from "./mls-escrow-api.js";
import { EscrowLoss } from "./mls-escrow-gap.js";
import { resolveEscrowKey } from "./mls-escrow-key.js";
import { listPending, pendingPath } from "./mls-escrow-pending.js";
import { giveUpFile, markStored, resolveRefusal } from "./mls-escrow-refusal.js";
import { type DrainOutcome, emptyOutcome } from "./mls-escrow-report.js";
import { isDue, isExhausted, readAttempts } from "./mls-escrow-retry.js";

/** The acting-agent headers every escrow call carries. */
export function actingHeaders(actor: PeerActor): Record<string, string> {
	return { ...actor.extraHeaders, [ACTING_AGENT_HEADER]: actor.agentId };
}

/** The acting agent as the uploader of its own escrows, under its current key generation. */
export function escrowUploader(actor: PeerActor): EscrowUploader {
	const keys = loadAgentKeys(actor.configDir, actor.agentId);
	return {
		agentId: actor.agentId,
		keyGen: keys.keyGen,
		signingPrivateKey: keys.signing.privateKey,
	};
}

/** Whether an upload pass honours the files' retry schedule, and the clock it reads. */
export interface UploadPace {
	/** Skip a file whose next try is in the future. A send retry needs every file now. */
	dueOnly: boolean;
	/** Unix seconds. */
	nowS: number;
}

/** The pace of a drain or a sweep: the retry schedule is honoured. */
export function duePace(nowS = Date.now() / 1000): UploadPace {
	return { dueOnly: true, nowS };
}

/**
 * Upload this group's pending files, oldest epoch first, resolving each by the
 * server's answer. Returns false when a network failure stopped the loop or the
 * server answered 429 or 5xx, so the caller should not go on to other groups.
 */
export async function uploadPending(
	actor: PeerActor,
	groupId: string,
	key: VerifiedEscrowKey,
	uploader: EscrowUploader,
	outcome: DrainOutcome,
	pace: UploadPace = duePace(),
): Promise<boolean> {
	const headers = actingHeaders(actor);
	for (const p of listPending(actor.configDir, actor.agentId, groupId)) {
		if (isExhausted(readAttempts(pendingPath(actor.configDir, actor.agentId, p)))) {
			giveUpFile(actor, p, EscrowLoss.Refused, outcome);
			continue;
		}
		if (
			pace.dueOnly &&
			!isDue(pendingPath(actor.configDir, actor.agentId, p), pace.nowS)
		) {
			continue;
		}
		const slot: EscrowSlot = { groupId, epoch: p.epoch, fp: p.fp };
		const sig = ed25519.sign(
			escrowSigningInput(key, slot, uploader, p.sealed),
			uploader.signingPrivateKey,
		);
		try {
			await uploadEscrow(
				actor.client,
				groupId,
				p.epoch,
				{
					fp: toBase64Url(p.fp),
					sealed: toBase64Url(p.sealed),
					key_gen: uploader.keyGen,
					sig: toBase64Url(sig),
				},
				headers,
			);
		} catch (error) {
			if (!(error instanceof RineApiError)) {
				// Not the server's answer about this file: the network, so stop.
				outcome.failures.push(error instanceof Error ? error : new Error(String(error)));
				return false;
			}
			// A 429 or a 5xx is the server, not this file: the rest wait too.
			if (!resolveRefusal(actor, p, error, outcome, pace.nowS)) return false;
			continue;
		}
		markStored(actor, p);
		outcome.uploaded++;
	}
	return true;
}

/**
 * Upload this group's pending escrows without taking or saving anything: the
 * send retry's step after a 409 `escrow_missing`.
 *
 * Throws when the branch escrow key cannot be resolved or verified.
 */
export async function uploadPendingEscrow(
	actor: PeerActor,
	groupId: string,
): Promise<DrainOutcome> {
	const key = await resolveEscrowKey(actor, actingHeaders(actor));
	const outcome = emptyOutcome();
	await uploadPending(actor, groupId, key, escrowUploader(actor), outcome, {
		dueOnly: false,
		nowS: Date.now() / 1000,
	});
	return outcome;
}
