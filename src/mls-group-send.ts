/**
 * The MLS half of a group send, once for every surface: sync to the group's
 * current epoch, drain the escrow, seal at that epoch and post the ciphertext
 * naming the epoch's escrow.
 *
 * The server refuses an `mls-v1` post that does not carry `escrow_fp`, so the
 * escrow is drained BEFORE the encrypt: a drain that cannot run
 * ({@link EscrowGapError}, {@link EscrowUnavailableError}) must not leave a
 * spent ratchet generation for a message that was never posted, and the
 * fingerprint must name the epoch the ciphertext is built for.
 */
import { isNoMlsStateError } from "./crypto/mls.js";
import { encryptMlsGroupMessage } from "./message-mls.js";
import type { PeerActor } from "./mls-allowed.js";
import { postWithEscrowRetry, prepareEscrowForSend } from "./mls-escrow-send.js";
import { actingHeaders } from "./mls-escrow-upload.js";
import { processMlsWelcomes } from "./mls-ops-join.js";
import { syncMlsGroup } from "./mls-ops-sync.js";

/** What an `mls-v1` send body gains from sealing: the ciphertext fields and the escrow fingerprint. */
export type MlsSealedFields = Awaited<ReturnType<typeof encryptMlsGroupMessage>> & {
	escrow_fp: string;
};

/**
 * Seal `payload` for the MLS group as `actor` and hand the fields to `post`,
 * which sends them. A 409 `escrow_missing` is answered by one escrow upload and
 * one more post with the same fingerprint; an {@link EscrowGapError} propagates
 * with its own words.
 *
 * With no local state for the group, the pending Welcomes install once, scoped
 * to this group, and the seal is tried again. The scope matters: left unscoped,
 * a substituted Welcome for another group would abort this send with that
 * group's refusal.
 */
export async function sealAndPostMlsGroupMessage<T>(
	actor: PeerActor,
	groupId: string,
	payload: unknown,
	post: (fields: MlsSealedFields) => Promise<T>,
): Promise<T> {
	const { configDir, agentId, client } = actor;
	const headers = actingHeaders(actor);
	const sync = () => syncMlsGroup(configDir, agentId, groupId, client, headers);

	// The pre-sync is non-fatal: the no-state recovery below answers a failure.
	await processMlsWelcomes(configDir, agentId, client).catch(() => {});
	await sync().catch(() => {});

	const attempt = async () => {
		const escrowFp = await prepareEscrowForSend(actor, groupId);
		const result = await encryptMlsGroupMessage(configDir, agentId, groupId, payload);
		return { result, escrowFp };
	};
	let sealed: Awaited<ReturnType<typeof attempt>>;
	try {
		sealed = await attempt();
	} catch (err) {
		if (!isNoMlsStateError(err)) throw err;
		await processMlsWelcomes(configDir, agentId, client, { forGroup: groupId });
		await sync();
		sealed = await attempt();
	}
	return postWithEscrowRetry(actor, groupId, sealed.escrowFp, (escrowFp) =>
		post({ ...sealed.result, escrow_fp: escrowFp }),
	);
}
