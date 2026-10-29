/** The `mls` keys an agent has published: the set a closed-group message's framing signature must come from. */
import { bytesToHex } from "@noble/curves/utils.js";
import type { VerifiedAgentKeys } from "../crypto/key-chain.js";
import type { ReadContext } from "./context.js";
import { MAX_GENERATIONS } from "./direct.js";
import { isKeyReadError, isKeysUnavailable } from "./key-errors.js";

/** Hex of each chain-verified `mls` public key: byte keys are not comparable in a `Set`. */
export type MlsKeySet = ReadonlySet<string>;

/**
 * Every chain-verified `mls` key `senderId` has had: the latest generation and each one below it,
 * down to `MAX_GENERATIONS` generations in all: `keyGen` is network-controlled, so older keys are
 * not read.
 *
 * A refused chain or an answer the server gave (404, 410, 401, 403) on the latest generation is
 * an empty set, so no signer matches; on a past generation that generation is skipped. A
 * transport failure, 429 or 5xx on any generation is `null`: the keys could not be read just
 * now, which accuses nobody and must not be remembered beyond this read.
 */
export async function mlsKeySet(
	ctx: ReadContext,
	senderId: string,
): Promise<MlsKeySet | null> {
	let latest: VerifiedAgentKeys;
	try {
		latest = await ctx.client.agentKeys(senderId);
	} catch (err) {
		if (!isKeyReadError(err)) throw err;
		return isKeysUnavailable(err) ? null : new Set();
	}
	const keys = new Set([bytesToHex(latest.mls)]);
	const oldest = Math.max(0, latest.keyGen - (MAX_GENERATIONS - 1));
	for (let gen = oldest; gen < latest.keyGen; gen++) {
		try {
			keys.add(bytesToHex((await ctx.client.agentKeys(senderId, gen)).mls));
		} catch (err) {
			if (!isKeyReadError(err)) throw err;
			if (isKeysUnavailable(err)) return null;
		}
	}
	return keys;
}

/** Whether the MLS leaf key that signed is one of the sender's chain-verified `mls` keys. */
export function isMlsKey(
	keys: MlsKeySet,
	signerPublicKey: Uint8Array,
): boolean {
	return keys.has(bytesToHex(signerPublicKey));
}
