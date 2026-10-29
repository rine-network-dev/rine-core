import { bytesToHex } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { AgentKeysResponse } from "../api-types.js";
import type { TtlCache } from "../cache.js";
import type { HttpClient } from "../http.js";
import type { InnerEnvelope } from "./envelope.js";
import {
	KeyChainError,
	type PublishedKeys,
	type VerifiedAgentKeys,
	signedWithinValidity,
	verifyKeyChain,
} from "./key-chain.js";
import { getPublishedKeys } from "./published-keys.js";
import { pinsFor } from "./key-pins.js";
import { InvalidSigningKidError, parseSigningKid } from "./keys.js";
import type { VerificationStatus } from "./message.js";
import { type SigContext, verifyMessageSignature } from "./sign.js";

export interface RecipientKeys {
	encryption: Uint8Array;
	pqEncryption: Uint8Array;
}

/**
 * A peer's published signing key differed from the copy this client had cached
 * for it. Fingerprints are hex SHA-256 over the raw Ed25519 public key, so they
 * are comparable across languages and safe to log or show to an operator.
 */
export interface SenderKeyChange {
	agentId: string;
	previousFingerprint: string;
	currentFingerprint: string;
}

interface SenderVerification {
	verified: boolean;
	verificationStatus: VerificationStatus;
	/** Set only when the rotation refetch returned a different signing key. */
	keyChanged?: SenderKeyChange;
}

/** What the cache-reading fetch needs; a real {@link HttpClient} satisfies it. */
type CachingClient = Pick<HttpClient, "get"> & {
	readonly keyCache?: TtlCache<AgentKeysResponse>;
};

/**
 * Stable short identity for a published signing key, used to tell a rotation
 * apart from a repeated wrong answer.
 */
function signingKeyFingerprint(signing: Uint8Array): string {
	return bytesToHex(sha256(signing));
}

/**
 * Fetch and chain-verify an agent's published keys (`GET /agents/{id}/keys`)
 * through the client's per-agent {@link HttpClient.keyCache}.
 *
 * This is the INBOUND-VERIFY read. It may serve a cached raw response because a
 * wrong one announces itself here — the signature fails and
 * {@link verifyEnvelopeSender} refetches. `bypassCache` forces a fresh fetch and
 * overwrites the entry. A history read (`opts.gen`) caches under a distinct key
 * so it can never collide with the current-generation entry.
 *
 * The raw response is cached only after {@link verifyKeyChain} accepts it: a
 * broken chain propagates its {@link KeyChainError} and leaves the cache empty,
 * so a refusal is never remembered as a usable key. The cache stays optional on
 * the parameter type so a caller holding only a `get` — a stub, a narrower
 * transport — still fetches rather than throwing.
 */
export async function fetchAgentKeys(
	client: CachingClient,
	agentId: string,
	opts?: { bypassCache?: boolean; gen?: number },
): Promise<{ keys: VerifiedAgentKeys; fromCache: boolean }> {
	const cache = client.keyCache;
	const cacheKey = opts?.gen === undefined ? agentId : `${agentId}#${opts.gen}`;
	const pins = pinsFor(client);
	const cached = cache && !opts?.bypassCache ? cache.get(cacheKey) : undefined;
	if (cached !== undefined) {
		try {
			const keys = verifyKeyChain(cached, { agentId, gen: opts?.gen }, pins);
			return { keys, fromCache: true };
		} catch (err) {
			// A cached copy can fall behind pins another read advanced (the outbound
			// path shares them); it is dropped and fetched once, never trusted.
			if (!(err instanceof KeyChainError)) throw err;
			cache?.delete(cacheKey);
		}
	}
	const raw = await getPublishedKeys(client, agentId, opts?.gen);
	const keys = verifyKeyChain(raw, { agentId, gen: opts?.gen }, pins);
	cache?.set(cacheKey, raw);
	return { keys, fromCache: false };
}

/**
 * Fetch a recipient's encryption keys, including the PQ key for hybrid mode.
 *
 * The OUTBOUND-SEAL read, and deliberately cache-free: the parameter type grants
 * only `get`, so this path cannot reach {@link HttpClient.keyCache} even by
 * accident. Sealing is one-shot and silent — nothing ever tells this client that
 * the key it sealed to was superseded, so a cached entry would let a peer's
 * rotation pass unnoticed for a whole TTL and every message sealed in that
 * window would be permanently unreadable for its recipient. The verify path can
 * afford a cache precisely because it has a failure signal to act on; this one
 * does not. Keep the two asymmetric.
 *
 * The chain is verified before the keys are returned: a broken chain throws the
 * {@link KeyChainError} ("recipient key chain invalid") and sealing is refused.
 * There is no fallback — sealing to an unverified key is the failure this check
 * exists to prevent.
 */
export async function fetchRecipientKeys(
	client: Pick<HttpClient, "get">,
	agentId: string,
): Promise<RecipientKeys> {
	const raw = await getPublishedKeys(client, agentId);
	const keys = verifyKeyChain(raw, { agentId }, pinsFor(client));
	return { encryption: keys.encryption, pqEncryption: keys.pqEncryption };
}

/**
 * Agent ids are server-issued UUIDs; compare them case- and space-insensitively.
 *
 * Exported because binding a signature to a sender is one rule, and a caller that
 * re-checks the same binding elsewhere — the SDK's memo replay, say — has to
 * normalize identically or a differently-cased id refuses a legitimate row.
 */
export function sameAgentId(a: string, b: string): boolean {
	return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * A signature only counts against the exact generation the kid names. For a
 * generation below the sender's current one (`row.history`, with the
 * row's server `created_at`) it also has to be an object stamped before that
 * generation was superseded. A generation of a revoked agent, current or not,
 * carries `revoked_at` and is bounded by it the same way.
 */
function verifyAgainst(
	keys: VerifiedAgentKeys,
	keyGen: number,
	ctx: SigContext,
	decoded: InnerEnvelope,
	row: { createdAt: string | undefined; history: boolean },
): boolean {
	if (keys.keyGen !== keyGen) return false;
	if (!signedWithinValidity(keys, row.createdAt, row.history)) return false;
	return verifyMessageSignature(keys.signing, ctx, decoded.payload, decoded.signature);
}

/**
 * Verify an envelope's Ed25519 signature against the sender's published signing
 * key, and bind that signature to the sender the SERVER authenticated.
 *
 * `expectedSenderAgentId` is the `from_agent_id` of the row being opened. The
 * envelope's `kid` must name that same agent: the signature covers the plaintext
 * alone, so without this comparison a signed envelope re-sealed by a third party
 * would verify under the original signer's key while the server attributes the
 * row to the resealer. A mismatch is `"sender-mismatch"` and costs no network
 * round-trip — it is decided before any key is fetched, because it is not a
 * question the key endpoint can answer.
 *
 * The kid also names the generation the sender signed under. If the current
 * response is newer, the named generation is fetched as a history read (whose
 * rollback pin is skipped); a kid generation HIGHER than the fetched one is a
 * stale cache and counts as not verified. A history read verifies only when
 * `createdAt`, the row's server `created_at`, is at or before that generation's
 * `superseded_at`; without it an older generation is `"invalid"`. A revoked
 * agent's keys carry `revoked_at`, and the same comparison applies to the
 * earlier of the two bounds, current generation included. The bound is read off
 * the key view, and a cached view is as old as the client's cache TTL, so a
 * revocation newer than the cached fetch is seen once the entry expires.
 *
 * If a CACHED key yields a failure, the sender may have rotated mid-TTL: refetch
 * once bypassing the cache for the same slot. Exactly one refetch per call —
 * whoever answers the key endpoint chooses the second answer, so retrying until
 * something verifies would hand them an oracle. A repeat of the same key is not
 * re-verified (same inputs, same verdict); a genuinely different key is
 * re-verified and reported as a key change, whichever way that verdict falls. A
 * fresh fetch that fails is not refetched.
 *
 * A {@link KeyChainError} anywhere is a verdict, not a transient miss: the
 * content is withheld as `"invalid"`. A malformed kid is `"sender-mismatch"`,
 * decided before any fetch. Any other error (network) still yields
 * `"unverifiable"`.
 */
export async function verifyEnvelopeSender(
	decoded: InnerEnvelope,
	client: CachingClient,
	expectedSenderAgentId: string,
	ctx: SigContext,
	createdAt?: string,
): Promise<SenderVerification> {
	try {
		const { agentId, keyGen } = parseSigningKid(decoded.kid);
		if (!sameAgentId(agentId, expectedSenderAgentId)) {
			return { verified: false, verificationStatus: "sender-mismatch" };
		}
		let opts: { bypassCache?: boolean; gen?: number } | undefined;
		let { keys, fromCache } = await fetchAgentKeys(client, agentId);
		if (keys.keyGen > keyGen) {
			opts = { gen: keyGen };
			({ keys, fromCache } = await fetchAgentKeys(client, agentId, opts));
		}
		const row = { createdAt, history: opts !== undefined };
		let verified = verifyAgainst(keys, keyGen, ctx, decoded, row);
		let keyChanged: SenderKeyChange | undefined;
		if (!verified && fromCache) {
			const fresh = await fetchAgentKeys(client, agentId, {
				...opts,
				bypassCache: true,
			});
			const previousFingerprint = signingKeyFingerprint(keys.signing);
			const currentFingerprint = signingKeyFingerprint(fresh.keys.signing);
			if (previousFingerprint !== currentFingerprint) {
				verified = verifyAgainst(fresh.keys, keyGen, ctx, decoded, row);
				keyChanged = { agentId, previousFingerprint, currentFingerprint };
			}
		}
		const verificationStatus: VerificationStatus = verified
			? "verified"
			: "invalid";
		return keyChanged
			? { verified, verificationStatus, keyChanged }
			: { verified, verificationStatus };
	} catch (err) {
		if (err instanceof KeyChainError) {
			return { verified: false, verificationStatus: "invalid" };
		}
		// A kid no honest client emits names no sender, so it is a refusal and
		// never a lookup outcome.
		if (err instanceof InvalidSigningKidError) {
			return { verified: false, verificationStatus: "sender-mismatch" };
		}
		// Could not fetch sender's key — signature unverifiable.
		return { verified: false, verificationStatus: "unverifiable" };
	}
}
