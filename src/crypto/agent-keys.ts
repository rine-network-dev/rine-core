import { bytesToHex } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { AgentKeysResponse } from "../api-types.js";
import type { TtlCache } from "../cache.js";
import type { HttpClient } from "../http.js";
import type { InnerEnvelope } from "./envelope.js";
import {
	type PqJWK,
	agentIdFromKid,
	jwkToPqPublicKey,
	jwkToPublicKey,
} from "./keys.js";
import type { VerificationStatus } from "./message.js";
import { verifySignature } from "./sign.js";

export interface RecipientKeys {
	encryption: Uint8Array;
	pqEncryption?: Uint8Array;
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

export interface SenderVerification {
	verified: boolean;
	verificationStatus: VerificationStatus;
	/** Set only when the rotation refetch returned a different signing key. */
	keyChanged?: SenderKeyChange;
}

/** What the cache-reading fetch needs; a real {@link HttpClient} satisfies it. */
type CachingClient = Pick<HttpClient, "get"> & {
	readonly keyCache?: TtlCache<AgentKeysResponse>;
};

function getPublishedKeys(
	client: Pick<HttpClient, "get">,
	agentId: string,
): Promise<AgentKeysResponse> {
	return client.get(`/agents/${agentId}/keys`) as Promise<AgentKeysResponse>;
}

/**
 * Stable short identity for a published signing key, used to tell a rotation
 * apart from a repeated wrong answer.
 */
function signingKeyFingerprint(keys: AgentKeysResponse): string {
	return bytesToHex(sha256(jwkToPublicKey(keys.signing_public_key)));
}

/**
 * Fetch an agent's published keys (`GET /agents/{id}/keys`) through the client's
 * per-agent {@link HttpClient.keyCache}.
 *
 * This is the INBOUND-VERIFY read. It may serve a cached key because a wrong one
 * announces itself here — the signature fails and {@link verifyEnvelopeSender}
 * refetches. `bypassCache` forces a fresh fetch and overwrites the entry.
 *
 * A real {@link HttpClient} always carries a cache, so every production verify is
 * cached; the cache stays optional on the parameter type so a caller holding only
 * a `get` — a stub, a narrower transport — still fetches rather than throwing.
 */
export async function fetchAgentKeys(
	client: CachingClient,
	agentId: string,
	opts?: { bypassCache?: boolean },
): Promise<{ keys: AgentKeysResponse; fromCache: boolean }> {
	const cache = client.keyCache;
	if (cache && !opts?.bypassCache) {
		const hit = cache.get(agentId);
		if (hit !== undefined) return { keys: hit, fromCache: true };
	}
	const keys = await getPublishedKeys(client, agentId);
	cache?.set(agentId, keys);
	return { keys, fromCache: false };
}

/**
 * Fetch a recipient's encryption keys, including the optional PQ key for hybrid
 * mode.
 *
 * The OUTBOUND-SEAL read, and deliberately cache-free: the parameter type grants
 * only `get`, so this path cannot reach {@link HttpClient.keyCache} even by
 * accident. Sealing is one-shot and silent — nothing ever tells this client that
 * the key it sealed to was superseded, so a cached entry would let a peer's
 * rotation pass unnoticed for a whole TTL and every message sealed in that
 * window would be permanently unreadable for its recipient. The verify path can
 * afford a cache precisely because it has a failure signal to act on; this one
 * does not. Keep the two asymmetric.
 */
export async function fetchRecipientKeys(
	client: Pick<HttpClient, "get">,
	agentId: string,
): Promise<RecipientKeys> {
	const keys = await getPublishedKeys(client, agentId);
	const out: RecipientKeys = {
		encryption: jwkToPublicKey(keys.encryption_public_key),
	};
	if (keys.pq_encryption_public_key) {
		out.pqEncryption = jwkToPqPublicKey(keys.pq_encryption_public_key as PqJWK);
	}
	return out;
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
 * If a CACHED key yields a failure, the sender may have rotated mid-TTL: refetch
 * once bypassing the cache. Exactly one refetch per call — whoever answers the
 * key endpoint chooses the second answer, so retrying until something verifies
 * would hand them an oracle. A repeat of the same key is not re-verified (same
 * inputs, same verdict); a genuinely different key is re-verified and reported
 * as a key change, whichever way that verdict falls. A fresh fetch that fails is
 * not refetched. Any network/lookup error still yields "unverifiable".
 */
export async function verifyEnvelopeSender(
	decoded: InnerEnvelope,
	client: HttpClient,
	expectedSenderAgentId: string,
): Promise<SenderVerification> {
	try {
		const senderAgentId = agentIdFromKid(decoded.kid);
		if (!sameAgentId(senderAgentId, expectedSenderAgentId)) {
			return { verified: false, verificationStatus: "sender-mismatch" };
		}
		const { keys, fromCache } = await fetchAgentKeys(client, senderAgentId);
		let verified = verifyWith(keys, decoded);
		let keyChanged: SenderKeyChange | undefined;
		if (!verified && fromCache) {
			const fresh = await fetchAgentKeys(client, senderAgentId, {
				bypassCache: true,
			});
			const previousFingerprint = signingKeyFingerprint(keys);
			const currentFingerprint = signingKeyFingerprint(fresh.keys);
			if (previousFingerprint !== currentFingerprint) {
				verified = verifyWith(fresh.keys, decoded);
				keyChanged = {
					agentId: senderAgentId,
					previousFingerprint,
					currentFingerprint,
				};
			}
		}
		const verificationStatus: VerificationStatus = verified
			? "verified"
			: "invalid";
		return keyChanged
			? { verified, verificationStatus, keyChanged }
			: { verified, verificationStatus };
	} catch {
		// Could not fetch sender's key — signature unverifiable.
		return { verified: false, verificationStatus: "unverifiable" };
	}
}

function verifyWith(keys: AgentKeysResponse, decoded: InnerEnvelope): boolean {
	const senderSigningPk = jwkToPublicKey(keys.signing_public_key);
	return verifySignature(senderSigningPk, decoded.payload, decoded.signature);
}
