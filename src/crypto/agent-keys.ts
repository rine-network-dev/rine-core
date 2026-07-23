import type { AgentKeysResponse } from "../api-types.js";
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
 * Fetch an agent's published keys (`GET /agents/{id}/keys`), reading through the
 * client's optional per-agent {@link HttpClient.keyCache}. Both the recipient-keys
 * (send) and sender-keys (inbound verify) paths hit this one endpoint, so a cached
 * entry primed by a send is reused by a later verify for the same peer — this is
 * what collapses the per-key request volume on a multi-agent host.
 * `bypassCache` forces a fresh fetch (and overwrites the cached entry) — used for
 * the verify-failure rotation refetch.
 */
export async function fetchAgentKeys(
	client: HttpClient,
	agentId: string,
	opts?: { bypassCache?: boolean },
): Promise<{ keys: AgentKeysResponse; fromCache: boolean }> {
	const cache = client.keyCache;
	if (cache && !opts?.bypassCache) {
		const hit = cache.get(agentId);
		if (hit !== undefined) return { keys: hit, fromCache: true };
	}
	const keys = (await client.get(
		`/agents/${agentId}/keys`,
	)) as AgentKeysResponse;
	cache?.set(agentId, keys);
	return { keys, fromCache: false };
}

/** Fetch a recipient's encryption keys, including the optional PQ key for hybrid mode. */
export async function fetchRecipientKeys(
	client: HttpClient,
	agentId: string,
): Promise<RecipientKeys> {
	const { keys } = await fetchAgentKeys(client, agentId);
	const out: RecipientKeys = {
		encryption: jwkToPublicKey(keys.encryption_public_key),
	};
	if (keys.pq_encryption_public_key) {
		out.pqEncryption = jwkToPqPublicKey(keys.pq_encryption_public_key as PqJWK);
	}
	return out;
}

/**
 * Verify an envelope's Ed25519 signature against the sender's published signing key.
 * If a CACHED key yields a verification failure, the sender may have rotated keys
 * mid-TTL: refetch once bypassing the cache and re-verify before surfacing "invalid".
 * A genuinely fresh fetch that fails is not re-fetched. Any network/lookup
 * error still yields "unverifiable".
 */
export async function verifyEnvelopeSender(
	decoded: InnerEnvelope,
	client: HttpClient,
): Promise<{ verified: boolean; verificationStatus: VerificationStatus }> {
	try {
		const senderAgentId = agentIdFromKid(decoded.kid);
		const { keys, fromCache } = await fetchAgentKeys(client, senderAgentId);
		let verified = verifyWith(keys, decoded);
		if (!verified && fromCache) {
			const fresh = await fetchAgentKeys(client, senderAgentId, {
				bypassCache: true,
			});
			verified = verifyWith(fresh.keys, decoded);
		}
		return { verified, verificationStatus: verified ? "verified" : "invalid" };
	} catch {
		// Could not fetch sender's key — signature unverifiable.
		return { verified: false, verificationStatus: "unverifiable" };
	}
}

function verifyWith(keys: AgentKeysResponse, decoded: InnerEnvelope): boolean {
	const senderSigningPk = jwkToPublicKey(keys.signing_public_key);
	return verifySignature(senderSigningPk, decoded.payload, decoded.signature);
}
