// Compares the server's copy of an agent against the keys derived from the phrase.
import type { AgentKeysResponse } from "./api-types.js";
import {
	type AgentDerivedKeys,
	type BranchKeys,
	agentCertClaims,
	toBase64Url,
	verifyAgentCert,
} from "./crypto/index.js";

type KeyField =
	| "signing_public_key"
	| "encryption_public_key"
	| "mls_signing_public_key"
	| "pq_encryption_public_key"
	| "pq_signing_public_key";

function publicKeyOf(derived: AgentDerivedKeys, field: KeyField): Uint8Array {
	switch (field) {
		case "signing_public_key":
			return derived.ed25519.publicKey;
		case "encryption_public_key":
			return derived.x25519.publicKey;
		case "mls_signing_public_key":
			return derived.mlsEd25519.publicKey;
		case "pq_encryption_public_key":
			return derived.mlKem768.publicKey;
		case "pq_signing_public_key":
			return derived.mlDsa65.publicKey;
	}
}

const KEY_FIELDS: readonly KeyField[] = [
	"signing_public_key",
	"encryption_public_key",
	"mls_signing_public_key",
	"pq_encryption_public_key",
	"pq_signing_public_key",
];

/** The first way the server's copy of an agent differs from the derived keys, or undefined. */
export function mismatchReason(
	orgId: string,
	branch: BranchKeys,
	derived: AgentDerivedKeys,
	server: AgentKeysResponse,
): string | undefined {
	for (const field of KEY_FIELDS) {
		if (server[field].x !== toBase64Url(publicKeyOf(derived, field))) {
			return `${field} differs from the key derived from this phrase`;
		}
	}
	try {
		const claims = verifyAgentCert(
			server.agent_certificate,
			branch.ed25519.publicKey,
		);
		const expected = agentCertClaims(orgId, derived, claims.iat);
		for (const [key, value] of Object.entries(expected)) {
			if (claims[key as keyof typeof claims] !== value) {
				return `agent certificate claim '${key}' differs`;
			}
		}
	} catch {
		return "agent certificate does not verify under the derived branch key";
	}
	return undefined;
}
