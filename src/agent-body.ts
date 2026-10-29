// The one builder for the key material of an agent create or rotate request.
// Create is generation 0 plus id, name and flags; rotate is the next
// generation and nothing else, so both start from the same body.
import type { Custody } from "./custody.js";
import {
	type AgentKeys,
	agentKeysFromDerived,
	deriveAgent,
	encryptionPublicKeyToJWK,
	issueAgentCert,
	pqPublicKeyToJWK,
	pqSigningPublicKeyToJWK,
	signingPublicKeyToJWK,
} from "./crypto/index.js";
import type { AgentDerivedKeys } from "./crypto/index.js";

export interface AgentKeyBody {
	branch: string;
	signing_public_key: ReturnType<typeof signingPublicKeyToJWK>;
	encryption_public_key: ReturnType<typeof encryptionPublicKeyToJWK>;
	pq_encryption_public_key: ReturnType<typeof pqPublicKeyToJWK>;
	pq_signing_public_key: ReturnType<typeof pqSigningPublicKeyToJWK>;
	mls_signing_public_key: ReturnType<typeof signingPublicKeyToJWK>;
	agent_certificate: string;
}

export interface AgentCreateParams {
	name: string;
	humanOversight?: boolean;
	unlisted?: boolean;
}

export type AgentCreateBody = AgentKeyBody & {
	id: string;
	name: string;
	human_oversight?: boolean;
	unlisted?: boolean;
};

/** A request body and the leaf keys to save once the server accepts it. */
export interface AgentRequest<Body> {
	body: Body;
	keys: AgentKeys;
}

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

export function agentKeyBody(
	custody: Custody,
	derived: AgentDerivedKeys,
	iat: number = nowSeconds(),
): AgentKeyBody {
	return {
		branch: custody.branch.name,
		signing_public_key: signingPublicKeyToJWK(derived.ed25519.publicKey),
		encryption_public_key: encryptionPublicKeyToJWK(derived.x25519.publicKey),
		pq_encryption_public_key: pqPublicKeyToJWK(derived.mlKem768.publicKey),
		pq_signing_public_key: pqSigningPublicKeyToJWK(derived.mlDsa65.publicKey),
		mls_signing_public_key: signingPublicKeyToJWK(derived.mlsEd25519.publicKey),
		agent_certificate: issueAgentCert(
			{ orgId: custody.orgId },
			custody.branch,
			derived,
			iat,
		),
	};
}

function request(
	custody: Custody,
	agentId: string,
	gen: number,
): AgentRequest<AgentKeyBody> {
	const derived = deriveAgent(custody.branch, agentId, gen);
	return { body: agentKeyBody(custody, derived), keys: agentKeysFromDerived(derived) };
}

/** `POST /agents` body for a new agent: the client mints the id and the keys are generation 0. */
export function agentCreateRequest(
	custody: Custody,
	agentId: string,
	params: AgentCreateParams,
): AgentRequest<AgentCreateBody> {
	const { body, keys } = request(custody, agentId, 0);
	return {
		body: {
			id: agentId,
			name: params.name,
			...(params.humanOversight === undefined
				? {}
				: { human_oversight: params.humanOversight }),
			...(params.unlisted === undefined ? {} : { unlisted: params.unlisted }),
			...body,
		},
		keys,
	};
}

/** `POST /agents/{id}/keys` body for generation `nextGen` (the current generation plus one). */
export function agentRotateRequest(
	custody: Custody,
	agentId: string,
	nextGen: number,
): AgentRequest<AgentKeyBody & { key_gen: number }> {
	const { body, keys } = request(custody, agentId, nextGen);
	return { body: { key_gen: nextGen, ...body }, keys };
}
