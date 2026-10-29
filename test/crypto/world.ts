// A self-consistent org world for tests: real derivation, real certs, and a fake
// client that answers `GET /agents/{id}/keys` the way the server does. Every
// consumer that verifies a peer's key chain is exercised through this file.
import { randomUUID } from "node:crypto";
import type { AgentKeysResponse } from "../../src/api-types.js";
import { TtlCache } from "../../src/cache.js";
import { issueAgentCert, issueBranchCert } from "../../src/crypto/certs.js";
import {
	type AgentDerivedKeys,
	type BranchKeys,
	type OrgKeys,
	deriveAgent,
	deriveBranch,
	deriveOrg,
} from "../../src/crypto/derive.js";
import {
	agentKeysFromDerived,
	encryptionPublicKeyToJWK,
	pqPublicKeyToJWK,
	saveAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
} from "../../src/crypto/keys.js";

const IAT = 1_700_000_000;

/** When the world says a superseded generation stopped being valid. */
export const SUPERSEDED_AT = "2026-01-01T00:00:00.000Z";

export interface WorldAgent {
	id: string;
	gen: number;
	derived: AgentDerivedKeys;
	org: OrgKeys;
	branch: BranchKeys;
	response: AgentKeysResponse;
}

export type ResponseMutator = (
	response: AgentKeysResponse,
) => AgentKeysResponse;

export class World {
	readonly org: OrgKeys;
	readonly branches = new Map<string, BranchKeys>();
	readonly agents = new Map<string, WorldAgent[]>();
	/** The `superseded_at` a history read serves for every generation below the newest. */
	supersededAt = SUPERSEDED_AT;

	constructor(entropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32))) {
		this.org = deriveOrg(entropy);
	}

	branch(name = "main"): BranchKeys {
		let branch = this.branches.get(name);
		if (!branch) {
			branch = deriveBranch(this.org, name);
			this.branches.set(name, branch);
		}
		return branch;
	}

	/** Mint an agent generation (a new `gen` of an existing id supersedes the old one). */
	addAgent(opts: { id?: string; gen?: number; branch?: string } = {}): WorldAgent {
		const id = opts.id ?? randomUUID();
		const gen = opts.gen ?? 0;
		const branch = this.branch(opts.branch);
		const derived = deriveAgent(branch, id, gen);
		const response: AgentKeysResponse = {
			agent_id: id,
			signing_public_key: signingPublicKeyToJWK(derived.ed25519.publicKey),
			encryption_public_key: encryptionPublicKeyToJWK(derived.x25519.publicKey),
			mls_signing_public_key: signingPublicKeyToJWK(derived.mlsEd25519.publicKey),
			pq_encryption_public_key: pqPublicKeyToJWK(derived.mlKem768.publicKey),
			pq_signing_public_key: {
				kty: "MLDSA",
				alg: "ML-DSA-65",
				x: toBase64Url(derived.mlDsa65.publicKey),
			},
			org_id: this.org.orgId,
			org_signing_public_key: toBase64Url(this.org.ed25519.publicKey),
			org_pq_signing_public_key: toBase64Url(this.org.mlDsa65.publicKey),
			branch: branch.name,
			branch_certificate: issueBranchCert(this.org, branch, IAT),
			key_gen: gen,
			agent_certificate: issueAgentCert(this.org, branch, derived, IAT),
		};
		const agent = { id, gen, derived, org: this.org, branch, response };
		this.agents.set(id, [...(this.agents.get(id) ?? []), agent]);
		return agent;
	}

	/** The published keys of `id`'s newest generation, minting the agent on first use. */
	published(id: string): AgentKeysResponse {
		const generations = this.agents.get(id);
		return (generations?.[generations.length - 1] ?? this.addAgent({ id })).response;
	}

	/** Write an agent's leaf keys into `configDir`, as onboarding would. */
	save(configDir: string, agent: WorldAgent): void {
		saveAgentKeys(configDir, agent.id, agentKeysFromDerived(agent.derived));
	}

	/**
	 * A client whose `GET /agents/{id}/keys` serves the newest generation (or
	 * `?gen=N`). `mutate` rewrites each served response to build a broken chain.
	 */
	client(mutate: ResponseMutator = (response) => response) {
		const served: string[] = [];
		const lookup = (path: string, params?: Record<string, string | number | boolean>) => {
			const id = /^\/agents\/([^/]+)\/keys$/.exec(path)?.[1];
			const generations = id ? this.agents.get(id) : undefined;
			if (!generations?.length) throw new Error(`world: no keys for ${path}`);
			const wanted = params?.["gen"];
			const found =
				wanted === undefined
					? generations.reduce((a, b) => (b.gen > a.gen ? b : a))
					: generations.find((g) => g.gen === Number(wanted));
			if (!found) throw new Error(`world: no generation ${String(wanted)} for ${path}`);
			const newest = generations.some((g) => g.gen > found.gen);
			return newest
				? { ...found.response, superseded_at: this.supersededAt }
				: found.response;
		};
		return {
			served,
			keyCache: new TtlCache<AgentKeysResponse>(),
			get: async (
				path: string,
				params?: Record<string, string | number | boolean>,
			) => {
				served.push(params ? `${path}?gen=${String(params["gen"])}` : path);
				return structuredClone(mutate(structuredClone(lookup(path, params))));
			},
			post: async () => undefined,
		};
	}
}
