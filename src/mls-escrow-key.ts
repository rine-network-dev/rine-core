// The verified branch escrow key, cached per (org id, agent id). The read is the only
// place a 410 `branch revoked` is handled, and the only place the key is verified
// against the caller's own org and own agent certificate.
import type { AgentKeysResponse } from "./api-types.js";
import { TtlCache } from "./cache.js";
import { pinsFor } from "./crypto/key-pins.js";
import { loadAgentKeys } from "./crypto/keys.js";
import {
	type BranchEscrowKeyResponse,
	verifyBranchEscrowKey,
} from "./crypto/escrow-key.js";
import type { VerifiedEscrowKey } from "./crypto/escrow.js";
import { RineApiError } from "./errors.js";
import type { HttpClient } from "./http.js";
import { fetchBranchEscrowKey } from "./mls-escrow-api.js";
import { orgIdOfAgent } from "./own-identity.js";

/** The server's answer when a branch has been revoked: `GET …/escrow-key` 410s. */
export const ESCROW_KEY_REVOKED = "branch revoked";

/**
 * A branch whose escrow key the server refuses to serve any more. Never a
 * fallback: an escrow sealed to a revoked branch's key is readable by nobody,
 * so the read stops rather than sealing to a key the org has retired.
 */
export class BranchRevokedError extends Error {
	constructor() {
		super(ESCROW_KEY_REVOKED);
		this.name = "BranchRevokedError";
	}
}

/**
 * Verified branch escrow keys per (org id, agent id), process-wide, for the same
 * window as the agent-key cache ({@link TtlCache}'s default): a key the server
 * stops serving is not trusted past it.
 *
 * Keyed by agent rather than by branch because the branch is only known from
 * the `GET /agents/{id}/keys` response, and a cache hit must not pay for that
 * read. The verified key carries its own `branch`, which is what
 * {@link dropEscrowKeys} filters on.
 */
const cache = new TtlCache<VerifiedEscrowKey>();

/** The acting agent as the key cache and the verification know it. */
type EscrowActor = { configDir: string; agentId: string; client: HttpClient };

/** The own org id of the acting agent, read locally, or `undefined` when none is known. */
function knownOrgId({ configDir, agentId, client }: EscrowActor): string | undefined {
	return pinsFor(client).ownOrgId ?? orgIdOfAgent(configDir, agentId);
}

/** The own org id of the acting agent; no verification is possible without it. */
function ownOrgId(actor: EscrowActor): string {
	const orgId = knownOrgId(actor);
	if (orgId === undefined) {
		throw new Error(
			`no own org id for agent ${actor.agentId}: cannot verify the branch escrow key`,
		);
	}
	return orgId;
}

function cacheKey(orgId: string, agentId: string): string {
	return `${orgId}/${agentId}`;
}

/** Test seam and 410 handler: forget every cached key (optionally only one branch). */
export function dropEscrowKeys(orgId?: string, branch?: string): void {
	if (orgId === undefined) {
		cache.clear();
		return;
	}
	const prefix = `${orgId}/`;
	cache.deleteWhere(
		(key, value) =>
			key.startsWith(prefix) && (branch === undefined || value.branch === branch),
	);
}

/** Forget the acting agent's cached key: the server has just said its branch is revoked. */
export function forgetEscrowKey(actor: EscrowActor): void {
	const orgId = knownOrgId(actor);
	if (orgId !== undefined) cache.delete(cacheKey(orgId, actor.agentId));
}

/**
 * The acting agent's verified escrow key if one is cached and still within its
 * window, with no network call. This is what a settle may use: it must never
 * wait on the server.
 */
export function cachedEscrowKey(actor: EscrowActor): VerifiedEscrowKey | undefined {
	const orgId = knownOrgId(actor);
	return orgId === undefined ? undefined : cache.get(cacheKey(orgId, actor.agentId));
}

/**
 * The branch escrow key of the acting agent's own branch, verified against the
 * caller's own org and its own agent certificate, then cached.
 *
 * The agent certificate is read raw off `GET /agents/{id}/keys` on purpose —
 * `fetchAgentKeys` caches that response and enforces the key-chain pins on a
 * different path, and the verification here IS `verifyBranchEscrowKey`, which
 * checks the agent cert chains to the branch cert and that the org id matches.
 */
export async function resolveEscrowKey(
	actor: EscrowActor,
	extraHeaders?: Record<string, string>,
): Promise<VerifiedEscrowKey> {
	const { configDir, agentId, client } = actor;
	const orgId = ownOrgId(actor);
	const key = cacheKey(orgId, agentId);
	const cached = cache.get(key);
	if (cached !== undefined) return cached;

	const resp = (await client.get(
		`/agents/${agentId}/keys`,
		undefined,
		extraHeaders,
	)) as AgentKeysResponse;
	const agentSigningPk = loadAgentKeys(configDir, agentId).signing.publicKey;

	let body: BranchEscrowKeyResponse;
	try {
		body = await fetchBranchEscrowKey(client, resp.branch, extraHeaders);
	} catch (error) {
		if (error instanceof RineApiError && error.status === 410) {
			dropEscrowKeys(orgId, resp.branch);
			throw new BranchRevokedError();
		}
		throw error;
	}

	const verified = verifyBranchEscrowKey(body, {
		orgId,
		agentId,
		agentSigningPk,
		agentCertificate: resp.agent_certificate,
	});
	cache.set(key, verified);
	return verified;
}
