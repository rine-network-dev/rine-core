/**
 * A self-consistent org for tests: real derivation and real certificates, so a
 * peer's key chain verifies the way it does against the server. Test-only: import
 * it from `@rine-network/core/testing`, never from the package root.
 */
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgentKeysResponse } from "./api-types.js";
import { saveTokenCache } from "./config.js";
import { issueAgentCert, issueBranchCert } from "./crypto/certs.js";
import { deriveAgent, deriveBranch, deriveOrg } from "./crypto/derive.js";
import {
	type AgentKeys,
	agentKeysFromDerived,
	encryptionPublicKeyToJWK,
	pqPublicKeyToJWK,
	pqSigningPublicKeyToJWK,
	saveAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
} from "./crypto/keys.js";
import type { CustodyDirs } from "./custody.js";
import { saveRoot } from "./owner.js";
import { MAIN_BRANCH, PrincipalKind, principalString } from "./principal.js";
import { DEFAULT_PROFILE, saveProfiles } from "./profiles.js";

/** A fixed org root: every call derives the same org, branch and agent keys. */
export const FIXTURE_ROOT = new Uint8Array(32).fill(5);

/** The fixture org's id, derived from {@link FIXTURE_ROOT}. */
export const FIXTURE_ORG_ID = deriveOrg(FIXTURE_ROOT).orgId;

const CERT_IAT = 1_700_000_000;
const TEST_TOKEN = "test-token";
const TOKEN_LIFETIME_S = 3600;

/** The generation-0 leaf keys of `agentId` under the org of `root`. */
export function fixtureAgentKeys(
	agentId: string,
	root: Uint8Array = FIXTURE_ROOT,
): AgentKeys {
	const branch = deriveBranch(deriveOrg(root), MAIN_BRANCH);
	return agentKeysFromDerived(deriveAgent(branch, agentId, 0));
}

/** Leaf keys for `agentId` at key generation `keyGen`, under a fresh random org. */
export function derivedAgentKeys(agentId: string, keyGen = 0): AgentKeys {
	const branch = deriveBranch(deriveOrg(randomBytes(32)), MAIN_BRANCH);
	return agentKeysFromDerived(deriveAgent(branch, agentId, keyGen));
}

/** Write the generation-0 leaf keys of `agentId` (of the fixture org) into `configDir`. */
export function seedAgentKeys(configDir: string, agentId: string): AgentKeys {
	const keys = fixtureAgentKeys(agentId);
	saveAgentKeys(configDir, agentId, keys);
	return keys;
}

/** Write the org root and its org profile `profile` (default `default`) into `ownerDir`. */
export function seedOrgIdentity(
	ownerDir: string,
	root: Uint8Array = FIXTURE_ROOT,
	profile = DEFAULT_PROFILE,
): void {
	const { orgId } = deriveOrg(root);
	saveRoot(ownerDir, root);
	saveProfiles(ownerDir, {
		[profile]: {
			org_id: orgId,
			principal: principalString({ kind: PrincipalKind.Org, orgId }),
		},
	});
}

/**
 * Make `configDir` an agent runtime dir for `agentId`: its leaf keys, an `agent:`
 * profile (named `profile`, default `default`) and, unless `cacheToken` is false, a
 * live cached token so the OAuth mint never hits the wire.
 */
export function seedAgentRuntime(
	configDir: string,
	agentId: string,
	opts: { profile?: string; pollUrl?: string; cacheToken?: boolean } = {},
): AgentKeys {
	const keys = seedAgentKeys(configDir, agentId);
	const principal = principalString({ kind: PrincipalKind.Agent, agentId });
	saveProfiles(configDir, {
		[opts.profile ?? DEFAULT_PROFILE]: {
			org_id: FIXTURE_ORG_ID,
			principal,
			branch: MAIN_BRANCH,
			agent_id: agentId,
			...(opts.pollUrl ? { poll_url: opts.pollUrl } : {}),
		},
	});
	if (opts.cacheToken !== false) {
		saveTokenCache(configDir, {
			[principal]: {
				access_token: TEST_TOKEN,
				expires_at: Date.now() / 1000 + TOKEN_LIFETIME_S,
			},
		});
	}
	return keys;
}

export interface CustodyFixture {
	dirs: CustodyDirs;
	orgId: string;
	cleanup(): void;
}

/** Two temp dirs (runtime config + owner) holding a root key and the org profile `default` in the owner dir. */
export function makeCustodyFixture(): CustodyFixture {
	const base = fs.mkdtempSync(join(tmpdir(), "rine-custody-"));
	const dirs = {
		configDir: join(base, "config"),
		ownerDir: join(base, "owner"),
	};
	fs.mkdirSync(dirs.configDir, { recursive: true });
	seedOrgIdentity(dirs.ownerDir);
	return {
		dirs,
		orgId: FIXTURE_ORG_ID,
		cleanup: () => fs.rmSync(base, { recursive: true, force: true }),
	};
}

/**
 * Give the fixture's runtime dir a generation-0 agent: leaf keys on disk and a
 * runtime profile naming it (default profile name `agent`, no cached token).
 */
export function seedAgent(
	fx: CustodyFixture,
	agentId: string,
	opts: { profile?: string; pollUrl?: string } = {},
): void {
	seedAgentRuntime(fx.dirs.configDir, agentId, {
		profile: opts.profile ?? "agent",
		pollUrl: opts.pollUrl,
		cacheToken: false,
	});
}

/**
 * What `GET /agents/{id}/keys` answers for a fixture-org agent at generation `gen`:
 * a self-consistent key chain (org, branch cert, agent cert) that peers verify.
 * `root` places the agent under another org, for a response that re-homes a peer.
 */
export function publishedKeys(
	agentId: string,
	gen = 0,
	root: Uint8Array = FIXTURE_ROOT,
): AgentKeysResponse {
	const org = deriveOrg(root);
	const branch = deriveBranch(org, MAIN_BRANCH);
	const derived = deriveAgent(branch, agentId, gen);
	return {
		agent_id: agentId,
		signing_public_key: signingPublicKeyToJWK(derived.ed25519.publicKey),
		encryption_public_key: encryptionPublicKeyToJWK(derived.x25519.publicKey),
		mls_signing_public_key: signingPublicKeyToJWK(derived.mlsEd25519.publicKey),
		pq_encryption_public_key: pqPublicKeyToJWK(derived.mlKem768.publicKey),
		pq_signing_public_key: pqSigningPublicKeyToJWK(derived.mlDsa65.publicKey),
		org_id: org.orgId,
		org_signing_public_key: toBase64Url(org.ed25519.publicKey),
		org_pq_signing_public_key: toBase64Url(org.mlDsa65.publicKey),
		branch: branch.name,
		branch_certificate: issueBranchCert(org, branch, CERT_IAT),
		key_gen: gen,
		agent_certificate: issueAgentCert(org, branch, derived, CERT_IAT),
	};
}

/** A `get` that serves the fixture org's published keys and nothing else. */
export function keysGet(path: string): unknown {
	const id = /^\/agents\/([^/]+)\/keys$/.exec(path)?.[1];
	if (id === undefined) throw new Error(`unexpected GET ${path}`);
	return publishedKeys(id);
}
