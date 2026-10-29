// Peer-side key chain verification and pins. Chain logic only: the claim builders and cert verifiers
// live in certs.ts.
import { sha256 } from "@noble/hashes/sha2.js";
import type { AgentKeysResponse } from "../api-types.js";
import { verifyAgentCert, verifyBranchCert } from "./certs.js";
import { canonicalUuid, orgIdFromKeys } from "./derive.js";
import { assertStrictEd25519PublicKey } from "./ed25519-strict.js";
import { instantMicros } from "./instant.js";
import { fromBase64Url, toBase64Url } from "./keys.js";
import type { KeyPins } from "./key-pins.js";

export type KeyChainFault =
	| "malformed"
	| "org_id"
	| "own_org_pin"
	| "agent_org_pin"
	| "key_gen_rollback"
	| "branch_cert"
	| "agent_cert"
	| "field_mismatch"
	| "weak_key";

export class KeyChainError extends Error {
	readonly fault: KeyChainFault;

	constructor(fault: KeyChainFault) {
		super("recipient key chain invalid");
		this.fault = fault;
	}
}

/**
 * A key response. A superseded generation (`?gen=N` below the current one)
 * also carries `superseded_at`, the instant its validity ended; a generation of
 * a revoked agent, or of an agent under a revoked branch, carries `revoked_at`.
 */
export type PublishedKeys = AgentKeysResponse & { superseded_at?: string };

export interface VerifiedAgentKeys {
	agentId: string;
	orgId: string;
	branch: string;
	keyGen: number;
	signing: Uint8Array;
	encryption: Uint8Array;
	pqEncryption: Uint8Array;
	pqSigning: Uint8Array;
	mls: Uint8Array;
	orgSigning: Uint8Array;
	/** Epoch microseconds the generation was superseded; unset for the current one. */
	supersededAt?: number;
	/** Epoch microseconds the agent or its branch was revoked; unset while neither is. */
	revokedAt?: number;
}

/**
 * Whether an object the server stamped at `createdAt` was made while the
 * generation was still valid: at or before the earlier of `keys.supersededAt`
 * and `keys.revokedAt`. A generation with either bound refuses an object with
 * no readable stamp. `history` marks a read of a generation below the current
 * one, which must carry `superseded_at` itself: a revocation bound alone does
 * not stand in for it, so a history read that omits it cannot reopen a
 * rotated-away key.
 */
export function signedWithinValidity(
	keys: VerifiedAgentKeys,
	createdAt: string | undefined,
	history: boolean,
): boolean {
	if (history && keys.supersededAt === undefined) return false;
	const bounds = [keys.supersededAt, keys.revokedAt].filter(
		(bound): bound is number => bound !== undefined,
	);
	if (bounds.length === 0) return true;
	if (createdAt === undefined) return false;
	const created = instantMicros(createdAt);
	return created !== undefined && created <= Math.min(...bounds);
}

function fail(fault: KeyChainFault): never {
	throw new KeyChainError(fault);
}

const KEY32_SIZE = 32;
const MLKEM_PK_SIZE = 1184;
const MLDSA_PK_SIZE = 1952;

/** An optional server timestamp as epoch microseconds; present text that is not an instant is malformed. */
function optionalInstant(text: string | null | undefined): number | undefined {
	if (text === undefined || text === null) return undefined;
	const instant = instantMicros(text);
	if (instant === undefined) fail("malformed");
	return instant;
}

function decodeKey(text: string, size: number): Uint8Array {
	const bytes = fromBase64Url(text);
	if (bytes.length !== size) fail("malformed");
	return bytes;
}

function assertStrict(key: Uint8Array): void {
	try {
		assertStrictEd25519PublicKey(key);
	} catch {
		fail("weak_key");
	}
}

/**
 * The five checks a peer runs on the chain. Every failure is
 * `recipient key chain invalid`; the fault names the step that refused.
 */
export function verifyKeyChain(
	resp: PublishedKeys,
	expect: { agentId: string; gen?: number },
	pins: KeyPins,
): VerifiedAgentKeys {
	try {
		canonicalUuid(expect.agentId, "agent id");
	} catch {
		fail("malformed");
	}
	if (resp.agent_id !== expect.agentId) fail("malformed");
	if (expect.gen !== undefined && resp.key_gen !== expect.gen) fail("malformed");

	const signing = decodeKey(resp.signing_public_key.x, KEY32_SIZE);
	const encryption = decodeKey(resp.encryption_public_key.x, KEY32_SIZE);
	const mls = decodeKey(resp.mls_signing_public_key.x, KEY32_SIZE);
	const pqEncryption = decodeKey(resp.pq_encryption_public_key.x, MLKEM_PK_SIZE);
	const pqSigning = decodeKey(resp.pq_signing_public_key.x, MLDSA_PK_SIZE);
	const orgSigning = decodeKey(resp.org_signing_public_key, KEY32_SIZE);
	const orgPqSigning = decodeKey(resp.org_pq_signing_public_key, MLDSA_PK_SIZE);

	assertStrict(signing);
	assertStrict(mls);
	assertStrict(orgSigning);

	if (orgIdFromKeys(orgSigning, orgPqSigning) !== resp.org_id) fail("org_id");

	let branchCert: ReturnType<typeof verifyBranchCert>;
	try {
		branchCert = verifyBranchCert(resp.branch_certificate, orgSigning);
	} catch {
		fail("branch_cert");
	}
	if (branchCert.org !== resp.org_id || branchCert.branch !== resp.branch) {
		fail("branch_cert");
	}
	const branchSigning = decodeKey(branchCert.sig, KEY32_SIZE);
	assertStrict(branchSigning);

	let agentCert: ReturnType<typeof verifyAgentCert>;
	try {
		agentCert = verifyAgentCert(resp.agent_certificate, branchSigning);
	} catch {
		fail("agent_cert");
	}
	if (
		agentCert.agent !== resp.agent_id ||
		agentCert.org !== resp.org_id ||
		agentCert.branch !== resp.branch ||
		agentCert.gen !== resp.key_gen ||
		agentCert.enc !== toBase64Url(encryption) ||
		agentCert.sig !== toBase64Url(signing) ||
		agentCert.mls !== toBase64Url(mls) ||
		agentCert.kem !== toBase64Url(sha256(pqEncryption)) ||
		agentCert.dsa !== toBase64Url(sha256(pqSigning))
	) {
		fail("field_mismatch");
	}

	const supersededAt = optionalInstant(resp.superseded_at);
	const revokedAt = optionalInstant(resp.revoked_at);

	const verified: VerifiedAgentKeys = {
		agentId: resp.agent_id,
		orgId: resp.org_id,
		branch: resp.branch,
		keyGen: resp.key_gen,
		signing,
		encryption,
		pqEncryption,
		pqSigning,
		mls,
		orgSigning,
		...(supersededAt === undefined ? {} : { supersededAt }),
		...(revokedAt === undefined ? {} : { revokedAt }),
	};
	pins.check(verified, { current: expect.gen === undefined });
	return verified;
}
