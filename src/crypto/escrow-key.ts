// The branch escrow key check (steps 1-3 of the branch escrow key read). Split
// out of certs.ts to keep both modules small; certs.ts does not re-export it.
import { sha256 } from "@noble/hashes/sha2.js";
import { equalBytes } from "./bytes.js";
import { verifyAgentCert, verifyBranchCert } from "./certs.js";
import { orgIdFromKeys } from "./derive.js";
import type { VerifiedEscrowKey } from "./escrow.js";
import { fromBase64Url, toBase64Url } from "./keys.js";

export class BranchEscrowKeyError extends Error {}

/** Wire shape of `GET /orgs/me/branches/{name}/escrow-key`. */
export interface BranchEscrowKeyResponse {
	org_id: string;
	org_signing_public_key: string;
	org_pq_signing_public_key: string;
	branch: string;
	branch_certificate: string;
	escrow_public_key: string;
	escrow_pq_public_key: string;
}

/** What the client itself holds: its org id, its agent id, its signing key and its agent cert. */
export interface OwnIdentity {
	orgId: string;
	agentId: string;
	agentSigningPk: Uint8Array;
	agentCertificate: string;
}

const X25519_PK_SIZE = 32;
const MLKEM_PK_SIZE = 1184;
const INVALID = "branch escrow key invalid";

/**
 * Steps 1-3 of the branch escrow key read (step 4, the 410 `branch revoked`
 * handling, lives at the read). Every failure is `branch escrow key invalid`.
 */
export function verifyBranchEscrowKey(
	resp: BranchEscrowKeyResponse,
	own: OwnIdentity,
): VerifiedEscrowKey {
	try {
		const orgPk = fromBase64Url(resp.org_signing_public_key);
		const orgDsaPk = fromBase64Url(resp.org_pq_signing_public_key);
		if (
			orgIdFromKeys(orgPk, orgDsaPk) !== resp.org_id ||
			resp.org_id !== own.orgId
		) {
			throw new BranchEscrowKeyError(INVALID);
		}
		const branchCert = verifyBranchCert(resp.branch_certificate, orgPk);
		const agentCert = verifyAgentCert(
			own.agentCertificate,
			fromBase64Url(branchCert.sig),
		);
		if (
			!equalBytes(fromBase64Url(agentCert.sig), own.agentSigningPk) ||
			agentCert.org !== own.orgId ||
			agentCert.agent !== own.agentId
		) {
			throw new BranchEscrowKeyError(INVALID);
		}
		if (
			branchCert.org !== own.orgId ||
			branchCert.branch !== agentCert.branch ||
			branchCert.branch !== resp.branch
		) {
			throw new BranchEscrowKeyError(INVALID);
		}
		const x25519 = fromBase64Url(resp.escrow_public_key);
		const mlKem = fromBase64Url(resp.escrow_pq_public_key);
		if (x25519.length !== X25519_PK_SIZE || mlKem.length !== MLKEM_PK_SIZE) {
			throw new BranchEscrowKeyError(INVALID);
		}
		if (
			branchCert.escx !== toBase64Url(x25519) ||
			branchCert.esck !== toBase64Url(sha256(mlKem))
		) {
			throw new BranchEscrowKeyError(INVALID);
		}
		return { orgId: own.orgId, branch: branchCert.branch, x25519, mlKem };
	} catch (error) {
		if (error instanceof BranchEscrowKeyError) throw error;
		throw new BranchEscrowKeyError(INVALID);
	}
}
