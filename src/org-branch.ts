/**
 * Creating and revoking a delegated branch: the org root publishes
 * the branch's public keys and certificate; the branch's secrets travel to the
 * delegate sealed (`crypto/recipient-key.ts`), never through the server.
 */
import {
	type BranchKeys,
	type OrgKeys,
	assertBranchName,
	issueBranchCert,
	toBase64Url,
} from "./crypto/index.js";
import type { HttpClient } from "./http.js";

/** The public half of a branch as the server stores it: keys and the org-signed certificate. */
export function branchPublication(org: OrgKeys, branch: BranchKeys, nowS: number) {
	const b64 = toBase64Url;
	return {
		signing_public_key: b64(branch.ed25519.publicKey),
		pq_signing_public_key: b64(branch.mlDsa65.publicKey),
		escrow_public_key: b64(branch.escrowX25519.publicKey),
		escrow_pq_public_key: b64(branch.escrowMlKem768.publicKey),
		reader_public_key: b64(branch.reader.publicKey),
		certificate: issueBranchCert(org, branch, nowS),
	};
}

/** `POST /orgs/me/branches`: publish a branch. Org principal only. */
export async function createBranch(
	client: HttpClient,
	org: OrgKeys,
	branch: BranchKeys,
): Promise<void> {
	await client.post("/orgs/me/branches", {
		name: branch.name,
		...branchPublication(org, branch, Math.floor(Date.now() / 1000)),
	});
}

/**
 * `DELETE /orgs/me/branches/{name}`: revoke a branch. The name is checked before it reaches a path.
 * The server refuses to revoke `main` or the org's last live branch unless `confirm` is set.
 */
export async function revokeBranch(
	client: HttpClient,
	name: string,
	confirm = false,
): Promise<void> {
	await client.delete(
		`/orgs/me/branches/${encodeURIComponent(assertBranchName(name))}`,
		undefined,
		{ confirm },
	);
}
