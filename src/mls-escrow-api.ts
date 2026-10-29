// The two MLS read-escrow HTTP calls. Kept out of
// `crypto/mls-api.ts` because that module belongs to the MLS group-state owner;
// these two are the escrow read's own routes.
//
// Both paths are template literals with the variable spliced in, like
// `crypto/mls-api.ts` does, so the client⇄server contract gate can extract them
// and resolve them against the server's routes.
import type { BranchEscrowKeyResponse } from "./crypto/escrow-key.js";
import type { HttpClient } from "./http.js";

/** The `PUT /groups/{groupId}/mls/escrow/{epoch}` body; every field is base64url. */
export interface EscrowUploadBody {
	fp: string;
	sealed: string;
	key_gen: number;
	sig: string;
}

/**
 * PUT /groups/{groupId}/mls/escrow/{epoch}; resolves on 201 and 200 (an
 * identical row), throws RineApiError otherwise.
 *
 * The client already treats every 2xx as success, so the two statuses need no
 * branch here: 201 is the first upload of the slot and 200 is the server
 * recognising a byte-identical retry, and both mean the escrow is stored.
 */
export async function uploadEscrow(
	client: HttpClient,
	groupId: string,
	epoch: number,
	body: EscrowUploadBody,
	extraHeaders?: Record<string, string>,
): Promise<void> {
	await client.put(
		`/groups/${groupId}/mls/escrow/${epoch}`,
		body,
		extraHeaders,
	);
}

/** GET /orgs/me/branches/{branch}/escrow-key (encodeURIComponent the branch). */
export async function fetchBranchEscrowKey(
	client: HttpClient,
	branch: string,
	extraHeaders?: Record<string, string>,
): Promise<BranchEscrowKeyResponse> {
	return (await client.get(
		`/orgs/me/branches/${encodeURIComponent(branch)}/escrow-key`,
		undefined,
		extraHeaders,
	)) as BranchEscrowKeyResponse;
}
