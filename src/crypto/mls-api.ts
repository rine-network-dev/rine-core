import type { HttpClient } from "../http.js";

// MLS server uses standard base64 (not base64url)
function toBase64(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64");
}

function fromBase64(s: string): Uint8Array {
	return new Uint8Array(Buffer.from(s, "base64"));
}

export { toBase64 as mlsToBase64, fromBase64 as mlsFromBase64 };

export interface MlsInitResponse {
	mls_pending: boolean;
	members: { agent_id: string; has_key_package: boolean }[];
}

export interface MlsCommitBody {
	commit: string;
	welcomes?: { agent_id: string; welcome: string }[];
	group_info?: string;
	cipher_suite?: number;
	epoch?: number;
	/**
	 * The agents this commit's Remove proposals take out of the ratchet tree.
	 * The server records the list and spends each name once,
	 * on `DELETE /groups/{id}/members/{id}` — a commit that declares nobody can
	 * be named in no removal.
	 *
	 * It is **client-asserted**: the commit blob is opaque to a passthrough
	 * server, so nothing server-side confirms that the commit really carries a
	 * Remove for these agents. What declaring buys is that the claim is
	 * made once, in advance, and is spendable once.
	 */
	removes?: string[];
}

export interface MlsCommitResponse {
	epoch: number | null;
	delivered_to: number;
	// False for an open-enrollment tentative commit awaiting a peer ACK.
	// Observability-only — the client adopts local state after the 200 either way.
	confirmed?: boolean;
}

export interface MlsAckResponse {
	confirmed: boolean;
	acks: number;
	needed: number;
}

export interface MlsNackResponse {
	quarantined: boolean;
}

export interface MlsHandshakeEntry {
	id: string;
	epoch: number | null;
	blob: string;
	created_at: string;
}

export interface MlsWelcomeEntry {
	id: string;
	group_id: string | null;
	blob: string;
	created_at: string;
}

export interface MlsGroupInfoResponse {
	group_info: string | null;
	epoch: number | null;
}

export async function uploadKeyPackages(
	client: HttpClient,
	agentId: string,
	packages: string[],
): Promise<{ stored: number }> {
	return (await client.post(`/agents/${agentId}/mls/key-packages`, {
		packages,
	})) as { stored: number };
}

export async function claimKeyPackages(
	client: HttpClient,
	agentId: string,
	count = 1,
): Promise<{ packages: string[]; agent_id: string }> {
	return (await client.get(`/agents/${agentId}/mls/key-packages`, {
		count: String(count),
	})) as { packages: string[]; agent_id: string };
}

/** One agent's claimed KeyPackages in a batch claim. */
export interface MlsKeyPackageClaim {
	agent_id: string;
	packages: string[];
}

/**
 * Claim KeyPackages for many agents in one request.
 *
 * A claim consumes one-time-use KeyPackages, which is why reading them is a
 * POST. Authorization is per agent id and identical to the single-agent route —
 * a batch is not an authorization shortcut. An agent with none available comes
 * back with an empty `packages` array rather than an error or a missing entry,
 * so the caller can tell "none available" from "not asked".
 *
 * The server caps `agent_ids` per request; callers chunk to
 * `MLS_CLAIM_AGENTS_MAX` (`claimFoundingKeyPackages` in `mls-founding.ts`).
 *
 * The route lives under `/agents`, like the batch `GET /agents/keys` it mirrors,
 * because rine has no top-level `/mls` prefix and Caddy has no handle for one —
 * a client that invents one 404s in production against the landing server's
 * catch-all while every local test passes.
 */
export async function claimKeyPackagesBatch(
	client: HttpClient,
	agentIds: string[],
	countPerAgent = 1,
): Promise<{ claims: MlsKeyPackageClaim[] }> {
	return (await client.post("/agents/mls/key-packages/claim", {
		agent_ids: agentIds,
		count_per_agent: countPerAgent,
	})) as { claims: MlsKeyPackageClaim[] };
}

export async function mlsInit(
	client: HttpClient,
	groupId: string,
	extraHeaders?: Record<string, string>,
): Promise<MlsInitResponse> {
	return (await client.post(
		`/groups/${groupId}/mls/init`,
		{},
		extraHeaders,
	)) as MlsInitResponse;
}

export async function mlsCommit(
	client: HttpClient,
	groupId: string,
	body: MlsCommitBody,
	extraHeaders?: Record<string, string>,
): Promise<MlsCommitResponse> {
	return (await client.post(
		`/groups/${groupId}/mls/commit`,
		body,
		extraHeaders,
	)) as MlsCommitResponse;
}

/**
 * ACK a handshake the local client processed cleanly. Once MLS_ACK_QUORUM
 * distinct clean ACKs land server-side, the tentative commit + its GroupInfo are
 * confirmed and mls_confirmed_epoch advances. extraHeaders is threaded so a
 * multi-agent client ACKs as the right acting agent (sibling /groups bug: do not
 * drop extraHeaders here).
 */
export async function mlsAck(
	client: HttpClient,
	groupId: string,
	body: { object_id: string },
	extraHeaders?: Record<string, string>,
): Promise<MlsAckResponse> {
	return (await client.post(
		`/groups/${groupId}/mls/ack`,
		body,
		extraHeaders,
	)) as MlsAckResponse;
}

/**
 * NACK a handshake the local client could NOT process. The server marks the
 * delivery and lazily rolls the tentative commit back. A NACK is non-destructive:
 * it only ever un-advances unconfirmed, never-served state. extraHeaders threaded.
 */
export async function mlsNack(
	client: HttpClient,
	groupId: string,
	body: { object_id: string; epoch: number; reason?: string },
	extraHeaders?: Record<string, string>,
): Promise<MlsNackResponse> {
	return (await client.post(
		`/groups/${groupId}/mls/nack`,
		body,
		extraHeaders,
	)) as MlsNackResponse;
}

export async function fetchHandshakes(
	client: HttpClient,
	groupId: string,
	sinceEpoch?: number,
	extraHeaders?: Record<string, string>,
): Promise<{ handshakes: MlsHandshakeEntry[] }> {
	const params: Record<string, string> = {};
	if (sinceEpoch !== undefined) params["since_epoch"] = String(sinceEpoch);
	return (await client.get(
		`/groups/${groupId}/mls/handshakes`,
		params,
		extraHeaders,
	)) as { handshakes: MlsHandshakeEntry[] };
}

export async function fetchWelcomes(
	client: HttpClient,
	agentId: string,
): Promise<{ welcomes: MlsWelcomeEntry[] }> {
	return (await client.get(`/agents/${agentId}/mls/welcomes`)) as {
		welcomes: MlsWelcomeEntry[];
	};
}

export async function fetchGroupInfo(
	client: HttpClient,
	groupId: string,
	extraHeaders?: Record<string, string>,
): Promise<MlsGroupInfoResponse> {
	return (await client.get(
		`/groups/${groupId}/mls/group-info`,
		undefined,
		extraHeaders,
	)) as MlsGroupInfoResponse;
}
