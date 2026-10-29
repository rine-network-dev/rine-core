/** Minimal client interface — only `post` is needed for agent creation. */
export interface ApiPoster {
	post(path: string, body?: unknown): Promise<unknown>;
}

/** Server response from `POST /agents/{id}/verify-svid/challenge`. */
interface SvidChallengeResponse {
	audience: string;
	expires_in: number;
}

/**
 * Server response from `POST /agents/{id}/verify-svid` — mirrors the backend
 * `VerifySvidResponse` schema. Re-exported as the public result of
 * `verifyIdentitySpiffe` so callers (CLI, future SDK surfaces) stay typed.
 */
export interface VerifyIdentityResult {
	agent_id: string;
	spiffe_id: string;
	trust_domain: string;
	trust_tier: number;
	verified_at: string;
}

export interface VerifyIdentitySpiffeOptions {
	/**
	 * A caller-supplied SPIFFE JWT-SVID. When present it is used directly for the
	 * audience minted by the challenge — the caller is responsible for fetching an
	 * SVID whose `aud` matches. When absent, an automatic fetch via the SPIFFE
	 * Workload API is attempted (see `autoFetchSvid`).
	 */
	svid?: string;
	/** Sink for human-readable diagnostics (defaults to `console.error`). */
	log?: (message: string) => void;
}

/**
 * Error thrown when SPIFFE identity verification cannot obtain an SVID — never a
 * silent no-op. Carries a machine-readable `reason` so callers can branch.
 */
export class SpiffeVerificationError extends Error {
	constructor(
		message: string,
		readonly reason: "no-svid" | "autofetch-unavailable",
	) {
		super(message);
		this.name = "SpiffeVerificationError";
	}
}

/** Env var that, when set by a SPIFFE workload, points at the Workload API socket. */
export const SPIFFE_ENDPOINT_SOCKET_ENV = "SPIFFE_ENDPOINT_SOCKET";

/** True when the process is running inside a SPIFFE-aware workload environment. */
export function hasSpiffeEndpoint(): boolean {
	return Boolean(process.env[SPIFFE_ENDPOINT_SOCKET_ENV]);
}

/**
 * Attempt to fetch a JWT-SVID for `audience` from the SPIFFE Workload API at
 * `SPIFFE_ENDPOINT_SOCKET` (the `FetchJWTSVID` RPC).
 *
 * No maintained, first-party Node Workload-API client is bundled (the registry
 * options are single-maintainer 0.x gRPC wrappers we will not pull into a
 * published crypto core). So this is intentionally a stub that reports the
 * auto-fetch path as unavailable — it NEVER silently returns nothing. Callers
 * fall back to the explicit `--svid` path. When a maintained client is adopted
 * later, only this function changes.
 */
async function autoFetchSvid(
	audience: string,
	log: (message: string) => void,
): Promise<string | undefined> {
	const socket = process.env[SPIFFE_ENDPOINT_SOCKET_ENV];
	if (!socket) return undefined;
	log(
		`SPIFFE Workload API detected at ${socket}, but automatic JWT-SVID fetch is not available in this build. Re-run with an explicit --svid <jwt> for audience '${audience}'.`,
	);
	return undefined;
}

/**
 * Prove control of a SPIFFE identity for `agentId` and elevate the org to trust
 * tier 2. Three steps, in order:
 *   1. `POST /agents/{id}/verify-svid/challenge` → a single-purpose `audience`.
 *   2. Obtain a JWT-SVID whose `aud` is that audience — prefer the Workload API
 *      auto-fetch, else the caller-supplied `opts.svid`.
 *   3. `POST /agents/{id}/verify-svid` with the SVID → typed result.
 *
 * Generic by design: the same shape can back DID/SDK verification surfaces later.
 * Throws {@link SpiffeVerificationError} (never a silent no-op) when no SVID can
 * be obtained, and propagates `RineApiError` from the HTTP layer for 4xx/5xx.
 */
export async function verifyIdentitySpiffe(
	client: ApiPoster,
	agentId: string,
	opts: VerifyIdentitySpiffeOptions = {},
): Promise<VerifyIdentityResult> {
	const log = opts.log ?? ((m: string) => console.error(m));

	const challenge = (await client.post(
		`/agents/${agentId}/verify-svid/challenge`,
	)) as SvidChallengeResponse;

	let svid = opts.svid;
	if (!svid) {
		svid = await autoFetchSvid(challenge.audience, log);
	}
	if (!svid) {
		if (hasSpiffeEndpoint()) {
			throw new SpiffeVerificationError(
				"SPIFFE Workload API auto-fetch is unavailable; supply a JWT-SVID via --svid.",
				"autofetch-unavailable",
			);
		}
		throw new SpiffeVerificationError(
			"No JWT-SVID provided and no SPIFFE Workload API endpoint detected; supply one via --svid.",
			"no-svid",
		);
	}

	return (await client.post(`/agents/${agentId}/verify-svid`, {
		svid,
	})) as VerifyIdentityResult;
}

/**
 * The post-create SPIFFE hook shared by every create path: verify when explicitly
 * requested, when a Workload API endpoint is present, or when the caller supplied an
 * explicit `svid` (passing one without `verifyIdentity` must NOT silently discard it).
 * The agent already exists, so a verification FAILURE must not undo creation nor
 * suppress the creation-success output — it comes back as `identityError` for the
 * caller to surface as a warning (never swallowed).
 */
export async function verifyNewAgent(
	client: ApiPoster,
	agentId: string,
	opts: { verifyIdentity?: boolean; svid?: string; log?: (message: string) => void },
): Promise<{ identity?: VerifyIdentityResult; identityError?: string }> {
	if (!(opts.verifyIdentity || hasSpiffeEndpoint() || opts.svid)) return {};
	try {
		return {
			identity: await verifyIdentitySpiffe(client, agentId, {
				svid: opts.svid,
				log: opts.log,
			}),
		};
	} catch (err) {
		return { identityError: err instanceof Error ? err.message : String(err) };
	}
}
