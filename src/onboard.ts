import type { AgentRead } from "./api-types.js";
import { cacheToken, loadCredentials, saveCredentials } from "./config.js";
import {
	encryptionPublicKeyToJWK,
	generateAgentKeys,
	pqPublicKeyToJWK,
	saveAgentKeys,
	signingPublicKeyToJWK,
} from "./crypto/index.js";
import { fetchOAuthToken } from "./http.js";
import type { HttpClient } from "./http.js";
import { publishMlsKeyPackages } from "./mls-ops.js";
import { solveTimeLockWithProgress } from "./timelock.js";

interface ChallengeResponse {
	challenge_id: string;
	prefix: string;
	modulus: string;
	difficulty: number;
	algorithm: string;
	expires_in: number;
}

interface RegisterSolveResponse {
	org_id: string;
	client_id: string;
	client_secret: string;
}

/** Validate an org slug: 2-32 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphen. */
export function validateSlug(slug: string): boolean {
	return /^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$/.test(slug);
}

/**
 * Full registration flow: challenge → validate → solve PoW → save credentials → cache token.
 * Throws typed error messages on failure.
 */
export async function performRegistration(
	apiUrl: string,
	configDir: string,
	profile: string,
	params: { email: string; slug: string; name: string },
	onProgress?: (pct: number) => void,
): Promise<{ org_id: string; client_id: string }> {
	// Step 1: POST /auth/register → PoW challenge
	const challengeRes = await fetch(`${apiUrl}/auth/register`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ email: params.email, org_slug: params.slug }),
	});
	if (challengeRes.status === 409)
		throw new Error("Email or slug already registered");
	if (challengeRes.status === 429)
		throw new Error("Rate limited — please wait before retrying");
	if (!challengeRes.ok) {
		const body = (await challengeRes.json().catch(() => ({}))) as {
			detail?: unknown;
		};
		const detail =
			typeof body.detail === "string"
				? body.detail
				: body.detail
					? JSON.stringify(body.detail)
					: challengeRes.statusText;
		throw new Error(`Registration failed: ${detail}`);
	}
	const challenge = (await challengeRes.json()) as ChallengeResponse;

	// Step 2: Validate algorithm
	if (challenge.algorithm !== "rsa-timelock-v1") {
		throw new Error(
			`Unsupported algorithm: ${challenge.algorithm}. Please upgrade.`,
		);
	}

	// Step 3: Solve PoW
	const nonce = await solveTimeLockWithProgress(
		challenge.prefix,
		challenge.modulus,
		challenge.difficulty,
		onProgress,
	);

	// Step 4: POST /auth/register/solve
	const solveRes = await fetch(`${apiUrl}/auth/register/solve`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			challenge_id: challenge.challenge_id,
			nonce,
			org_name: params.name,
			org_slug: params.slug,
			consent: true,
		}),
	});
	if (solveRes.status === 409)
		throw new Error("Conflict: email or slug already registered");
	if (solveRes.status === 410)
		throw new Error("Challenge expired — please try again");
	if (!solveRes.ok) {
		const body = (await solveRes.json().catch(() => ({}))) as {
			detail?: unknown;
		};
		const detail =
			typeof body.detail === "string"
				? body.detail
				: body.detail
					? JSON.stringify(body.detail)
					: solveRes.statusText;
		throw new Error(`Solve failed: ${detail}`);
	}
	const data = (await solveRes.json()) as RegisterSolveResponse;

	// Step 5: Save credentials
	const creds = loadCredentials(configDir);
	creds[profile] = {
		client_id: data.client_id,
		client_secret: data.client_secret,
	};
	saveCredentials(configDir, creds);

	// Step 6: Cache initial token (non-fatal)
	try {
		const tokenData = await fetchOAuthToken(
			apiUrl,
			data.client_id,
			data.client_secret,
		);
		cacheToken(configDir, profile, tokenData);
	} catch {
		// token cache failure is non-fatal
	}

	return { org_id: data.org_id, client_id: data.client_id };
}

/** Minimal client interface — only `post` is needed for agent creation. */
interface ApiPoster {
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
 * Create an agent: generate keys, POST to API, save keys + poll_url.
 */
export async function performAgentCreation(
	client: ApiPoster,
	configDir: string,
	profile: string,
	params: {
		name: string;
		humanOversight?: boolean;
		unlisted?: boolean;
		/**
		 * Run SPIFFE identity verification after the agent is created. Auto-enabled
		 * by the caller when `SPIFFE_ENDPOINT_SOCKET` is present or `--verify-identity`
		 * is passed. The verification result is returned alongside the agent.
		 */
		verifyIdentity?: boolean;
		/** Caller-supplied JWT-SVID for the verification step (see verifyIdentitySpiffe). */
		svid?: string;
		log?: (message: string) => void;
	},
): Promise<
	AgentRead & {
		poll_url?: string;
		identity?: VerifyIdentityResult;
		identityError?: string;
	}
> {
	const agentKeys = generateAgentKeys();

	const body: Record<string, unknown> = {
		name: params.name,
		signing_public_key: signingPublicKeyToJWK(agentKeys.signing.publicKey),
		encryption_public_key: encryptionPublicKeyToJWK(
			agentKeys.encryption.publicKey,
		),
	};
	if (agentKeys.pqEncryption) {
		body.pq_encryption_public_key = pqPublicKeyToJWK(
			agentKeys.pqEncryption.publicKey,
		);
	}
	if (params.humanOversight !== undefined)
		body.human_oversight = params.humanOversight;
	if (params.unlisted !== undefined) body.unlisted = params.unlisted;

	const agent = (await client.post("/agents", body)) as AgentRead & {
		poll_url?: string;
		identity?: VerifyIdentityResult;
		identityError?: string;
	};

	saveAgentKeys(configDir, agent.id, agentKeys);

	// Publish an initial batch of MLS KeyPackages so the agent can be added to
	// MLS groups from birth. Best-effort: a failure here must never abort agent
	// creation (the agent works fine on sender-key groups without them, and
	// KeyPackages can be republished later). Only `.post` is used.
	try {
		await publishMlsKeyPackages(
			configDir,
			agent.id,
			client as unknown as HttpClient,
		);
	} catch {
		// non-fatal — agent is usable; KeyPackages can be published later
	}

	// Save poll_url to credentials if returned
	if (agent.poll_url) {
		const creds = loadCredentials(configDir);
		if (creds[profile]) {
			creds[profile].poll_url = agent.poll_url;
			saveCredentials(configDir, creds);
		}
	}

	// SPIFFE identity verification (REQ-SPF-10): run when explicitly requested, when a
	// SPIFFE Workload API endpoint is present, or when the caller supplied an explicit
	// `--svid` (passing an SVID without `--verify-identity` must NOT silently discard it).
	// The agent already exists, so a verification FAILURE must not undo creation nor
	// suppress the creation-success output — it is captured in `identityError` for the
	// caller to surface as a warning (never swallowed).
	if (params.verifyIdentity || hasSpiffeEndpoint() || params.svid) {
		try {
			agent.identity = await verifyIdentitySpiffe(client, agent.id, {
				svid: params.svid,
				log: params.log,
			});
		} catch (err) {
			agent.identityError =
				err instanceof Error ? err.message : String(err);
		}
	}

	return agent;
}
