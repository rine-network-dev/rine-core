import type { AgentRead } from "./api-types.js";
import {
	cacheToken,
	loadCredentials,
	saveCredentials,
} from "./config.js";
import { fetchOAuthToken } from "./http.js";
import {
	generateAgentKeys,
	saveAgentKeys,
	signingPublicKeyToJWK,
	encryptionPublicKeyToJWK,
	pqPublicKeyToJWK,
} from "./crypto/index.js";
import { solveTimeLockWithProgress } from "./timelock.js";
import { publishMlsKeyPackages } from "./mls-ops.js";
import type { HttpClient } from "./http.js";

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
		const detail = typeof body.detail === "string"
			? body.detail
			: body.detail ? JSON.stringify(body.detail) : challengeRes.statusText;
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
		const detail = typeof body.detail === "string"
			? body.detail
			: body.detail ? JSON.stringify(body.detail) : solveRes.statusText;
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

/**
 * Create an agent: generate keys, POST to API, save keys + poll_url.
 */
export async function performAgentCreation(
	client: ApiPoster,
	configDir: string,
	profile: string,
	params: { name: string; humanOversight?: boolean; unlisted?: boolean },
): Promise<AgentRead & { poll_url?: string }> {
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
	};

	saveAgentKeys(configDir, agent.id, agentKeys);

	// Publish an initial batch of MLS KeyPackages so the agent can be added to
	// MLS groups from birth. Best-effort: a failure here must never abort agent
	// creation (the agent works fine on sender-key groups without them, and
	// KeyPackages can be republished later). Only `.post` is used.
	try {
		await publishMlsKeyPackages(configDir, agent.id, client as unknown as HttpClient);
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

	return agent;
}
