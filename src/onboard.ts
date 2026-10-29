// User-held registration: the client mints the org root, derives
// every key, and the server only ever sees public keys, a branch cert and a PoP.
import { MAIN_BRANCH, principalString, PrincipalKind } from "./principal.js";
import { saveProfiles } from "./profiles.js";
import { cacheToken } from "./config.js";
import { orgSigner } from "./assertion.js";
import type { CustodyDirs } from "./custody.js";
import {
	JwsTyp,
	deriveBranch,
	deriveOrg,
	orgWords,
	registerPopClaims,
	signJws,
	toBase64Url,
} from "./crypto/index.js";
import { branchPublication } from "./org-branch.js";
import { fetchOAuthToken } from "./token.js";
import {
	PHRASE_FILE,
	assertFreshOwnerDir,
	removeOwnerFiles,
	saveRoot,
} from "./owner.js";
import { solveTimeLockWithProgress } from "./timelock.js";
import { join } from "node:path";

interface ChallengeResponse {
	challenge_id: string;
	prefix: string;
	modulus: string;
	difficulty: number;
	algorithm: string;
	expires_in: number;
}

export interface RegistrationResult {
	org_id: string;
	/** The 8 org verification words: safe to print, they are not the phrase. */
	org_words: string;
	/** Where the 24-word phrase was written. The phrase itself is never returned. */
	phrase_path: string;
}

/** Validate an org slug: 2-32 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphen. */
export function validateSlug(slug: string): boolean {
	return /^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$/.test(slug);
}

/** The server's `detail`, or "" when the body carries none. */
async function bodyDetail(res: Response): Promise<string> {
	const body = (await res.json().catch(() => ({}))) as { detail?: unknown };
	if (typeof body.detail === "string") return body.detail;
	return body.detail ? JSON.stringify(body.detail) : "";
}

async function failureDetail(res: Response): Promise<string> {
	return (await bodyDetail(res)) || res.statusText;
}

/**
 * The 409 message on both registration calls. The server names which value collided
 * (email, slug or org id) in `detail`; only the slug has a code of its own, so the sentence
 * is the one signal for all three.
 */
async function conflictMessage(res: Response): Promise<string> {
	const detail = await bodyDetail(res);
	return `Conflict: ${detail || "email, slug or org id already registered"}`;
}

const b64 = toBase64Url;

/**
 * Full registration flow: mint `R` → challenge → solve PoW → save the root → solve.
 *
 * `root.key` and the phrase are written BEFORE `POST /auth/register/solve`: an org
 * whose root only ever lived in memory would be unrecoverable if the process died
 * after the server committed. They are removed again only when the solve request
 * itself is answered with a definitive refusal (a 4xx); a network failure or a 5xx
 * keeps them, because the org may exist. An answer to any other request proves
 * nothing, so a later 401 can never delete the only copy of the root.
 */
export async function performRegistration(
	apiUrl: string,
	dirs: CustodyDirs,
	profile: string,
	params: { email: string; slug: string; name: string },
	onProgress?: (pct: number) => void,
): Promise<RegistrationResult> {
	assertFreshOwnerDir(dirs.ownerDir, dirs.configDir);
	const root = crypto.getRandomValues(new Uint8Array(32));
	const org = deriveOrg(root);
	const main = deriveBranch(org, MAIN_BRANCH);

	// Step 1: POST /auth/register → PoW challenge
	const challengeRes = await fetch(`${apiUrl}/auth/register`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			email: params.email,
			org_slug: params.slug,
			org_id: org.orgId,
			org_signing_public_key: b64(org.ed25519.publicKey),
			org_pq_signing_public_key: b64(org.mlDsa65.publicKey),
		}),
	});
	if (challengeRes.status === 409)
		throw new Error(await conflictMessage(challengeRes));
	if (challengeRes.status === 429)
		throw new Error("Rate limited — please wait before retrying");
	if (!challengeRes.ok) {
		throw new Error(`Registration failed: ${await failureDetail(challengeRes)}`);
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

	// Step 4: keep the root, then POST /auth/register/solve
	saveRoot(dirs.ownerDir, root);
	saveProfiles(dirs.ownerDir, {
		[profile]: {
			org_id: org.orgId,
			principal: principalString({ kind: PrincipalKind.Org, orgId: org.orgId }),
		},
	});
	const solveRes = await fetch(`${apiUrl}/auth/register/solve`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			challenge_id: challenge.challenge_id,
			nonce,
			org_name: params.name,
			org_slug: params.slug,
			consent: true,
			main_branch: branchPublication(org, main, Math.floor(Date.now() / 1000)),
			reader_public_key: b64(org.reader.publicKey),
			proof: signJws(
				JwsTyp.RegisterPop,
				registerPopClaims(apiUrl, org, challenge.challenge_id),
				org.ed25519.privateKey,
			),
		}),
	});
	if (!solveRes.ok) {
		if (solveRes.status < 500) removeOwnerFiles(dirs.ownerDir);
		if (solveRes.status === 409)
			throw new Error(await conflictMessage(solveRes));
		if (solveRes.status === 410)
			throw new Error("Challenge expired — please try again");
		throw new Error(`Solve failed: ${await failureDetail(solveRes)}`);
	}
	const data = (await solveRes.json()) as { org_id: string };
	if (data.org_id !== org.orgId) {
		throw new Error(
			`The server registered org ${data.org_id}, not the org this root derives (${org.orgId}). The root is kept in ${dirs.ownerDir}.`,
		);
	}

	// Step 5: cache an initial org token in the owner dir (non-fatal)
	try {
		const signer = orgSigner(org);
		cacheToken(
			dirs.ownerDir,
			principalString(signer.principal),
			await fetchOAuthToken(apiUrl, signer),
		);
	} catch {
		// token cache failure is non-fatal
	}

	return {
		org_id: org.orgId,
		org_words: orgWords(org.orgId),
		phrase_path: join(dirs.ownerDir, PHRASE_FILE),
	};
}
