// Certificates, assertions and the register PoP. Port of
// scripts/vectors/lib/claims.mjs; the byte formats are pinned by
// scripts/vectors/sections/certs.mjs. The branch escrow key check lives in
// escrow-key.ts.
import { sha256 } from "@noble/hashes/sha2.js";
import type { AgentDerivedKeys, BranchKeys, OrgKeys } from "./derive.js";
import { type JcsObject, JwsError, JwsTyp, signJws, verifyJws } from "./jws.js";
import { toBase64Url } from "./keys.js";

export type BranchCertClaims = {
	branch: string;
	dsa: string;
	esck: string;
	escx: string;
	iat: number;
	org: string;
	rdr: string;
	sig: string;
	v: number;
};
export type AgentCertClaims = {
	agent: string;
	branch: string;
	dsa: string;
	enc: string;
	gen: number;
	iat: number;
	kem: string;
	mls: string;
	org: string;
	sig: string;
	v: number;
};
export type AssertionClaims = {
	aud: string;
	exp: number;
	iat: number;
	iss: string;
	jti: string;
	sub: string;
};
export type RegisterPopClaims = {
	aud: string;
	challenge_id: string;
	dsa: string;
	org: string;
	rdr: string;
	v: number;
};

/** A cert claim digest is `b64u(sha256(publicKey))`. */
const digest = (publicKey: Uint8Array): string => toBase64Url(sha256(publicKey));

export function branchCertClaims(
	orgId: string,
	branch: BranchKeys,
	iat: number,
): BranchCertClaims {
	return {
		branch: branch.name,
		dsa: digest(branch.mlDsa65.publicKey),
		esck: digest(branch.escrowMlKem768.publicKey),
		escx: toBase64Url(branch.escrowX25519.publicKey),
		iat,
		org: orgId,
		rdr: toBase64Url(branch.reader.publicKey),
		sig: toBase64Url(branch.ed25519.publicKey),
		v: 1,
	};
}

export function agentCertClaims(
	orgId: string,
	agent: AgentDerivedKeys,
	iat: number,
): AgentCertClaims {
	return {
		agent: agent.id,
		branch: agent.branch,
		dsa: digest(agent.mlDsa65.publicKey),
		enc: toBase64Url(agent.x25519.publicKey),
		gen: agent.gen,
		iat,
		kem: digest(agent.mlKem768.publicKey),
		mls: toBase64Url(agent.mlsEd25519.publicKey),
		org: orgId,
		sig: toBase64Url(agent.ed25519.publicKey),
		v: 1,
	};
}

export function assertionClaims(
	baseUrl: string,
	principal: string,
	jti: string,
	iat: number,
): AssertionClaims {
	return {
		aud: `${baseUrl.replace(/\/+$/, "")}/oauth/token`,
		exp: iat + 60,
		iat,
		iss: principal,
		jti,
		sub: principal,
	};
}

export function registerPopClaims(
	baseUrl: string,
	org: Pick<OrgKeys, "orgId" | "reader" | "mlDsa65">,
	challengeId: string,
): RegisterPopClaims {
	return {
		aud: `${baseUrl}/auth/register/solve`,
		challenge_id: challengeId,
		dsa: digest(org.mlDsa65.publicKey),
		org: org.orgId,
		rdr: toBase64Url(org.reader.publicKey),
		v: 1,
	};
}

export function issueBranchCert(
	org: OrgKeys,
	branch: BranchKeys,
	iat: number,
): string {
	return signJws(
		JwsTyp.BranchCert,
		branchCertClaims(org.orgId, branch, iat),
		org.ed25519.privateKey,
	);
}

export function issueAgentCert(
	org: Pick<OrgKeys, "orgId">,
	branch: BranchKeys,
	agent: AgentDerivedKeys,
	iat: number,
): string {
	return signJws(
		JwsTyp.AgentCert,
		agentCertClaims(org.orgId, agent, iat),
		branch.ed25519.privateKey,
	);
}

type ClaimField = "string" | "number";
type ClaimSpec = Record<string, ClaimField>;

/** Exact claim shape: every listed key present with the right type, `v === 1`, no extras. */
function checkClaims<T>(claims: JcsObject, spec: ClaimSpec): T {
	const expected = Object.keys(spec);
	if (Object.keys(claims).length !== expected.length) {
		throw new JwsError("cert: claim set does not match the certificate type");
	}
	for (const key of expected) {
		const value = claims[key];
		const kind = spec[key];
		if (kind === "string" ? typeof value !== "string" : typeof value !== "number") {
			throw new JwsError(`cert: claim ${key} has the wrong type`);
		}
	}
	if (claims.v !== 1) {
		throw new JwsError("cert: unsupported certificate version");
	}
	return claims as unknown as T;
}

const BRANCH_CERT_SPEC: ClaimSpec = {
	branch: "string",
	dsa: "string",
	esck: "string",
	escx: "string",
	iat: "number",
	org: "string",
	rdr: "string",
	sig: "string",
	v: "number",
};

const AGENT_CERT_SPEC: ClaimSpec = {
	agent: "string",
	branch: "string",
	dsa: "string",
	enc: "string",
	gen: "number",
	iat: "number",
	kem: "string",
	mls: "string",
	org: "string",
	sig: "string",
	v: "number",
};

export function verifyBranchCert(
	compact: string,
	orgEd25519Pk: Uint8Array,
): BranchCertClaims {
	return checkClaims<BranchCertClaims>(
		verifyJws(compact, orgEd25519Pk, JwsTyp.BranchCert),
		BRANCH_CERT_SPEC,
	);
}

export function verifyAgentCert(
	compact: string,
	branchEd25519Pk: Uint8Array,
): AgentCertClaims {
	return checkClaims<AgentCertClaims>(
		verifyJws(compact, branchEd25519Pk, JwsTyp.AgentCert),
		AGENT_CERT_SPEC,
	);
}
