// Signers and the client assertion for POST /oauth/token.
import { assertionClaims } from "./crypto/certs.js";
import type { BranchKeys, OrgKeys } from "./crypto/derive.js";
import { JwsTyp, signJws } from "./crypto/jws.js";
import { type AgentKeys, toBase64Url } from "./crypto/keys.js";
import { type Principal, PrincipalKind, principalString } from "./principal.js";

/** A principal and the Ed25519 seed that signs its assertions. */
export interface AssertionSigner {
	principal: Principal;
	seed: Uint8Array;
}

export function orgSigner(org: Pick<OrgKeys, "orgId" | "ed25519">): AssertionSigner {
	return {
		principal: { kind: PrincipalKind.Org, orgId: org.orgId },
		seed: org.ed25519.privateKey,
	};
}

export function orgReaderSigner(
	org: Pick<OrgKeys, "orgId" | "reader">,
): AssertionSigner {
	return {
		principal: { kind: PrincipalKind.Reader, orgId: org.orgId },
		seed: org.reader.privateKey,
	};
}

export function branchSigner(
	orgId: string,
	branch: Pick<BranchKeys, "name" | "ed25519">,
): AssertionSigner {
	return {
		principal: { kind: PrincipalKind.Branch, orgId, name: branch.name },
		seed: branch.ed25519.privateKey,
	};
}

export function branchReaderSigner(
	orgId: string,
	branch: Pick<BranchKeys, "name" | "reader">,
): AssertionSigner {
	return {
		principal: { kind: PrincipalKind.Reader, orgId, name: branch.name },
		seed: branch.reader.privateKey,
	};
}

export function agentSigner(
	agentId: string,
	keys: Pick<AgentKeys, "signing">,
): AssertionSigner {
	return {
		principal: { kind: PrincipalKind.Agent, agentId },
		seed: keys.signing.privateKey,
	};
}

/**
 * A fresh compact assertion: a new 128-bit `jti` and `iat` on every call, because
 * the server accepts each `jti` once, so a retry must never reuse one.
 */
export function buildAssertion(
	signer: AssertionSigner,
	apiUrl: string,
	nowSeconds: number = Math.floor(Date.now() / 1000),
): string {
	const jti = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
	return signJws(
		JwsTyp.Assertion,
		assertionClaims(apiUrl, principalString(signer.principal), jti, nowSeconds),
		signer.seed,
	);
}
