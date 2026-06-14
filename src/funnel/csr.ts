// rine Funnel local keypair + CSR + ACME directory selection (REQ-CERT-09/11).
//
// FROZEN-CONTRACT: the cert private key is born here via node:crypto and stays
// LOCAL. Only the CSR (which carries the PUBLIC key) is ever sent to Let's
// Encrypt; the private key is never serialized into any network call.

import { generateKeyPairSync } from "node:crypto";
import { crypto as acmeCrypto } from "acme-client";

// `acmeDirectoryUrl` lives next to the cache-path split (cert-cache.ts) so the
// directory_url and the staging cache subtree share one `isStaging` decision;
// it is re-exported here to keep the relay-facing import surface stable.
export { acmeDirectoryUrl } from "./cert-cache.js";

const HOOK_ZONE = "hook.rine.network";

/** The publicly-trusted hostname this relay terminates TLS for. */
export function hookFqdn(handle: string): string {
	return `${handle}.${HOOK_ZONE}`;
}

export interface KeypairAndCsr {
	/** Cert private key (PKCS#8 PEM) — LOCAL storage only, never transmitted. */
	keyPem: string;
	/** CSR (PEM) — the only artifact sent to LE; carries the public key only. */
	csrPem: string;
	commonName: string;
	subjectAltNames: string[];
	keyAlgorithm: "EC";
	keyCurve: string;
}

/**
 * Generate a fresh EC P-256 keypair (node:crypto) and a CSR for
 * `<handle>.hook.rine.network` whose CN and single SAN are that FQDN. A fresh,
 * unique key is minted on every call — no key reuse across issuances/renewals.
 */
export async function generateCertKeypairAndCsr(
	handle: string,
): Promise<KeypairAndCsr> {
	const fqdn = hookFqdn(handle);
	const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
	const [, csrBuf] = await acmeCrypto.createCsr(
		{ commonName: fqdn, altNames: [fqdn] },
		keyPem,
	);
	return {
		keyPem,
		csrPem: csrBuf.toString(),
		commonName: fqdn,
		subjectAltNames: [fqdn],
		keyAlgorithm: "EC",
		keyCurve: "P-256",
	};
}
