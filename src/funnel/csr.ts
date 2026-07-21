// rine Funnel local keypair + CSR + ACME directory selection.
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
const HOOK_ZONE_SUFFIX = `.${HOOK_ZONE}`;

/**
 * The per-agent wildcard FQDN a zero-trust relay terminates TLS for.
 * ONE `*.{agentLabel}.hook.rine.network` cert covers EVERY hook
 * of that agent — the cert win is the SAN cardinality dropping to one,
 * independent of how many hooks the agent owns.
 */
export function agentWildcardFqdn(agentLabel: string): string {
	return `*.${agentLabel}.${HOOK_ZONE}`;
}

/**
 * EXTRACT the agent label from a zero-trust hostname — the DNS label
 * immediately before `.hook.rine.network` (the second-to-last label of
 * `{hook}.{agentLabel}.hook.rine.network`). It is an OPAQUE string read off the
 * server-authoritative hostname: the relay never sees the agent UUID and never
 * re-encodes it (the backend `funnel_naming.agent_label` is the SOLE encoder).
 * Keying the cert cache by this label collapses all of an agent's
 * hook-relays onto ONE shared wildcard.
 *
 * Throws on a non-`.hook` hostname (e.g. a shared-edge `.edge` host) so a
 * mis-tiered host can never be fed into the zero-trust cert path.
 */
export function agentLabel(hostname: string): string {
	if (!hostname.endsWith(HOOK_ZONE_SUFFIX)) {
		throw new Error(`not a zero-trust .hook hostname: ${hostname}`);
	}
	const prefix = hostname.slice(0, -HOOK_ZONE_SUFFIX.length);
	const labels = prefix.split(".");
	const label = labels[labels.length - 1];
	if (!label) {
		throw new Error(`no agent label in hostname: ${hostname}`);
	}
	return label;
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
 * Generate a fresh EC P-256 keypair (node:crypto) and a CSR for the per-agent
 * wildcard `*.{agentLabel}.hook.rine.network` whose CN and SINGLE SAN are that
 * wildcard (SAN cardinality == 1, independent of hook_name). The
 * argument is the AGENT label (the relay never sees the UUID); one cert covers
 * every hook of the agent. A fresh, unique key is minted on every call — no key
 * reuse across issuances/renewals.
 */
export async function generateCertKeypairAndCsr(
	agentLabel: string,
): Promise<KeypairAndCsr> {
	const fqdn = agentWildcardFqdn(agentLabel);
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
