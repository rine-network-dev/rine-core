// rine Funnel one-shot ACME DNS-01 issuance (REQ-CERT-09/10). The injectable
// externals + the single-order issuance flow live here; the orchestrator
// (cert.ts) layers cache reuse, persisted backoff, and the readiness gate on top.
//
// FROZEN-CONTRACT enforced here: DNS-01 is the ONLY solver (no http-01/tls-alpn-01
// branch exists); the dns-challenge body carries ONLY the public ACME token; the
// cert key never crosses the network. All effects (the ACME order, the
// dns-challenge POST, the propagation poll, the clock) are injected so this flow
// is fully unit-testable without touching the network.

import { crypto as acmeCrypto } from "acme-client";
import type { CertMeta } from "./cert-cache.js";
import { generateCertKeypairAndCsr } from "./csr.js";

const DEFAULT_CERT_LIFETIME_MS = 90 * 86_400_000; // LE certs are 90 days

/** Injectable externals. ALL are mocked in unit tests — never hits LE/DNS/net. */
export interface IssueCertDeps {
	acme: {
		/** Place an ACME order; returns the DNS-01 token + the challenge types LE offered. */
		newOrder(args: {
			handle: string;
			directoryUrl: string;
		}): Promise<{ dnsChallengeToken: string; challengeTypesOffered: string[] }>;
		/** Tell LE to validate the challenge (only after DNS has propagated). */
		validate(args: { handle: string }): Promise<void>;
		/** Finalize the order with the CSR and download the issued chain. */
		finalizeAndDownload(args: {
			handle: string;
			csrPem: string;
		}): Promise<{ certPem: string }>;
		/** Relay-local revocation using the relay's own cert+account key. */
		revoke(args: { certPem: string; directoryUrl: string }): Promise<void>;
	};
	/**
	 * POST {action:"set",value} | {action:"clear"} to the dns-challenge endpoint.
	 * The `set` response carries `{status,fqdn}` where `fqdn` is
	 * `_acme-challenge.<cert-domain>.hook.rine.network` — the relative TXT rrset
	 * the backend wrote DIRECTLY in the single `rine.network` zone (no CNAME, no
	 * `acme.` delegation subzone). It is the source of truth for the propagation
	 * poll (the relay never derives it).
	 */
	dnsPost(action: "set" | "clear", value?: string): Promise<DnsChallengeResult>;
	/**
	 * Bounded poll of the authoritative DNS at `fqdn` until the TXT carrying
	 * `expectedValue` (this order's key-authorization) propagates — matching the
	 * value, not mere presence, so a stale/converging record never satisfies it.
	 */
	waitForPropagation(args: {
		fqdn: string;
		expectedValue?: string;
	}): Promise<void>;
	now(): number;
}

/** The dns-challenge endpoint response (REQ-CERT-08): `set` echoes the `fqdn`. */
export interface DnsChallengeResult {
	status?: string;
	fqdn?: string;
}

export interface IssuedCert {
	certPem: string;
	keyPem: string;
	meta: CertMeta;
}

function certNotAfter(certPem: string, nowMs: number): string {
	// Best-effort: derive expiry from the issued chain; fall back to the LE
	// default lifetime if the cert can't be parsed (e.g. a test fixture). meta's
	// not_after only drives the renewal timer, never trust decisions.
	try {
		return acmeCrypto.readCertificateInfo(certPem).notAfter.toISOString();
	} catch {
		return new Date(nowMs + DEFAULT_CERT_LIFETIME_MS).toISOString();
	}
}

/**
 * Run one ACME DNS-01 issuance. Sequence (REQ-CERT-10):
 *   newOrder -> dns:set -> waitForPropagation -> validate -> download -> dns:clear
 * The TXT is cleared in a `finally` so a FAILED order still cleans up its record
 * (no lingering challenge). Propagation is awaited BEFORE asking LE to validate
 * so a slow zone never burns a validation attempt.
 */
export async function issueCert(args: {
	handle: string;
	agentId: string;
	/**
	 * The cert handle — the relay passes its own `<handle>` here. Used only as a
	 * local cache label (persisted as `meta.delegation_id`) and to build the
	 * NEVER-HIT propagation-poll fallback FQDN below; the server always echoes the
	 * authoritative `fqdn` in its `set` response, so this fallback is dead in prod.
	 */
	delegationId: string;
	directoryUrl: string;
	deps: IssueCertDeps;
}): Promise<IssuedCert> {
	const { handle, delegationId, directoryUrl, deps } = args;
	const { keyPem, csrPem } = await generateCertKeypairAndCsr(handle);

	const order = await deps.acme.newOrder({ handle, directoryUrl });
	if (!order.challengeTypesOffered.includes("dns-01")) {
		// DNS-01 is the ONLY solver — there is no http-01/tls-alpn-01 fallback.
		throw new Error(
			`DNS-01 unavailable: order offered only [${order.challengeTypesOffered.join(", ")}]`,
		);
	}

	let txtSet = false;
	try {
		const setResult = await deps.dnsPost("set", order.dnsChallengeToken);
		txtSet = true;
		// Poll the FQDN the BACKEND wrote the TXT under (its `set` response), not a
		// relay-side guess: the server owns the
		// `_acme-challenge.<cert-domain>.hook.rine.network` name (a direct TXT in the
		// single rine.network zone — no CNAME/delegation). Fall back to the cert
		// handle's direct form only if the response omits it (NEVER-HIT in prod: the
		// server always echoes `fqdn`).
		const fqdn =
			setResult.fqdn ?? `_acme-challenge.${delegationId}.hook.rine.network`;
		// Match the record VALUE against this order's key-authorization (the exact
		// TXT the backend wrote + LE will check), not mere presence — so a stale or
		// partially-converged TXT at the same name never satisfies the gate.
		await deps.waitForPropagation({
			fqdn,
			expectedValue: order.dnsChallengeToken,
		});
		await deps.acme.validate({ handle });
		const { certPem } = await deps.acme.finalizeAndDownload({ handle, csrPem });
		const meta: CertMeta = {
			directory_url: directoryUrl,
			not_after: certNotAfter(certPem, deps.now()),
			delegation_id: delegationId,
			last_attempt_ts: deps.now(),
			consecutive_failures: 0,
		};
		return { certPem, keyPem, meta };
	} finally {
		if (txtSet) await deps.dnsPost("clear");
	}
}
