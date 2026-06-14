// rine Funnel relay-side ACME DNS-01 cert client — orchestrator (REQ-CERT-01,
// 09,10,11,12,13,14,15,16,32). The relay obtains a publicly-trusted TLS cert for
// `<handle>.hook.rine.network` with the private key born and kept on the user's
// box; rine only brokers the DNS-01 TXT (it never holds the key, so it cannot
// revoke — REQ-CERT-15). All external effects (the ACME order, the dns-challenge
// POST, the DNS propagation poll, the clock) are injected via IssueCertDeps so
// this orchestrator is fully unit-testable without touching the network.
//
// FROZEN-CONTRACT enforced here: DNS-01 is the ONLY solver (no http-01/tls-alpn-01
// branch exists); the dns-challenge body carries ONLY the public ACME token; the
// cert key never crosses the network; revocation is relay-local (acme.revoke),
// never a server call. The backend's DNS provider token is server-side only and
// is never referenced relay-side (asserted by a static source grep in the tests).

import { isRenewalDue, isTerminalAcmeError } from "./backoff.js";
import {
	type AcmeOptions,
	type CertMeta,
	acmeDirectoryUrl,
	loadCachedCert,
	loadMeta,
	saveCert,
	saveMeta,
	wipeHandleCache,
} from "./cert-cache.js";
import { type IssueCertDeps, type IssuedCert, issueCert } from "./issue.js";

// `cert.ts` is the relay-facing barrel: it re-exports the cache, backoff,
// keypair/CSR, and issuance surfaces so callers (and the test suite) import one
// module.
export type { AcmeOptions, CachedCert, CertMeta } from "./cert-cache.js";
export {
	accountKeyPath,
	acmeDirectoryUrl,
	funnelCacheDir,
	handleCacheDir,
	loadCachedCert,
	loadMeta,
	saveCert,
	saveMeta,
	wipeHandleCache,
} from "./cert-cache.js";
export {
	isRenewalDue,
	isTerminalAcmeError,
	nextBackoffDelayMs,
} from "./backoff.js";
export {
	type KeypairAndCsr,
	generateCertKeypairAndCsr,
	hookFqdn,
} from "./csr.js";
export { type IssueCertDeps, type IssuedCert, issueCert } from "./issue.js";

export interface EnsureCertResult extends IssuedCert {
	ready: boolean;
	fromCache: boolean;
}

/**
 * Cold-start readiness gate (REQ-CERT-32) + cache reuse + persisted backoff
 * (REQ-CERT-13). A valid, fresh cached cert opens the gate immediately with NO
 * ACME round-trip. Otherwise issue, persist atomically, and reset the failure
 * counter on success. On failure the persisted `consecutive_failures` is bumped
 * (read from the prior meta so a crash-loop never resets it to zero) and the
 * error re-thrown — a failed cold start installs NOTHING (gate stays closed).
 */
export async function ensureCert(args: {
	handle: string;
	agentId: string;
	/**
	 * The cert handle (the relay passes its own `<handle>`). Persisted as
	 * `meta.delegation_id` purely as a local cache label and used to build the
	 * never-hit propagation-poll fallback FQDN — the server always returns the
	 * authoritative `_acme-challenge.<cert-domain>.hook.rine.network` directly.
	 */
	delegationId: string;
	configDir: string;
	options: AcmeOptions;
	deps: IssueCertDeps;
}): Promise<EnsureCertResult> {
	const { handle, agentId, delegationId, configDir, options, deps } = args;
	const directoryUrl = acmeDirectoryUrl(options);

	const cached = loadCachedCert(configDir, handle, options);
	if (cached && !isRenewalDue(cached.meta, deps.now())) {
		return { ready: true, fromCache: true, ...cached };
	}

	const priorFailures =
		loadMeta(configDir, handle, options)?.consecutive_failures ?? 0;
	try {
		const issued = await issueCert({
			handle,
			agentId,
			delegationId,
			directoryUrl,
			deps,
		});
		saveCert(configDir, handle, options, issued); // atomic, consecutive_failures: 0
		return { ready: true, fromCache: false, ...issued };
	} catch (err) {
		persistFailure(configDir, handle, options, {
			delegationId,
			directoryUrl,
			priorFailures,
			nowMs: deps.now(),
		});
		throw isTerminalAcmeError(err)
			? new Error(`terminal ACME error (LE rate limit): ${describe(err)}`, {
					cause: err,
				})
			: err;
	}
}

/**
 * Graceful teardown (REQ-CERT-16): best-effort ACME revoke (relay-local — the
 * server holds no key and cannot revoke, REQ-CERT-15), then a SCOPED wipe of
 * just this handle's cache dir. A revoke failure (offline) is swallowed; the
 * local wipe is the meaningful local effect and always runs.
 */
export async function revokeAndWipeCache(args: {
	handle: string;
	configDir: string;
	options: AcmeOptions;
	deps: IssueCertDeps;
}): Promise<void> {
	const { handle, configDir, options, deps } = args;
	const cached = loadCachedCert(configDir, handle, options);
	if (cached) {
		try {
			await deps.acme.revoke({
				certPem: cached.certPem,
				directoryUrl: cached.meta.directory_url,
			});
		} catch {
			// best-effort: the user may be offline. The kill switch is server-side
			// DNS+route teardown (REQ-CERT-15), not relay cooperation.
		}
	}
	wipeHandleCache(configDir, handle, options);
}

function persistFailure(
	configDir: string,
	handle: string,
	options: AcmeOptions,
	ctx: {
		delegationId: string;
		directoryUrl: string;
		priorFailures: number;
		nowMs: number;
	},
): void {
	const existing = loadMeta(configDir, handle, options);
	const meta: CertMeta = {
		directory_url: existing?.directory_url ?? ctx.directoryUrl,
		not_after: existing?.not_after ?? new Date(ctx.nowMs).toISOString(),
		delegation_id: existing?.delegation_id ?? ctx.delegationId,
		last_attempt_ts: ctx.nowMs,
		consecutive_failures: ctx.priorFailures + 1,
	};
	saveMeta(configDir, handle, options, meta);
}

function describe(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
