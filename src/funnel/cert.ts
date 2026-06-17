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

import { crypto as acmeCrypto } from "acme-client";
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
import {
	loadAttemptLedger,
	saveAttemptLedger,
	withAgentIssuanceLock,
} from "./cert-lock.js";
import { agentWildcardFqdn } from "./csr.js";
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
	renewalDueWithJitter,
} from "./backoff.js";
export {
	type AttemptLedger,
	loadAttemptLedger,
	saveAttemptLedger,
	withAgentIssuanceLock,
} from "./cert-lock.js";
export {
	type KeypairAndCsr,
	agentLabel,
	agentWildcardFqdn,
	generateCertKeypairAndCsr,
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
 * (read from the wipe-surviving attempt-ledger so a crash-loop — even one that
 * wipes the cache — never resets it to zero) and the error re-thrown — a failed
 * cold start installs NOTHING (gate stays closed).
 *
 * `handle` is the AGENT label (REQ-CERT-42): one shared `*.{agentLabel}.hook`
 * wildcard serves every hook of the agent. Two guards make the sharing safe:
 *  - REQ-CERT-48 (SAN-match): a cached cert whose single wildcard SAN no longer
 *    matches the current agent label is force-reissued, never served mismatched.
 *  - AUD-B2/SCALE-4 (issuance lock): the ACME order runs under a cross-process
 *    per-agent lock; if a sibling hook-relay holds it, this run reuses whatever
 *    the sibling installs instead of firing a duplicate order.
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
	if (
		cached &&
		certMatchesAgentLabel(cached.certPem, handle) &&
		!isRenewalDue(cached.meta, deps.now())
	) {
		return { ready: true, fromCache: true, ...cached };
	}

	// Read the crash-loop counter from the wipe-surviving ledger, but never below
	// the prior meta — a meta-seeded counter (pre-existing tooling/tests) still
	// drives the bump even before a ledger exists.
	const priorFailures = Math.max(
		loadAttemptLedger(configDir, handle, options).consecutive_failures,
		loadMeta(configDir, handle, options)?.consecutive_failures ?? 0,
	);

	try {
		const locked = await withAgentIssuanceLock(
			{ configDir, certKey: handle, opts: options, now: deps.now },
			() => issueCert({ handle, agentId, delegationId, directoryUrl, deps }),
		);
		if (!locked.acquired) {
			// A sibling hook-relay of the same agent is mid-issuance for the identical
			// wildcard (AUD-B2/SCALE-4). Reuse whatever it installs rather than firing
			// a duplicate ACME order. This is NOT an ACME failure — it must NOT bump
			// the crash-loop ledger (that would wrongly penalize the agent's whole
			// fleet), so it throws the SIBLING_IN_PROGRESS sentinel the catch skips. If
			// the cert has not landed yet, the relay backs off and re-checks the cache.
			const sibling = loadCachedCert(configDir, handle, options);
			if (sibling) return { ready: true, fromCache: true, ...sibling };
			throw new SiblingIssuanceInProgress();
		}
		const issued = locked.result;
		saveCert(configDir, handle, options, issued); // atomic, consecutive_failures: 0
		saveAttemptLedger(configDir, handle, options, {
			consecutive_failures: 0,
			last_attempt_ts: deps.now(),
		});
		return { ready: true, fromCache: false, ...issued };
	} catch (err) {
		if (err instanceof SiblingIssuanceInProgress) throw err; // not an ACME failure
		saveAttemptLedger(configDir, handle, options, {
			consecutive_failures: priorFailures + 1,
			last_attempt_ts: deps.now(),
		});
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
 * Thrown when a sibling hook-relay of the same agent already holds the per-agent
 * issuance lock and the shared wildcard cert has not landed yet (AUD-B2). It is a
 * RETRYABLE signal (the relay backs off and re-checks the cache), never an ACME
 * failure — so it does NOT bump the crash-loop backoff ledger.
 */
export class SiblingIssuanceInProgress extends Error {
	constructor() {
		super("per-agent wildcard issuance in progress (sibling hook)");
		this.name = "SiblingIssuanceInProgress";
	}
}

/**
 * Graceful teardown (REQ-CERT-16): best-effort ACME revoke (relay-local — the
 * server holds no key and cannot revoke, REQ-CERT-15), then a SCOPED wipe of
 * just this handle's cache dir. A revoke failure (offline) is swallowed; the
 * local wipe is the meaningful local effect and always runs.
 *
 * NOT wired into the relay's single-hook teardown path (REQ-CERT-44): the cert
 * is now the per-agent `*.{agentLabel}.hook` wildcard SHARED by every hook of the
 * agent, so revoking it on one hook's BIND-revoked would kill all the agent's
 * sibling hooks. The kill switch is server-side DNS+route teardown, not relay
 * revocation. This stays a retained library primitive for an explicit, whole-agent
 * teardown — exercised by cert.test.ts, never called from `runRelayLoop`.
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

/**
 * REQ-CERT-48 (AUD-D1, defence-in-depth): does the cached leaf's SAN set still
 * cover the current agent label's wildcard? The label is UUID-derived and
 * immutable so this can never legitimately drift — but if a future label-scheme
 * change ever desyncs the cached cert from the live hostname, force-reissue loud
 * rather than serve a name-mismatched (though still time-valid) cert that fails
 * every TLS handshake. A cert that cannot be parsed (e.g. a test fixture) is
 * treated as matching so the normal renewal/cache logic still governs it.
 */
function certMatchesAgentLabel(certPem: string, agentLabel: string): boolean {
	const expected = agentWildcardFqdn(agentLabel);
	let info: ReturnType<typeof acmeCrypto.readCertificateInfo>;
	try {
		info = acmeCrypto.readCertificateInfo(certPem);
	} catch {
		return true; // unparseable -> can't assert a mismatch; defer to renewal logic
	}
	return (
		info.domains.altNames.includes(expected) ||
		info.domains.commonName === expected
	);
}
