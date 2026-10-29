// rine Funnel cert cache: per-cert-key cert+key+meta under the
// config dir, with the SAME perm discipline as crypto/keys.ts — dirs 0700, files
// 0600, atomic temp+rename writes. The cert private key is born here and never
// leaves the box (FROZEN-CONTRACT). Staging and prod are segregated into distinct
// subtrees so a staging cert is never presented in prod mode.
//
// The cache key (`certKey`) is now the AGENT label, not a per-hook label:
// every hook of an agent shares ONE `funnel/{agentLabel}/` subtree
// and ONE `*.{agentLabel}.hook.rine.network` wildcard cert. The per-agent
// issuance lock + the wipe-surviving attempt-ledger that this sharing requires
// live in `cert-lock.ts` (kept out of the wiped subtree).

import * as fs from "node:fs";
import { join } from "node:path";
import { writeAtomic } from "../config.js";

/** ACME directory selection. `RINE_ACME_STAGING=1` env is also honored. */
export type AcmeOptions = { staging?: boolean };

const LE_PROD = "https://acme-v02.api.letsencrypt.org/directory";
const LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";

/**
 * Resolve the ACME directory URL. Production by default; staging when either
 * `opts.staging` is set or `RINE_ACME_STAGING=1` is in the environment, so dev
 * never burns the production LE rate limits. Shares the single `isStaging`
 * decision with the cache-path split so a cert's directory_url and its cache
 * subtree are always derived from the same flag.
 */
export function acmeDirectoryUrl(opts: AcmeOptions): string {
	return isStaging(opts) ? LE_STAGING : LE_PROD;
}

/**
 * Order/renewal metadata persisted alongside the cert. `consecutive_failures`
 * is the persisted ACME-storm backoff counter — it survives a
 * crash-loop so a buggy relay can never reset its own backoff to zero on boot.
 */
export interface CertMeta {
	directory_url: string;
	not_after: string;
	/**
	 * The cert handle, kept as a local cache label only (historical field name —
	 * there is no DNS delegation anymore; the TXT lives directly at
	 * `_acme-challenge.<cert-domain>.hook.rine.network`). Drives nothing security-
	 * relevant; it only labels the cache and seeds the never-hit poll fallback.
	 */
	delegation_id: string;
	last_attempt_ts: number;
	consecutive_failures: number;
}

export interface CachedCert {
	certPem: string;
	keyPem: string;
	meta: CertMeta;
}

const CERT_FILE = "cert.pem";
const KEY_FILE = "key.pem";
const META_FILE = "meta.json";

function isStaging(opts: AcmeOptions): boolean {
	return opts.staging === true || process.env.RINE_ACME_STAGING === "1";
}

/** `${configDir}/funnel` (prod) or `${configDir}/funnel/staging` (staging). */
export function funnelCacheDir(configDir: string, opts: AcmeOptions): string {
	const root = join(configDir, "funnel");
	return isStaging(opts) ? join(root, "staging") : root;
}

/**
 * The per-cert-key cache dir under the (staging-segregated) funnel root.
 * `certKey` is the AGENT label: all of an agent's hook-relays share
 * this ONE dir, so it holds the single per-agent wildcard cert+key+meta.
 */
export function handleCacheDir(
	configDir: string,
	certKey: string,
	opts: AcmeOptions,
): string {
	return join(funnelCacheDir(configDir, opts), certKey);
}

/** One LE account key per relay, shared across cert keys, at the funnel root. */
export function accountKeyPath(configDir: string, opts: AcmeOptions): string {
	return join(funnelCacheDir(configDir, opts), "acme-account.key");
}

function ensureHandleDir(
	configDir: string,
	certKey: string,
	opts: AcmeOptions,
): string {
	const dir = handleCacheDir(configDir, certKey, opts);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	// recursive mkdir honors umask for already-existing parents; pin the leaf 0700.
	fs.chmodSync(dir, 0o700);
	return dir;
}

export function saveMeta(
	configDir: string,
	certKey: string,
	opts: AcmeOptions,
	meta: CertMeta,
): void {
	const dir = ensureHandleDir(configDir, certKey, opts);
	writeAtomic(join(dir, META_FILE), `${JSON.stringify(meta, null, 2)}\n`);
}

export function loadMeta(
	configDir: string,
	certKey: string,
	opts: AcmeOptions,
): CertMeta | null {
	const path = join(handleCacheDir(configDir, certKey, opts), META_FILE);
	try {
		return JSON.parse(fs.readFileSync(path, "utf-8")) as CertMeta;
	} catch {
		return null;
	}
}

export function saveCert(
	configDir: string,
	certKey: string,
	opts: AcmeOptions,
	cert: CachedCert,
): void {
	const dir = ensureHandleDir(configDir, certKey, opts);
	// Write key first, then cert, then meta — meta is the last write so a partial
	// install (interrupted before meta lands) reads back as a cache miss.
	writeAtomic(join(dir, KEY_FILE), cert.keyPem);
	writeAtomic(join(dir, CERT_FILE), cert.certPem);
	saveMeta(configDir, certKey, opts, cert.meta);
}

/**
 * Returns the cached cert ONLY if cert+key+meta are all present AND the meta's
 * directory_url matches the requested mode (staging cert never served in prod).
 * Any partial/corrupt cache reads back as `null` — never a half-cert.
 */
export function loadCachedCert(
	configDir: string,
	certKey: string,
	opts: AcmeOptions,
): CachedCert | null {
	const dir = handleCacheDir(configDir, certKey, opts);
	try {
		const certPem = fs.readFileSync(join(dir, CERT_FILE), "utf-8");
		const keyPem = fs.readFileSync(join(dir, KEY_FILE), "utf-8");
		const meta = JSON.parse(
			fs.readFileSync(join(dir, META_FILE), "utf-8"),
		) as CertMeta;
		if (!certPem || !keyPem || !meta.not_after) return null;
		// Belt-and-braces over the path split: never serve a cert whose recorded
		// directory_url disagrees with the requested mode (e.g. a staging cert
		// copied/symlinked into the prod tree, or a future shared-path refactor).
		if (meta.directory_url !== acmeDirectoryUrl(opts)) return null;
		return { certPem, keyPem, meta };
	} catch {
		return null;
	}
}

/**
 * Scoped wipe of one cert key's cert+key+meta subtree. Other cert
 * keys are untouched. The per-agent issuance lock and the attempt-ledger live at
 * the funnel ROOT (cert-lock.ts), OUTSIDE this subtree, so a wipe does NOT reset
 * the crash-loop backoff and never strands a held lock. Because the
 * cache key is now the agent label, a relay MUST NOT call this on a single hook's
 * teardown while sibling hooks of the same agent are still live — it would wipe
 * the shared wildcard. The wildcard teardown-revoke is dropped; the
 * kill switch is server-side DNS+route teardown.
 */
export function wipeHandleCache(
	configDir: string,
	certKey: string,
	opts: AcmeOptions,
): void {
	fs.rmSync(handleCacheDir(configDir, certKey, opts), {
		recursive: true,
		force: true,
	});
}
