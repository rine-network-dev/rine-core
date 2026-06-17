// rine Funnel production ACME adapter — concrete IssueCertDeps on top of the
// `acme-client` library, the rine-core HttpClient, and node:dns. The cert
// orchestrator (cert.ts) is library-agnostic and fully unit-tested with mocked
// deps; this module is the real wiring the relay (Track E) injects.
//
// FROZEN-CONTRACT: the dns-challenge POST body is {action, value?} ONLY — the
// relay never supplies the FQDN (the backend derives it from the owned hook row)
// and never transmits key material. Revocation runs through the ACME client with
// the relay's own cert+account key; rine holds no key and cannot revoke.

import * as fs from "node:fs";
import { dirname } from "node:path";
import { Client, crypto as acmeCrypto } from "acme-client";
import { RineApiError } from "../errors.js";
import type { HttpClient } from "../http.js";
import { type AcmeOptions, accountKeyPath } from "./cert-cache.js";
import { acmeDirectoryUrl, agentWildcardFqdn } from "./csr.js";
import type { DnsChallengeResult, IssueCertDeps } from "./issue.js";
import { sleep, waitForTxtPropagation } from "./propagation.js";

// Re-exported so the relay-facing barrel keeps a single import surface.
export { waitForTxtPropagation } from "./propagation.js";

/**
 * Tag an LE rate-limit failure so backoff.ts classifies it as TERMINAL. Matches
 * the stable LE stem `too many certificates` so the modern parenthetical-count
 * wording (`too many certificates (5) already issued ...`) is still caught —
 * see backoff.ts isTerminalAcmeError, which uses the same stems.
 */
export function tagLeRateLimit<E extends Error>(err: E): E {
	const msg = err.message.toLowerCase();
	if (msg.includes("too many certificates")) {
		(err as Error & { leRateLimit?: string }).leRateLimit =
			"duplicate-certificate";
	} else if (msg.includes("too many failed authorizations")) {
		(err as Error & { leRateLimit?: string }).leRateLimit = "failed-validation";
	}
	return err;
}

/**
 * POST to the backend dns-challenge endpoint, honoring a 429 + Retry-After
 * (the server-side rate-limit backstop, REQ-CERT-07). The body carries ONLY
 * {action, value?} — never the FQDN, never key material.
 */
export function makeDnsPost(
	http: HttpClient,
	agentId: string,
	agentHeaders: Record<string, string> = {},
): IssueCertDeps["dnsPost"] {
	const path = `/agents/${agentId}/funnel/dns-challenge`;
	return async (action, value) => {
		const body = action === "set" ? { action, value } : { action };
		try {
			return (await http.post(path, body, agentHeaders)) as DnsChallengeResult;
		} catch (err) {
			if (err instanceof RineApiError && err.status === 429) {
				const retryAfter = retryAfterMs(err);
				if (retryAfter > 0) await sleep(retryAfter);
				return (await http.post(
					path,
					body,
					agentHeaders,
				)) as DnsChallengeResult;
			}
			throw err;
		}
	};
}

function retryAfterMs(err: RineApiError): number {
	const res = err.raw;
	if (res instanceof Response) {
		const header = res.headers.get("retry-after");
		const secs = header ? Number(header) : Number.NaN;
		if (Number.isFinite(secs) && secs > 0) return secs * 1000;
	}
	return 0;
}

/**
 * Build the production ACME deps. The acme-client `Client` is the order driver;
 * a per-issuance closure holds the order/challenge between newOrder→validate→
 * download so the orchestrator's step boundaries map onto the RFC 8555 flow.
 */
export function makeAcmeClientDeps(
	client: Client,
): Pick<IssueCertDeps, "acme"> {
	type Pending = {
		order: Awaited<ReturnType<Client["createOrder"]>>;
		authz: Awaited<ReturnType<Client["getAuthorizations"]>>[number];
		challenge: { type: string };
	};
	let pending: Pending | undefined;

	return {
		acme: {
			async newOrder({ handle }) {
				// `handle` is the AGENT label; order the per-agent wildcard identifier
				// `*.{agentLabel}.hook.rine.network` (REQ-CERT-40). DNS-01 is already
				// the only solver and wildcards require it — no new solver code.
				const fqdn = agentWildcardFqdn(handle);
				try {
					const order = await client.createOrder({
						identifiers: [{ type: "dns", value: fqdn }],
					});
					const authz = (await client.getAuthorizations(order))[0];
					if (!authz) throw new Error("no authorization on order");
					const dns = authz.challenges.find((c) => c.type === "dns-01");
					const offered = authz.challenges.map((c) => c.type);
					if (dns) {
						const keyAuth = await client.getChallengeKeyAuthorization(dns);
						pending = { order, authz, challenge: dns };
						return {
							dnsChallengeToken: keyAuth,
							challengeTypesOffered: offered,
						};
					}
					return { dnsChallengeToken: "", challengeTypesOffered: offered };
				} catch (err) {
					throw tagLeRateLimit(err as Error);
				}
			},
			async validate() {
				if (!pending) throw new Error("validate called before newOrder");
				await client.completeChallenge(pending.challenge as never);
				await client.waitForValidStatus(pending.authz);
			},
			async finalizeAndDownload({ csrPem }) {
				if (!pending) throw new Error("finalize called before newOrder");
				const order = await client.finalizeOrder(pending.order, csrPem);
				const certPem = await client.getCertificate(order);
				return { certPem };
			},
			async revoke({ certPem }) {
				await client.revokeCertificate(certPem);
			},
		},
	};
}

/**
 * Load (or mint + persist 0600) the ONE shared ACME account key for this relay,
 * then build an `acme-client` Client against the selected LE directory. One LE
 * account is reused across all of the relay's hooks (REQ-CERT-12), so repeated
 * issuances don't churn accounts. The account key never leaves the box.
 */
export async function buildAcmeClient(
	configDir: string,
	options: AcmeOptions,
): Promise<Client> {
	const keyPath = accountKeyPath(configDir, options);
	let accountKey: string;
	try {
		accountKey = fs.readFileSync(keyPath, "utf-8");
	} catch {
		accountKey = (await acmeCrypto.createPrivateEcdsaKey("P-256")).toString();
		fs.mkdirSync(dirname(keyPath), { recursive: true, mode: 0o700 });
		const tmp = `${keyPath}.tmp`;
		fs.writeFileSync(tmp, accountKey, { mode: 0o600 });
		fs.renameSync(tmp, keyPath);
		fs.chmodSync(keyPath, 0o600);
	}
	const client = new Client({
		directoryUrl: acmeDirectoryUrl(options),
		accountKey,
	});
	await client.createAccount({ termsOfServiceAgreed: true });
	return client;
}

/**
 * Assemble the full production `IssueCertDeps` the relay (Track E) injects into
 * `ensureCert` / `revokeAndWipeCache`. Pure wiring: the ACME client drives the
 * order, the HttpClient brokers the TXT, node:dns confirms propagation.
 */
export async function buildIssueCertDeps(args: {
	configDir: string;
	options: AcmeOptions;
	http: HttpClient;
	agentId: string;
	agentHeaders?: Record<string, string>;
}): Promise<IssueCertDeps> {
	const client = await buildAcmeClient(args.configDir, args.options);
	return {
		...makeAcmeClientDeps(client),
		dnsPost: makeDnsPost(args.http, args.agentId, args.agentHeaders),
		waitForPropagation: waitForTxtPropagation,
		now: () => Date.now(),
	};
}
