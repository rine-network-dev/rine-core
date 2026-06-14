// rine Funnel DNS-01 propagation poll (REQ-CERT-10). Before telling Let's
// Encrypt to validate, the relay confirms the challenge TXT is live on the
// AUTHORITATIVE nameservers of the `rine.network` zone (the TXT now lives
// DIRECTLY at `_acme-challenge.<cert-domain>.hook.rine.network`, no CNAME /
// `acme.` delegation) — not the host's recursive resolver, which can negatively
// cache the name (NXDOMAIN long after the record is live) or return a positive
// answer LE's validators don't share. Both cases would burn a validation
// attempt; polling the authoritative servers avoids it. The poll also matches the
// record VALUE against this order's key-authorization, so a stale/partially-
// converged TXT at the same name never satisfies the gate (REQ-CERT-10).
//
// GRACE DELAY (REQ-CERT-33): the challenge name sits under the `*.hook` wildcard,
// so a TXT query issued BEFORE the record propagates (~15-34s after the backend's
// dns:set) returns NODATA carrying the zone SOA-minimum negative TTL. Hetzner's
// external authoritative anycast nodes negative-cache that NODATA, masking the
// now-live TXT from the relay AND Let's Encrypt for the whole TTL window. We
// therefore hold a fixed grace delay before the FIRST TXT query so the relay
// never poisons that cache. The NS-walk (NS-type queries) runs during the grace
// window — NS NODATA does not poison the TXT negative cache. The zone-side
// companion fix lowers the SOA-minimum so any residual poison self-heals fast.

import { Resolver, resolve4, resolveNs } from "node:dns/promises";

// Grace before the FIRST TXT query (REQ-CERT-33). Sized comfortably above the
// observed worst-case backend propagation (~34s) so the first query never
// precedes the live record — a query that does returns NODATA and Hetzner's
// anycast nodes cache it for the SOA-min negative TTL, masking the record.
const INITIAL_PROPAGATION_DELAY_MS = 45_000;
const PROPAGATION_TIMEOUT_MS = 120_000; // bounded poll AFTER the grace delay (REQ-CERT-10)
const PROPAGATION_INTERVAL_MS = 5_000;

export function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Minimal TXT-resolving surface (node:dns `Resolver` satisfies this). */
interface TxtResolver {
	resolveTxt(hostname: string): Promise<string[][]>;
}

/**
 * Test seams + tunables for `waitForTxtPropagation`. Production passes none — the
 * defaults wire the real authoritative resolver and real timers. Tests inject a
 * fake resolver + sleep so they assert ordering/timeout without touching the
 * network or waiting the real 45s grace. `nsResolve`/`a4Resolve` let tests drive
 * the REAL NS-walk (`authoritativeResolver`) without `resolverFactory`.
 */
export interface PropagationOptions {
	initialDelayMs?: number;
	timeoutMs?: number;
	intervalMs?: number;
	sleep?: (ms: number) => Promise<void>;
	resolverFactory?: (fqdn: string) => Promise<TxtResolver>;
	nsResolve?: (name: string) => Promise<string[]>;
	a4Resolve?: (host: string) => Promise<string[]>;
}

/**
 * The authoritative NS hostnames for the zone that contains `fqdn`. The
 * challenge name (`_acme-challenge.<label>.hook.rine.network`) is BELOW the zone
 * apex, where neither SOA nor NS records live, so we walk UP one label at a time
 * asking for NS until a parent answers (the apex — e.g. `rine.network`). A plain
 * `resolveSoa(fqdn)` returns ENODATA at a sub-apex name, which is why the prior
 * SOA->NS approach silently fell through to the host resolver every time.
 * Exported (with an injectable `nsResolve`) so the climb is unit-tested directly.
 */
export async function nsHostsForZoneOf(
	fqdn: string,
	nsResolve: (name: string) => Promise<string[]> = resolveNs,
): Promise<string[]> {
	let name = fqdn.replace(/\.$/, "");
	while (name.includes(".")) {
		try {
			const ns = await nsResolve(name);
			if (ns.length > 0) return ns;
		} catch {
			// NODATA/NXDOMAIN at this level — climb to the parent label.
		}
		name = name.slice(name.indexOf(".") + 1);
	}
	throw new Error(`no authoritative NS found for any parent of ${fqdn}`);
}

/**
 * Build a resolver pinned to the AUTHORITATIVE nameservers of `fqdn`'s zone
 * (NS -> A, then `Resolver.setServers`). One flaky NS-host A lookup must NOT cost
 * us the others, so `Promise.allSettled` keeps every address that did resolve.
 * Falls back to the system resolver only if NS discovery fails or NO address
 * resolves (best-effort — the bounded poll still backstops). Exported (with
 * injectable resolvers) so the NS-walk path is unit-tested directly.
 */
export async function authoritativeResolver(
	fqdn: string,
	nsResolve: (name: string) => Promise<string[]> = resolveNs,
	a4Resolve: (host: string) => Promise<string[]> = resolve4,
): Promise<Resolver> {
	const resolver = new Resolver();
	try {
		const nsHosts = await nsHostsForZoneOf(fqdn, nsResolve);
		const settled = await Promise.allSettled(
			nsHosts.map((ns) => a4Resolve(ns)),
		);
		const addresses = settled
			.flatMap((r) => (r.status === "fulfilled" ? r.value : []))
			.filter(Boolean);
		if (addresses.length > 0) resolver.setServers(addresses);
	} catch {
		// NS discovery failed — fall back to the system resolver below.
	}
	return resolver;
}

/** A TXT answer satisfies the gate iff it carries THIS order's key-authorization. */
function recordsMatch(records: string[][], expectedValue?: string): boolean {
	if (records.length === 0) return false;
	if (!expectedValue) return true; // no expected value supplied — any TXT counts
	return records.some((chunks) => chunks.join("").includes(expectedValue));
}

/**
 * Poll the authoritative DNS for the challenge TXT at the server-returned
 * `_acme-challenge.<cert-domain>.hook.rine.network` until the record carrying
 * `expectedValue` (this order's key-authorization) resolves (bounded) before
 * telling LE to validate, so a slow zone never burns a validation attempt. The
 * FQDN is the one the backend wrote the TXT under (the dns-challenge `set`
 * response's `fqdn`) — never derived from a relay-side guess.
 *
 * Order: build the authoritative resolver (NS-walk) -> hold the grace delay ->
 * poll TXT. The NS-walk overlaps the grace window and the grace delay keeps the
 * first TXT query from preceding propagation (avoids poisoning the negative
 * cache — see the module header).
 */
export async function waitForTxtPropagation(
	args: { fqdn: string; expectedValue?: string },
	opts: PropagationOptions = {},
): Promise<void> {
	const { fqdn, expectedValue } = args;
	const initialDelayMs = opts.initialDelayMs ?? INITIAL_PROPAGATION_DELAY_MS;
	const timeoutMs = opts.timeoutMs ?? PROPAGATION_TIMEOUT_MS;
	const intervalMs = opts.intervalMs ?? PROPAGATION_INTERVAL_MS;
	const doSleep = opts.sleep ?? sleep;
	const makeResolver =
		opts.resolverFactory ??
		((name: string) =>
			authoritativeResolver(name, opts.nsResolve, opts.a4Resolve));

	const resolver = await makeResolver(fqdn);
	await doSleep(initialDelayMs);

	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			const records = await resolver.resolveTxt(fqdn);
			if (recordsMatch(records, expectedValue)) return;
		} catch {
			// NXDOMAIN/SERVFAIL while the low-TTL record propagates — keep polling.
		}
		await doSleep(intervalMs);
	}
	throw new Error(`DNS propagation timeout for ${fqdn}`);
}
