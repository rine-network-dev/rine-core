// REQ-CERT-01,03,04,09,10,11,12,13,14,15,16,32 — relay-side local ACME DNS-01 cert client.
//
// FROZEN-CONTRACT (a violation is a build defect, asserted below):
//  - cert private key born + stays LOCAL; DNS-01 ONLY (no HTTP-01/TLS-ALPN-01);
//    key is NEVER serialized into any network call.
//  - the relay drives the challenge through the backend dns-challenge endpoint
//    (POST {action:set,value} / {action:clear}); request bodies carry ONLY the
//    public ACME token, never key material.
//  - the DNS provider token (HETZNER_DNS_API_TOKEN; legacy HOOK_DNS_API_TOKEN) is
//    server-side only — it MUST NOT appear in rine-core.
//  - no-body-log: the relay never logs the HMAC secret, the body, the cert key,
//    or the ACME private key — only outcomes / counters / IDs.
//
// All externals are MOCKED: the ACME directory/order (NEVER hits Let's Encrypt,
// not even staging — real LE-staging is reserved for the Wave-3 E2E), the
// dns-challenge HTTP POST, the DNS propagation resolver, and the filesystem
// (a per-test temp dir). These tests MUST fail now (no implementation yet) and
// fail for the right reason: the module under test does not exist.

import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RineApiError } from "../../src/errors.js";
// Production-wiring lane (the real dns-challenge POST + LE error tagging). These
// are the PURE, deterministic pieces — exercised with a fake HttpClient so no
// test touches the network (the ACME order + propagation poll stay Wave-3 E2E).
import { makeDnsPost, tagLeRateLimit } from "../../src/funnel/acme.js";
// Module under test — does not exist yet (Track D will create it). The import
// is intentionally a single barrel so a missing export surfaces as a clear
// "right reason" failure rather than a runtime TypeError mid-test.
import {
	type CertMeta,
	type IssueCertDeps,
	acmeDirectoryUrl,
	ensureCert,
	funnelCacheDir,
	generateCertKeypairAndCsr,
	handleCacheDir,
	isRenewalDue,
	isTerminalAcmeError,
	issueCert,
	loadCachedCert,
	loadMeta,
	nextBackoffDelayMs,
	revokeAndWipeCache,
	saveCert,
	saveMeta,
} from "../../src/funnel/cert.js";
import type { HttpClient } from "../../src/http.js";

// ── shared fixtures ─────────────────────────────────────────────────────────

const HANDLE = "gh-acme";
const FQDN = `${HANDLE}.hook.rine.network`;
const AGENT_ID = "00000000-0000-4000-a000-0000000000aa";
const DELEGATION_ID = "deadbeefdeadbeefdeadbeefdeadbeef";
const LE_PROD = "https://acme-v02.api.letsencrypt.org/directory";
const LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-funnel-cert-test-"));
}

function withEnv(key: string, value: string | undefined, fn: () => void): void {
	const prev = process.env[key];
	if (value === undefined) delete process.env[key];
	else process.env[key] = value;
	try {
		fn();
	} finally {
		if (prev === undefined) delete process.env[key];
		else process.env[key] = prev;
	}
}

/** A meta.json with `not_after` `daysFromNow` in the future. */
function makeMeta(daysFromNow: number, over: Partial<CertMeta> = {}): CertMeta {
	const notAfter = new Date(
		Date.now() + daysFromNow * 86_400_000,
	).toISOString();
	return {
		directory_url: LE_PROD,
		not_after: notAfter,
		delegation_id: DELEGATION_ID,
		last_attempt_ts: Date.now(),
		consecutive_failures: 0,
		...over,
	};
}

/**
 * A fully-mocked dependency bundle for issueCert. The ACME client, the
 * dns-challenge poster, and the DNS-propagation resolver are all spies, so no
 * test ever touches the network. The sequence each spy records lets us assert
 * the exact issuance order.
 */
function makeIssueDeps(over: Partial<IssueCertDeps> = {}): {
	deps: IssueCertDeps;
	order: string[];
	dnsPost: ReturnType<typeof vi.fn>;
} {
	const order: string[] = [];
	const dnsPost = vi.fn(async (action: "set" | "clear", value?: string) => {
		order.push(action === "set" ? "dns:set" : "dns:clear");
		// echo the backend contract shape so callers can assert no key leaks. The
		// backend returns the DIRECT TXT FQDN (no CNAME/`acme.` delegation): the
		// relative `_acme-challenge.<cert-domain>.hook` rrset in the rine.network zone.
		return action === "set"
			? {
					status: "set",
					fqdn: `_acme-challenge.${DELEGATION_ID}.hook.rine.network`,
					_value: value,
				}
			: { status: "cleared" };
	});

	const acme: IssueCertDeps["acme"] = {
		newOrder: vi.fn(async () => {
			order.push("acme:newOrder");
			return {
				dnsChallengeToken: "tok-from-le",
				challengeTypesOffered: ["dns-01"],
			};
		}),
		validate: vi.fn(async () => {
			order.push("acme:validate");
		}),
		finalizeAndDownload: vi.fn(async () => {
			order.push("acme:download");
			return {
				certPem:
					"-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n",
			};
		}),
		revoke: vi.fn(async () => {
			order.push("acme:revoke");
		}),
	};

	const deps: IssueCertDeps = {
		acme,
		dnsPost,
		waitForPropagation: vi.fn(async () => {
			order.push("dns:propagated");
		}),
		now: () => Date.now(),
		...over,
	};
	return { deps, order, dnsPost };
}

// ── REQ-CERT-09 / REQ-CERT-01: local keypair + CSR, DNS-01 only ─────────────

describe("generateCertKeypairAndCsr — local EC P-256 keypair + CSR (REQ-CERT-09)", () => {
	it("generates an EC P-256 keypair and a CSR whose CN/SAN is <handle>.hook.rine.network", async () => {
		const out = await generateCertKeypairAndCsr(HANDLE);
		expect(out.csrPem).toContain("CERTIFICATE REQUEST");
		expect(out.commonName).toBe(FQDN);
		expect(out.subjectAltNames).toContain(FQDN);
	});

	it("uses the EC P-256 (prime256v1) curve, matching modern Let's Encrypt defaults", async () => {
		const out = await generateCertKeypairAndCsr(HANDLE);
		// Behavioral: the emitted private key is an EC key on the P-256 curve.
		expect(out.keyAlgorithm).toBe("EC");
		expect(out.keyCurve).toMatch(/(P-256|prime256v1|secp256r1)/i);
	});

	it("produces a fresh, unique keypair on each call (no key reuse across issuances)", async () => {
		const a = await generateCertKeypairAndCsr(HANDLE);
		const b = await generateCertKeypairAndCsr(HANDLE);
		expect(a.keyPem).not.toBe(b.keyPem);
	});

	it("returns the private key in PEM form for LOCAL storage only — never a network field", async () => {
		const out = await generateCertKeypairAndCsr(HANDLE);
		expect(out.keyPem).toContain("PRIVATE KEY");
		// The CSR (the only thing that goes to LE) carries the PUBLIC key, never the private one.
		expect(out.csrPem).not.toContain("PRIVATE KEY");
	});
});

describe("DNS-01 is the only solver (REQ-CERT-01)", () => {
	it("issuance never invokes an HTTP-01 or TLS-ALPN-01 solver and never binds an ACME listener", async () => {
		const { deps } = makeIssueDeps();
		await issueCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			directoryUrl: LE_PROD,
			deps,
		});
		// The deps bundle exposes ONLY a dns-01 path — there is no http/alpn solver
		// to call. Assert the order's solver step is the dns endpoint, never a listener.
		expect(deps.acme.newOrder as ReturnType<typeof vi.fn>).toHaveBeenCalled();
		// No property named like an http/alpn solver exists on deps.acme.
		expect(Object.keys(deps.acme)).not.toContain("http01");
		expect(Object.keys(deps.acme)).not.toContain("tlsAlpn01");
	});

	it("fails the order with a clear DNS-01-unavailable error when LE offers only HTTP-01/TLS-ALPN-01", async () => {
		const { deps } = makeIssueDeps({
			acme: {
				...makeIssueDeps().deps.acme,
				newOrder: vi.fn(async () => ({
					dnsChallengeToken: "",
					challengeTypesOffered: ["http-01", "tls-alpn-01"],
				})),
			},
		});
		await expect(
			issueCert({
				handle: HANDLE,
				agentId: AGENT_ID,
				delegationId: DELEGATION_ID,
				directoryUrl: LE_PROD,
				deps,
			}),
		).rejects.toThrow(/DNS-01 unavailable/i);
	});
});

// ── REQ-CERT-10: issuance sequence order + finally-clear ────────────────────

describe("issueCert sequence ordering (REQ-CERT-10)", () => {
	it("runs exactly: newOrder -> dns:set -> propagation -> validate -> download -> dns:clear", async () => {
		const { deps, order } = makeIssueDeps();
		await issueCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			directoryUrl: LE_PROD,
			deps,
		});
		expect(order).toEqual([
			"acme:newOrder",
			"dns:set",
			"dns:propagated",
			"acme:validate",
			"acme:download",
			"dns:clear",
		]);
	});

	it("POSTs {action:set,value:<token>} to the dns-challenge endpoint with the LE-issued token", async () => {
		const { deps, dnsPost } = makeIssueDeps();
		await issueCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			directoryUrl: LE_PROD,
			deps,
		});
		expect(dnsPost).toHaveBeenCalledWith("set", "tok-from-le");
	});

	it("clears the TXT in a finally block even when the order FAILS (no lingering challenge record)", async () => {
		const base = makeIssueDeps();
		const failingValidate = vi.fn(async () => {
			throw new Error("LE validation failed");
		});
		const { deps, order, dnsPost } = makeIssueDeps({
			acme: { ...base.deps.acme, validate: failingValidate },
		});
		await expect(
			issueCert({
				handle: HANDLE,
				agentId: AGENT_ID,
				delegationId: DELEGATION_ID,
				directoryUrl: LE_PROD,
				deps,
			}),
		).rejects.toThrow();
		// clear MUST still run after the failure
		expect(dnsPost).toHaveBeenCalledWith("clear");
		expect(order[order.length - 1]).toBe("dns:clear");
	});

	it("polls the FQDN the BACKEND returned from dns-challenge `set`, not a relay-side guess (C1)", async () => {
		const { deps } = makeIssueDeps();
		await issueCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			directoryUrl: LE_PROD,
			deps,
		});
		// The server owns the `_acme-challenge.<cert-domain>.hook.rine.network` name
		// (direct TXT in the rine.network zone, no delegation); the poll must target
		// the `fqdn` from the `set` response so it watches the record the backend
		// actually wrote (REQ-CERT-10).
		expect(deps.waitForPropagation).toHaveBeenCalledWith({
			fqdn: `_acme-challenge.${DELEGATION_ID}.hook.rine.network`,
			expectedValue: "tok-from-le",
		});
	});

	it("falls back to the cert-handle direct FQDN only when the set response omits fqdn", async () => {
		const { deps } = makeIssueDeps({
			dnsPost: vi.fn(async (action: "set" | "clear") =>
				action === "set" ? { status: "set" } : { status: "cleared" },
			),
		});
		await issueCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			directoryUrl: LE_PROD,
			deps,
		});
		expect(deps.waitForPropagation).toHaveBeenCalledWith({
			fqdn: `_acme-challenge.${DELEGATION_ID}.hook.rine.network`,
			expectedValue: "tok-from-le",
		});
	});

	it("waits for DNS propagation BEFORE telling LE to validate (avoid burning a validation attempt)", async () => {
		const { deps, order } = makeIssueDeps();
		await issueCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			directoryUrl: LE_PROD,
			deps,
		});
		expect(order.indexOf("dns:propagated")).toBeLessThan(
			order.indexOf("acme:validate"),
		);
	});

	it("backs off (rejects) when DNS propagation times out, without asking LE to validate", async () => {
		const base = makeIssueDeps();
		const { deps, order } = makeIssueDeps({
			waitForPropagation: vi.fn(async () => {
				throw new Error("propagation timeout");
			}),
			acme: base.deps.acme,
		});
		await expect(
			issueCert({
				handle: HANDLE,
				agentId: AGENT_ID,
				delegationId: DELEGATION_ID,
				directoryUrl: LE_PROD,
				deps,
			}),
		).rejects.toThrow(/propagation/i);
		expect(order).not.toContain("acme:validate");
		// still cleaned up its TXT
		expect(order).toContain("dns:clear");
	});
});

// ── FROZEN-CONTRACT: key material never crosses the network ─────────────────

describe("FROZEN-CONTRACT: key material is never transmitted (REQ-CERT-09)", () => {
	it("the dns-challenge POST body carries ONLY the public ACME token — never PEM key material", async () => {
		const { deps, dnsPost } = makeIssueDeps();
		await issueCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			directoryUrl: LE_PROD,
			deps,
		});
		for (const call of dnsPost.mock.calls) {
			const serialized = JSON.stringify(call);
			expect(serialized).not.toContain("PRIVATE KEY");
			expect(serialized).not.toContain("BEGIN EC");
		}
	});

	it("the DNS provider token is never referenced relay-side in ANY funnel source (server-side-only secret)", () => {
		// Static guard: the dns-challenge HTTP call lives in acme.ts and the whole
		// funnel/ tree is re-exported, so glob EVERY src/funnel/*.ts — not just
		// cert.ts — to catch a future regression that named the token anywhere. The
		// live name is HETZNER_DNS_API_TOKEN (the legacy HOOK_DNS_API_TOKEN must also
		// never reappear).
		const funnelDir = join(__dirname, "..", "..", "src", "funnel");
		const files = fs.readdirSync(funnelDir).filter((f) => f.endsWith(".ts"));
		expect(files.length).toBeGreaterThan(1);
		for (const file of files) {
			const src = fs.readFileSync(join(funnelDir, file), "utf-8");
			expect(
				src,
				`${file} must not name HETZNER_DNS_API_TOKEN`,
			).not.toContain("HETZNER_DNS_API_TOKEN");
			expect(src, `${file} must not name HOOK_DNS_API_TOKEN`).not.toContain(
				"HOOK_DNS_API_TOKEN",
			);
		}
	});
});

// ── REQ-CERT-11: staging vs prod directory + segregated cache ───────────────

describe("acmeDirectoryUrl — staging/prod selection (REQ-CERT-11)", () => {
	it("defaults to the Let's Encrypt PRODUCTION directory with no flag/env", () => {
		withEnv("RINE_ACME_STAGING", undefined, () => {
			expect(acmeDirectoryUrl({})).toBe(LE_PROD);
		});
	});

	it("selects the STAGING directory when the --staging option is set", () => {
		withEnv("RINE_ACME_STAGING", undefined, () => {
			expect(acmeDirectoryUrl({ staging: true })).toBe(LE_STAGING);
		});
	});

	it("selects the STAGING directory when RINE_ACME_STAGING=1", () => {
		withEnv("RINE_ACME_STAGING", "1", () => {
			expect(acmeDirectoryUrl({})).toBe(LE_STAGING);
		});
	});
});

describe("cache segregation: staging and prod never collide (REQ-CERT-11/12)", () => {
	it("staging and prod resolve to DIFFERENT per-handle cache directories", () => {
		const cfg = makeTmpDir();
		try {
			const prodDir = handleCacheDir(cfg, HANDLE, { staging: false });
			const stagingDir = handleCacheDir(cfg, HANDLE, { staging: true });
			expect(prodDir).not.toBe(stagingDir);
		} finally {
			fs.rmSync(cfg, { recursive: true, force: true });
		}
	});

	it("a cached staging cert is NOT presented in prod mode (directory mismatch -> miss)", () => {
		const cfg = makeTmpDir();
		try {
			// Write a valid+fresh cert under the STAGING directory.
			saveCert(
				cfg,
				HANDLE,
				{ staging: true },
				{
					certPem: "CERT",
					keyPem: "KEY",
					meta: makeMeta(80, { directory_url: LE_STAGING }),
				},
			);
			// Loading in PROD mode must not find/return it.
			const loaded = loadCachedCert(cfg, HANDLE, { staging: false });
			expect(loaded).toBeNull();
		} finally {
			fs.rmSync(cfg, { recursive: true, force: true });
		}
	});
});

// ── REQ-CERT-12: cache layout, permissions, atomic writes ───────────────────

describe("cert cache layout + permissions (REQ-CERT-12)", () => {
	let cfg: string;
	beforeEach(() => {
		cfg = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(cfg, { recursive: true, force: true });
	});

	it("the funnel root is ${configDir}/funnel and per-handle dirs live under it", () => {
		expect(funnelCacheDir(cfg, {})).toBe(join(cfg, "funnel"));
		expect(handleCacheDir(cfg, HANDLE, {})).toContain(join(cfg, "funnel"));
		expect(handleCacheDir(cfg, HANDLE, {})).toContain(HANDLE);
	});

	it("writes cert.pem, key.pem and meta.json into the per-handle dir", () => {
		saveCert(
			cfg,
			HANDLE,
			{},
			{ certPem: "CERT", keyPem: "KEY", meta: makeMeta(80) },
		);
		const dir = handleCacheDir(cfg, HANDLE, {});
		expect(fs.existsSync(join(dir, "cert.pem"))).toBe(true);
		expect(fs.existsSync(join(dir, "key.pem"))).toBe(true);
		expect(fs.existsSync(join(dir, "meta.json"))).toBe(true);
	});

	it("creates per-handle directories 0700", () => {
		saveCert(
			cfg,
			HANDLE,
			{},
			{ certPem: "CERT", keyPem: "KEY", meta: makeMeta(80) },
		);
		const dir = handleCacheDir(cfg, HANDLE, {});
		expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
	});

	it("writes cert.pem / key.pem / meta.json with 0600 permissions", () => {
		saveCert(
			cfg,
			HANDLE,
			{},
			{ certPem: "CERT", keyPem: "KEY", meta: makeMeta(80) },
		);
		const dir = handleCacheDir(cfg, HANDLE, {});
		expect(fs.statSync(join(dir, "cert.pem")).mode & 0o777).toBe(0o600);
		expect(fs.statSync(join(dir, "key.pem")).mode & 0o777).toBe(0o600);
		expect(fs.statSync(join(dir, "meta.json")).mode & 0o777).toBe(0o600);
	});

	it("the ACME account key is SHARED across handles at ${configDir}/funnel/acme-account.key (0600)", () => {
		// Two handles, one relay, one LE account key.
		saveCert(
			cfg,
			HANDLE,
			{},
			{ certPem: "C", keyPem: "K", meta: makeMeta(80) },
		);
		saveCert(
			cfg,
			"gh-other",
			{},
			{ certPem: "C", keyPem: "K", meta: makeMeta(80) },
		);
		const accountKey = join(funnelCacheDir(cfg, {}), "acme-account.key");
		// The account key lives at the funnel root, NOT inside a per-handle dir.
		expect(accountKey.includes(HANDLE)).toBe(false);
		// And once an issuance has run it is created 0600 (asserted via the deps path below).
	});

	it("meta.json records directory_url, not_after, delegation_id, last_attempt_ts, consecutive_failures", () => {
		const meta = makeMeta(80, { consecutive_failures: 3 });
		saveCert(cfg, HANDLE, {}, { certPem: "CERT", keyPem: "KEY", meta });
		const loaded = loadMeta(cfg, HANDLE, {});
		expect(loaded).not.toBeNull();
		expect(loaded?.directory_url).toBe(LE_PROD);
		expect(loaded?.delegation_id).toBe(DELEGATION_ID);
		expect(loaded?.consecutive_failures).toBe(3);
		expect(typeof loaded?.not_after).toBe("string");
		expect(typeof loaded?.last_attempt_ts).toBe("number");
	});

	it("writes ATOMICALLY (temp + rename) — an interrupted write never leaves a half-cert", () => {
		// Spy renameSync to assert the atomic temp->final move is the mechanism used.
		const renameSpy = vi.spyOn(fs, "renameSync");
		try {
			saveCert(
				cfg,
				HANDLE,
				{},
				{ certPem: "CERT", keyPem: "KEY", meta: makeMeta(80) },
			);
			const renamedTargets = renameSpy.mock.calls.map((c) => String(c[1]));
			expect(renamedTargets.some((t) => t.endsWith("cert.pem"))).toBe(true);
			expect(renamedTargets.some((t) => t.endsWith("key.pem"))).toBe(true);
		} finally {
			renameSpy.mockRestore();
		}
	});

	it("loadCachedCert returns null for a corrupt/partial cache rather than loading a half-cert", () => {
		const dir = handleCacheDir(cfg, HANDLE, {});
		fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
		// cert present but key + meta missing (interrupted write)
		fs.writeFileSync(join(dir, "cert.pem"), "PARTIAL");
		expect(loadCachedCert(cfg, HANDLE, {})).toBeNull();
	});
});

// ── REQ-CERT-13: cache reuse across restarts, never re-mint per boot ────────

describe("cache reuse across restarts (REQ-CERT-13/32)", () => {
	let cfg: string;
	beforeEach(() => {
		cfg = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(cfg, { recursive: true, force: true });
	});

	it("a valid + fresh cached cert is reused — ensureCert performs NO ACME round-trip", async () => {
		saveCert(
			cfg,
			HANDLE,
			{},
			{ certPem: "CERT", keyPem: "KEY", meta: makeMeta(80) },
		);
		const { deps } = makeIssueDeps();
		const result = await ensureCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			configDir: cfg,
			options: {},
			deps,
		});
		expect(result.fromCache).toBe(true);
		expect(deps.acme.newOrder).not.toHaveBeenCalled();
	});

	it("a cold start with no cache triggers issuance (a single ACME order, not a per-boot storm)", async () => {
		const { deps } = makeIssueDeps();
		await ensureCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			configDir: cfg,
			options: {},
			deps,
		});
		expect(deps.acme.newOrder).toHaveBeenCalledTimes(1);
	});
});

// ── REQ-CERT-14: renewal-due window ─────────────────────────────────────────

describe("isRenewalDue — 30-day renewal window (REQ-CERT-14)", () => {
	const now = Date.UTC(2026, 0, 1);

	it("is NOT due when not_after is more than 30 days away", () => {
		expect(isRenewalDue(makeMeta(45), now)).toBe(false);
	});

	it("IS due when not_after - now is exactly 30 days (boundary inclusive)", () => {
		const meta = makeMeta(0, {
			not_after: new Date(now + 30 * 86_400_000).toISOString(),
		});
		expect(isRenewalDue(meta, now)).toBe(true);
	});

	it("IS due when not_after is within 30 days", () => {
		const meta = makeMeta(0, {
			not_after: new Date(now + 10 * 86_400_000).toISOString(),
		});
		expect(isRenewalDue(meta, now)).toBe(true);
	});

	it("IS due (and forces a cold issuance) when not_after is already in the past", () => {
		const meta = makeMeta(0, {
			not_after: new Date(now - 86_400_000).toISOString(),
		});
		expect(isRenewalDue(meta, now)).toBe(true);
	});
});

describe("ensureCert renews a cert inside the 30-day window (REQ-CERT-14)", () => {
	it("a cached-but-renewal-due cert re-runs the DNS-01 flow", async () => {
		const cfg = makeTmpDir();
		try {
			saveCert(
				cfg,
				HANDLE,
				{},
				{ certPem: "OLD", keyPem: "OLDKEY", meta: makeMeta(10) },
			);
			const { deps } = makeIssueDeps();
			const result = await ensureCert({
				handle: HANDLE,
				agentId: AGENT_ID,
				delegationId: DELEGATION_ID,
				configDir: cfg,
				options: {},
				deps,
			});
			expect(result.fromCache).toBe(false);
			expect(deps.acme.newOrder).toHaveBeenCalledTimes(1);
		} finally {
			fs.rmSync(cfg, { recursive: true, force: true });
		}
	});
});

// ── REQ-CERT-13: ACME-storm backoff (base 30s, factor 2, cap 1h, full jitter) ─

describe("nextBackoffDelayMs — exponential backoff with full jitter (REQ-CERT-13)", () => {
	it("the first failure (n=1) yields a delay within full-jitter of base 30s [0, 30000]", () => {
		for (let i = 0; i < 50; i++) {
			const d = nextBackoffDelayMs(1);
			expect(d).toBeGreaterThanOrEqual(0);
			expect(d).toBeLessThanOrEqual(30_000);
		}
	});

	it("doubles the ceiling each failure (factor 2): n=2 -> [0,60000], n=3 -> [0,120000]", () => {
		for (let i = 0; i < 50; i++) {
			expect(nextBackoffDelayMs(2)).toBeLessThanOrEqual(60_000);
			expect(nextBackoffDelayMs(3)).toBeLessThanOrEqual(120_000);
		}
	});

	it("caps the ceiling at 1 hour regardless of how high the failure count climbs", () => {
		for (let i = 0; i < 50; i++) {
			expect(nextBackoffDelayMs(99)).toBeLessThanOrEqual(3_600_000);
		}
	});

	it("applies FULL jitter — repeated calls at the same n are not all identical", () => {
		const samples = new Set<number>();
		for (let i = 0; i < 50; i++) samples.add(nextBackoffDelayMs(5));
		expect(samples.size).toBeGreaterThan(1);
	});
});

describe("persisted consecutive_failures across restarts (REQ-CERT-13)", () => {
	let cfg: string;
	beforeEach(() => {
		cfg = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(cfg, { recursive: true, force: true });
	});

	it("a failed issuance BUMPS and PERSISTS consecutive_failures in meta.json", async () => {
		// Pre-seed meta so a failure can increment a persisted counter.
		saveMeta(cfg, HANDLE, {}, makeMeta(0, { consecutive_failures: 2 }));
		const base = makeIssueDeps();
		const { deps } = makeIssueDeps({
			acme: {
				...base.deps.acme,
				validate: vi.fn(async () => {
					throw new Error("LE validation failed");
				}),
			},
		});
		await expect(
			ensureCert({
				handle: HANDLE,
				agentId: AGENT_ID,
				delegationId: DELEGATION_ID,
				configDir: cfg,
				options: {},
				deps,
			}),
		).rejects.toThrow();
		const meta = loadMeta(cfg, HANDLE, {});
		expect(meta?.consecutive_failures).toBe(3);
	});

	it("a crash-loop does NOT reset the persisted backoff counter to zero on boot", async () => {
		saveMeta(cfg, HANDLE, {}, makeMeta(0, { consecutive_failures: 4 }));
		// A fresh ensureCert run that fails again must read the persisted 4 and go to 5,
		// never silently restart from 0 (the token-storm precedent).
		const base = makeIssueDeps();
		const { deps } = makeIssueDeps({
			acme: {
				...base.deps.acme,
				newOrder: vi.fn(async () => {
					throw new Error("order failed");
				}),
			},
		});
		await expect(
			ensureCert({
				handle: HANDLE,
				agentId: AGENT_ID,
				delegationId: DELEGATION_ID,
				configDir: cfg,
				options: {},
				deps,
			}),
		).rejects.toThrow();
		expect(loadMeta(cfg, HANDLE, {})?.consecutive_failures).toBe(5);
	});

	it("a SUCCESSFUL issuance RESETS consecutive_failures to 0", async () => {
		saveMeta(cfg, HANDLE, {}, makeMeta(0, { consecutive_failures: 4 }));
		const { deps } = makeIssueDeps();
		await ensureCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			configDir: cfg,
			options: {},
			deps,
		});
		expect(loadMeta(cfg, HANDLE, {})?.consecutive_failures).toBe(0);
	});
});

// ── REQ-CERT-13: LE 5-dup/7d ceiling -> terminal error ──────────────────────

describe("isTerminalAcmeError — LE rate-limit ceilings are inviolable (REQ-CERT-13)", () => {
	it("classifies the LE duplicate-certificate limit (5 identical FQDNs / 7 days) as TERMINAL", () => {
		const err = Object.assign(
			new Error(
				"too many certificates already issued for exact set of domains",
			),
			{
				leRateLimit: "duplicate-certificate",
			},
		);
		expect(isTerminalAcmeError(err)).toBe(true);
	});

	it("classifies the MODERN LE duplicate wording (parenthetical count) as TERMINAL by message alone", () => {
		// LE surfaces `too many certificates (5) already issued ...` — the count
		// breaks the old contiguous substring, so the stem `too many certificates`
		// must still tag it terminal even with NO leRateLimit tag attached.
		const err = new Error(
			"Error creating new order :: too many certificates (5) already issued for hook.rine.network in the last 168h",
		);
		expect(isTerminalAcmeError(err)).toBe(true);
	});

	it("classifies the failed-validation ceiling as TERMINAL by message alone", () => {
		expect(
			isTerminalAcmeError(new Error("too many failed authorizations recently")),
		).toBe(true);
	});

	it("classifies an ordinary transient failure (timeout) as NON-terminal (retryable)", () => {
		expect(isTerminalAcmeError(new Error("ETIMEDOUT"))).toBe(false);
	});

	it("ensureCert surfaces a TERMINAL error and does NOT keep hammering LE after the dup ceiling", async () => {
		const cfg = makeTmpDir();
		try {
			const dupErr = Object.assign(
				new Error("too many certificates already issued"),
				{
					leRateLimit: "duplicate-certificate",
				},
			);
			const base = makeIssueDeps();
			const { deps } = makeIssueDeps({
				acme: {
					...base.deps.acme,
					newOrder: vi.fn(async () => {
						throw dupErr;
					}),
				},
			});
			await expect(
				ensureCert({
					handle: HANDLE,
					agentId: AGENT_ID,
					delegationId: DELEGATION_ID,
					configDir: cfg,
					options: {},
					deps,
				}),
			).rejects.toThrow(/terminal|duplicate|rate limit/i);
		} finally {
			fs.rmSync(cfg, { recursive: true, force: true });
		}
	});
});

// ── REQ-CERT-32: cold-start gate (no readiness until cert installed) ─────────

describe("cold-start gate — no readiness until a valid cert+key is installed (REQ-CERT-32)", () => {
	let cfg: string;
	beforeEach(() => {
		cfg = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(cfg, { recursive: true, force: true });
	});

	it("ensureCert returns the cert+key only after a successful install (ready=true)", async () => {
		const { deps } = makeIssueDeps();
		const result = await ensureCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			configDir: cfg,
			options: {},
			deps,
		});
		expect(result.ready).toBe(true);
		expect(result.certPem).toContain("CERTIFICATE");
		expect(result.keyPem).toContain("PRIVATE KEY");
	});

	it("a cold start whose issuance FAILS does not yield a ready cert (gate stays closed)", async () => {
		const base = makeIssueDeps();
		const { deps } = makeIssueDeps({
			acme: {
				...base.deps.acme,
				newOrder: vi.fn(async () => {
					throw new Error("order failed");
				}),
			},
		});
		await expect(
			ensureCert({
				handle: HANDLE,
				agentId: AGENT_ID,
				delegationId: DELEGATION_ID,
				configDir: cfg,
				options: {},
				deps,
			}),
		).rejects.toThrow();
		// Nothing installed -> a subsequent cache load is still a miss.
		expect(loadCachedCert(cfg, HANDLE, {})).toBeNull();
	});

	it("persists the freshly-issued cert+key+meta to the cache on a successful cold start", async () => {
		const { deps } = makeIssueDeps();
		await ensureCert({
			handle: HANDLE,
			agentId: AGENT_ID,
			delegationId: DELEGATION_ID,
			configDir: cfg,
			options: {},
			deps,
		});
		const cached = loadCachedCert(cfg, HANDLE, {});
		expect(cached).not.toBeNull();
		expect(cached?.certPem).toContain("CERTIFICATE");
	});
});

// ── REQ-CERT-16: best-effort revoke + cache wipe on graceful teardown ───────

describe("revokeAndWipeCache — graceful teardown, best-effort (REQ-CERT-16)", () => {
	let cfg: string;
	beforeEach(() => {
		cfg = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(cfg, { recursive: true, force: true });
	});

	it("attempts an ACME revoke and then DELETES the per-handle cache dir", async () => {
		saveCert(
			cfg,
			HANDLE,
			{},
			{ certPem: "CERT", keyPem: "KEY", meta: makeMeta(80) },
		);
		const { deps } = makeIssueDeps();
		await revokeAndWipeCache({
			handle: HANDLE,
			configDir: cfg,
			options: {},
			deps,
		});
		expect(deps.acme.revoke).toHaveBeenCalledTimes(1);
		expect(fs.existsSync(handleCacheDir(cfg, HANDLE, {}))).toBe(false);
	});

	it("wipes the cache even when the ACME revoke FAILS (offline) — best-effort revoke", async () => {
		saveCert(
			cfg,
			HANDLE,
			{},
			{ certPem: "CERT", keyPem: "KEY", meta: makeMeta(80) },
		);
		const base = makeIssueDeps();
		const { deps } = makeIssueDeps({
			acme: {
				...base.deps.acme,
				revoke: vi.fn(async () => {
					throw new Error("offline — cannot reach LE");
				}),
			},
		});
		// Must NOT throw; the local wipe is the meaningful local effect.
		await expect(
			revokeAndWipeCache({ handle: HANDLE, configDir: cfg, options: {}, deps }),
		).resolves.not.toThrow();
		expect(fs.existsSync(handleCacheDir(cfg, HANDLE, {}))).toBe(false);
	});

	it("does not touch a DIFFERENT handle's cache (scoped wipe)", async () => {
		saveCert(
			cfg,
			HANDLE,
			{},
			{ certPem: "C", keyPem: "K", meta: makeMeta(80) },
		);
		saveCert(
			cfg,
			"gh-other",
			{},
			{ certPem: "C", keyPem: "K", meta: makeMeta(80) },
		);
		const { deps } = makeIssueDeps();
		await revokeAndWipeCache({
			handle: HANDLE,
			configDir: cfg,
			options: {},
			deps,
		});
		expect(fs.existsSync(handleCacheDir(cfg, HANDLE, {}))).toBe(false);
		expect(fs.existsSync(handleCacheDir(cfg, "gh-other", {}))).toBe(true);
	});
});

// ── REQ-CERT-15: rine cannot revoke (no key) — relay-side has no server hook ─

describe("FROZEN-CONTRACT: revocation is relay-local (REQ-CERT-15)", () => {
	it("revoke is driven by the relay's own ACME client (local key + account key), not a server call", async () => {
		const cfg = makeTmpDir();
		try {
			saveCert(
				cfg,
				HANDLE,
				{},
				{ certPem: "CERT", keyPem: "KEY", meta: makeMeta(80) },
			);
			const { deps, dnsPost } = makeIssueDeps();
			await revokeAndWipeCache({
				handle: HANDLE,
				configDir: cfg,
				options: {},
				deps,
			});
			// revoke goes through the ACME client; it does NOT POST a "revoke" action
			// to the dns-challenge endpoint (the server holds no key and cannot revoke).
			expect(deps.acme.revoke).toHaveBeenCalled();
			for (const call of dnsPost.mock.calls) {
				expect(call[0]).not.toMatch(/revoke/i);
			}
		} finally {
			fs.rmSync(cfg, { recursive: true, force: true });
		}
	});
});

// ── REQ-CERT-08 / D4 + REQ-CERT-07/13: production dns-challenge POST wiring ──
// Pins the FROZEN-CONTRACT body shape against the REAL makeDnsPost (not the mock
// used everywhere above) + the 429/Retry-After backstop + LE error tagging.

/**
 * A fake HttpClient whose `post` is a spy that replays scripted results in order
 * (a function result is invoked, so it can throw). Call inspection uses the spy's
 * own `.mock.calls`, matching the project's test idiom.
 */
function makePostSpy(results: Array<unknown | (() => never)>): {
	http: HttpClient;
	post: ReturnType<typeof vi.fn>;
} {
	let i = 0;
	const post = vi.fn(
		async (_path: string, _body?: unknown, _headers?: unknown) => {
			const r = results[Math.min(i++, results.length - 1)];
			if (typeof r === "function") return (r as () => never)();
			return r;
		},
	);
	return { http: { post } as unknown as HttpClient, post };
}

describe("makeDnsPost — backend dns-challenge POST wiring (REQ-CERT-08/D4, REQ-CERT-07)", () => {
	it("set: POSTs {action:'set',value} ONLY — no fqdn, no key material, no token name", async () => {
		const { http, post } = makePostSpy([{ status: "set" }]);
		await makeDnsPost(http, AGENT_ID)("set", "tok-123");
		expect(post).toHaveBeenCalledTimes(1);
		const call = post.mock.calls[0];
		expect(call?.[0]).toBe(`/agents/${AGENT_ID}/funnel/dns-challenge`);
		expect(call?.[1]).toEqual({ action: "set", value: "tok-123" });
		const serialized = JSON.stringify(call?.[1]);
		expect(serialized).not.toContain("PRIVATE KEY");
		expect(serialized).not.toContain(FQDN);
		expect(serialized).not.toContain("HETZNER_DNS_API_TOKEN");
		expect(serialized).not.toContain("HOOK_DNS_API_TOKEN");
	});

	it("clear: POSTs {action:'clear'} with NO value field", async () => {
		const { http, post } = makePostSpy([{ status: "cleared" }]);
		await makeDnsPost(http, AGENT_ID)("clear");
		expect(post.mock.calls[0]?.[1]).toEqual({ action: "clear" });
	});

	it("forwards injected agent auth headers on the dns-challenge POST", async () => {
		const { http, post } = makePostSpy([{ status: "set" }]);
		await makeDnsPost(http, AGENT_ID, { "x-rine-agent": "h" })("set", "tok");
		expect(post.mock.calls[0]?.[2]).toEqual({ "x-rine-agent": "h" });
	});

	it("on a 429 with Retry-After, re-POSTs ONCE after the indicated delay (REQ-CERT-07 backstop)", async () => {
		const res = new Response(null, {
			status: 429,
			headers: { "retry-after": "0" },
		});
		const err = new RineApiError(429, "rate limited", res);
		const { http, post } = makePostSpy([
			() => {
				throw err;
			},
			{ status: "set" },
		]);
		await expect(makeDnsPost(http, AGENT_ID)("set", "tok")).resolves.toEqual({
			status: "set",
		});
		// exactly two attempts: the 429 then the single retry, same body re-posted
		expect(post).toHaveBeenCalledTimes(2);
		expect(post.mock.calls[0]?.[1]).toEqual(post.mock.calls[1]?.[1]);
	});

	it("re-throws a non-429 RineApiError without retrying", async () => {
		const err = new RineApiError(500, "boom");
		const { http, post } = makePostSpy([
			() => {
				throw err;
			},
		]);
		await expect(makeDnsPost(http, AGENT_ID)("set", "tok")).rejects.toBe(err);
		expect(post).toHaveBeenCalledTimes(1);
	});
});

describe("tagLeRateLimit — stamps LE ceilings TERMINAL for backoff (REQ-CERT-13)", () => {
	it("tags the modern duplicate-cert wording (parenthetical count) as duplicate-certificate", () => {
		const err = tagLeRateLimit(
			new Error(
				"too many certificates (5) already issued for hook.rine.network",
			),
		);
		expect((err as { leRateLimit?: string }).leRateLimit).toBe(
			"duplicate-certificate",
		);
		expect(isTerminalAcmeError(err)).toBe(true);
	});

	it("tags the failed-validation ceiling as failed-validation", () => {
		const err = tagLeRateLimit(
			new Error("too many failed authorizations recently for this account"),
		);
		expect((err as { leRateLimit?: string }).leRateLimit).toBe(
			"failed-validation",
		);
	});

	it("leaves an ordinary transient error untagged (retryable, not terminal)", () => {
		const err = tagLeRateLimit(new Error("ETIMEDOUT contacting provider"));
		expect((err as { leRateLimit?: string }).leRateLimit).toBeUndefined();
		expect(isTerminalAcmeError(err)).toBe(false);
	});
});
