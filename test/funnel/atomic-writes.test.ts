// The funnel's private files (cert key, cert, meta, attempt ledger, ACME account
// key) are written through the shared `writeAtomic`: a random exclusive temp
// file at 0600, then a rename. A `.tmp` symlink planted beside a target is
// never written through, and every final file is 0600.

import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("acme-client", async (importOriginal) => {
	const real = await importOriginal<typeof import("acme-client")>();
	class OfflineClient {
		async createAccount(): Promise<void> {}
	}
	return { ...real, Client: OfflineClient };
});

import { buildAcmeClient } from "../../src/funnel/acme.js";
import {
	type CertMeta,
	accountKeyPath,
	funnelCacheDir,
	handleCacheDir,
	saveCert,
	saveMeta,
} from "../../src/funnel/cert-cache.js";
import { saveAttemptLedger } from "../../src/funnel/cert-lock.js";

const AGENT_LABEL = "a1b2c3d4e5";

function meta(): CertMeta {
	return {
		directory_url: "https://acme-v02.api.letsencrypt.org/directory",
		not_after: new Date(Date.now() + 80 * 86_400_000).toISOString(),
		delegation_id: "d-1",
		last_attempt_ts: 0,
		consecutive_failures: 0,
	};
}

/** Plant `<target>.tmp` as a symlink to a decoy outside the funnel tree. */
function plantTmpSymlink(target: string, decoy: string): void {
	fs.mkdirSync(join(target, ".."), { recursive: true, mode: 0o700 });
	fs.writeFileSync(decoy, "DECOY");
	fs.symlinkSync(decoy, `${target}.tmp`);
}

function mode(path: string): number {
	return fs.statSync(path).mode & 0o777;
}

describe("funnel private files are written atomically and never through a planted .tmp", () => {
	let cfg: string;
	let decoy: string;
	beforeEach(() => {
		cfg = fs.mkdtempSync(join(tmpdir(), "rine-funnel-atomic-"));
		decoy = join(cfg, "decoy.txt");
	});
	afterEach(() => {
		fs.rmSync(cfg, { recursive: true, force: true });
	});

	for (const file of ["key.pem", "cert.pem", "meta.json"]) {
		it(`saveCert does not write ${file} through a planted .tmp symlink`, () => {
			const target = join(handleCacheDir(cfg, AGENT_LABEL, {}), file);
			plantTmpSymlink(target, decoy);
			saveCert(
				cfg,
				AGENT_LABEL,
				{},
				{ certPem: "CERT", keyPem: "KEY", meta: meta() },
			);
			expect(fs.readFileSync(decoy, "utf-8")).toBe("DECOY");
			expect(fs.lstatSync(target).isSymbolicLink()).toBe(false);
			expect(mode(target)).toBe(0o600);
		});
	}

	it("saveMeta replaces an existing meta.json with a 0600 file", () => {
		saveMeta(cfg, AGENT_LABEL, {}, meta());
		const path = join(handleCacheDir(cfg, AGENT_LABEL, {}), "meta.json");
		fs.chmodSync(path, 0o644);
		saveMeta(cfg, AGENT_LABEL, {}, { ...meta(), consecutive_failures: 2 });
		expect(
			JSON.parse(fs.readFileSync(path, "utf-8")).consecutive_failures,
		).toBe(2);
		expect(mode(path)).toBe(0o600);
	});

	it("saveAttemptLedger does not write through a planted .tmp symlink and lands 0600", () => {
		const target = join(
			funnelCacheDir(cfg, {}),
			`${AGENT_LABEL}.attempts.json`,
		);
		plantTmpSymlink(target, decoy);
		saveAttemptLedger(
			cfg,
			AGENT_LABEL,
			{},
			{ consecutive_failures: 1, last_attempt_ts: 5 },
		);
		expect(fs.readFileSync(decoy, "utf-8")).toBe("DECOY");
		expect(fs.lstatSync(target).isSymbolicLink()).toBe(false);
		expect(mode(target)).toBe(0o600);
	});

	it("buildAcmeClient does not write a new account key through a planted .tmp symlink and lands 0600", async () => {
		const target = accountKeyPath(cfg, {});
		plantTmpSymlink(target, decoy);
		await buildAcmeClient(cfg, {});
		expect(fs.readFileSync(decoy, "utf-8")).toBe("DECOY");
		expect(fs.lstatSync(target).isSymbolicLink()).toBe(false);
		expect(fs.readFileSync(target, "utf-8")).toContain("PRIVATE KEY");
		expect(mode(target)).toBe(0o600);
	});

	it("buildAcmeClient reuses an existing account key without rewriting it", async () => {
		const target = accountKeyPath(cfg, {});
		await buildAcmeClient(cfg, {});
		const first = fs.readFileSync(target, "utf-8");
		await buildAcmeClient(cfg, {});
		expect(fs.readFileSync(target, "utf-8")).toBe(first);
	});
});
