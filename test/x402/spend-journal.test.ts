import { execSync } from "node:child_process";
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	vi,
} from "vitest";
import { X402Error, X402_ERROR } from "../../src/x402/errors.js";
import {
	readDailySpent,
	recordSpend,
	reserveSpend,
} from "../../src/x402/spend-journal.js";
import {
	POLL_MS,
	spendLockPath,
	withSpendLock,
} from "../../src/x402/spend-lock.js";
import type {
	PaymentPolicy,
	PaymentRequirements,
} from "../../src/x402/types.js";

const AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const USDC_SEPOLIA = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const DAY1 = Date.parse("2026-07-18T10:00:00Z") / 1000;
const DAY1_LATE = Date.parse("2026-07-18T23:00:00Z") / 1000;
const DAY2 = Date.parse("2026-07-19T00:30:00Z") / 1000;

const POLICY: PaymentPolicy = {
	perTxCap: "5.00",
	dailyCap: "3.00",
	allowedAssets: ["USDC"],
	allowedNetworks: ["eip155:84532"],
	autoPayThreshold: "1.00",
};

function makeRequirement(
	over: Partial<PaymentRequirements> = {},
): PaymentRequirements {
	return {
		scheme: "exact",
		network: "eip155:84532",
		amount: "1000000", // 1.00 USDC (6 decimals) → 1_000_000 canonical
		asset: USDC_SEPOLIA,
		payTo: "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF",
		maxTimeoutSeconds: 60,
		extra: { name: "USDC", version: "2" },
		...over,
	};
}

function journalFile(dir: string): string {
	return join(dir, "keys", AGENT_ID, "wallet-spend.json");
}

function readPaidIds(dir: string): string[] {
	const j = JSON.parse(fs.readFileSync(journalFile(dir), "utf-8"));
	return j.paidIds ?? [];
}

describe("spend journal read/record", () => {
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-journal-test-"));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
	});

	it("returns_zero_when_no_journal", () => {
		expect(readDailySpent(dir, AGENT_ID, DAY1)).toBe(0n);
	});

	it("accumulates_within_same_day", () => {
		recordSpend(dir, AGENT_ID, 1_000_000n, DAY1);
		recordSpend(dir, AGENT_ID, 500_000n, DAY1_LATE);
		expect(readDailySpent(dir, AGENT_ID, DAY1_LATE)).toBe(1_500_000n);
	});

	it("resets_on_day_rollover", () => {
		recordSpend(dir, AGENT_ID, 1_000_000n, DAY1);
		expect(readDailySpent(dir, AGENT_ID, DAY2)).toBe(0n);
		recordSpend(dir, AGENT_ID, 250_000n, DAY2);
		expect(readDailySpent(dir, AGENT_ID, DAY2)).toBe(250_000n);
	});

	it("writes_journal_0600", () => {
		recordSpend(dir, AGENT_ID, 1n, DAY1);
		expect(fs.statSync(journalFile(dir)).mode & 0o777).toBe(0o600);
	});

	it("record_preserves_paidIds", () => {
		fs.mkdirSync(join(dir, "keys", AGENT_ID), { recursive: true });
		fs.writeFileSync(
			journalFile(dir),
			JSON.stringify({
				day: "2026-07-18",
				spentCanonical: "5",
				paidIds: ["m1"],
			}),
		);
		recordSpend(dir, AGENT_ID, 5n, DAY1);
		expect(readPaidIds(dir)).toEqual(["m1"]);
	});
});

describe("reserveSpend", () => {
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-reserve-test-"));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
	});

	async function expectCode(p: Promise<unknown>, code: string): Promise<void> {
		await expect(p).rejects.toBeInstanceOf(X402Error);
		await p.catch((e: X402Error) => expect(e.code).toBe(code));
	}

	it("reserves_and_returns_the_canonical_value", async () => {
		const v = await reserveSpend(dir, AGENT_ID, POLICY, makeRequirement(), {
			nowSeconds: DAY1,
		});
		expect(v).toBe(1_000_000n);
		expect(readDailySpent(dir, AGENT_ID, DAY1)).toBe(1_000_000n);
	});

	it("denies_by_default_when_policy_is_null", async () => {
		await expectCode(
			reserveSpend(dir, AGENT_ID, null, makeRequirement(), {
				nowSeconds: DAY1,
			}),
			X402_ERROR.NO_POLICY,
		);
		expect(readDailySpent(dir, AGENT_ID, DAY1)).toBe(0n);
	});

	it("enforces_the_daily_cap_across_sequential_reserves", async () => {
		for (let i = 0; i < 3; i++) {
			await reserveSpend(dir, AGENT_ID, POLICY, makeRequirement(), {
				messageId: `m${i}`,
				nowSeconds: DAY1,
			});
		}
		await expectCode(
			reserveSpend(dir, AGENT_ID, POLICY, makeRequirement(), {
				messageId: "m3",
				nowSeconds: DAY1,
			}),
			X402_ERROR.DAILY_CAP_EXCEEDED,
		);
		expect(readDailySpent(dir, AGENT_ID, DAY1)).toBe(3_000_000n);
	});

	it("refuses_a_repeat_of_the_same_message_with_already_paid", async () => {
		await reserveSpend(dir, AGENT_ID, POLICY, makeRequirement(), {
			messageId: "quote-1",
			nowSeconds: DAY1,
		});
		await expectCode(
			reserveSpend(dir, AGENT_ID, POLICY, makeRequirement(), {
				messageId: "quote-1",
				nowSeconds: DAY1,
			}),
			X402_ERROR.ALREADY_PAID,
		);
		expect(readDailySpent(dir, AGENT_ID, DAY1)).toBe(1_000_000n); // no double debit
		expect(readPaidIds(dir)).toEqual(["quote-1"]);
	});

	it("force_re_pays_a_message_with_a_single_paidIds_entry", async () => {
		await reserveSpend(dir, AGENT_ID, POLICY, makeRequirement(), {
			messageId: "quote-1",
			nowSeconds: DAY1,
		});
		const v = await reserveSpend(dir, AGENT_ID, POLICY, makeRequirement(), {
			messageId: "quote-1",
			force: true,
			nowSeconds: DAY1,
		});
		expect(v).toBe(1_000_000n);
		expect(readDailySpent(dir, AGENT_ID, DAY1)).toBe(2_000_000n); // debited twice
		expect(readPaidIds(dir)).toEqual(["quote-1"]); // still a single entry
	});

	it("day_rollover_resets_spend_and_paidIds", async () => {
		await reserveSpend(dir, AGENT_ID, POLICY, makeRequirement(), {
			messageId: "quote-1",
			nowSeconds: DAY1,
		});
		// Same messageId the next UTC day is NOT already-paid — the bucket reset.
		const v = await reserveSpend(dir, AGENT_ID, POLICY, makeRequirement(), {
			messageId: "quote-1",
			nowSeconds: DAY2,
		});
		expect(v).toBe(1_000_000n);
		expect(readDailySpent(dir, AGENT_ID, DAY2)).toBe(1_000_000n);
		expect(readPaidIds(dir)).toEqual(["quote-1"]);
	});

	it("tolerates_an_old_journal_without_paidIds", async () => {
		fs.mkdirSync(join(dir, "keys", AGENT_ID), { recursive: true });
		fs.writeFileSync(
			journalFile(dir),
			JSON.stringify({ day: "2026-07-18", spentCanonical: "500000" }), // v1, no paidIds
		);
		const v = await reserveSpend(dir, AGENT_ID, POLICY, makeRequirement(), {
			messageId: "quote-1",
			nowSeconds: DAY1,
		});
		expect(v).toBe(1_000_000n);
		expect(readDailySpent(dir, AGENT_ID, DAY1)).toBe(1_500_000n);
		expect(readPaidIds(dir)).toEqual(["quote-1"]);
	});

	it("the_no_messageId_path_never_touches_paidIds", async () => {
		await reserveSpend(dir, AGENT_ID, POLICY, makeRequirement(), {
			nowSeconds: DAY1,
		});
		expect(readPaidIds(dir)).toEqual([]);
	});

	it("computes_the_utc_day_bucket_inside_the_lock_not_before", async () => {
		// Clobber variant: when a reserve waits on a contended lock and the wall clock
		// crosses UTC midnight during the wait, the debit MUST land in the day observed
		// AFTER acquisition. Computing `day` before the lock would write the pre-rollover
		// day, clobbering the new day's independently-tracked total.
		const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
		const preRollover = Date.parse("2026-07-18T23:59:59.000Z"); // DAY1, seconds to go
		const postRollover = Date.parse("2026-07-19T00:00:01.000Z"); // DAY2, +2s (< budget)

		// A sibling holds the lock so the reserve is forced to wait (real cross-async
		// contention). The holder acquires under the real clock, before we freeze it.
		let releaseHolder: () => void = () => {};
		const gate = new Promise<void>((r) => {
			releaseHolder = r;
		});
		const holder = withSpendLock(spendLockPath(dir, AGENT_ID), () => gate);
		await sleep(10); // let the holder acquire

		// Freeze the clock at DAY1; the reserve is created and starts polling here.
		const clock = vi.spyOn(Date, "now").mockReturnValue(preRollover);
		const reserving = reserveSpend(dir, AGENT_ID, POLICY, makeRequirement());
		await sleep(POLL_MS * 2); // reserve is now blocked polling the held (fresh) lock

		// Midnight passes while the reserve still waits; then the holder releases.
		clock.mockReturnValue(postRollover);
		releaseHolder();
		const value = await reserving;
		await holder;
		clock.mockRestore();

		expect(value).toBe(1_000_000n);
		// The debit landed in the post-rollover DAY2 bucket, evaluated inside the lock.
		const written = JSON.parse(fs.readFileSync(journalFile(dir), "utf-8"));
		expect(written.day).toBe("2026-07-19");
		expect(readDailySpent(dir, AGENT_ID, postRollover / 1000)).toBe(1_000_000n);
	});
});

describe("reserveSpend cross-process contention", () => {
	const pkgRoot = fileURLToPath(new URL("../../", import.meta.url));
	const workerPath = fileURLToPath(
		new URL("./fixtures/reserve-worker.mjs", import.meta.url),
	);
	let dir: string;

	// The worker imports the BUILT package so the OS file-lock is genuinely
	// cross-process; ensure dist is current for a standalone `vitest run`.
	beforeAll(() => {
		execSync("npm run build", { cwd: pkgRoot, stdio: "ignore" });
	}, 120_000);

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-contend-test-"));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	function runWorker(
		args: string[],
	): Promise<{ code: number; stdout: string; stderr: string }> {
		return new Promise((resolve) => {
			const child = spawn(process.execPath, [workerPath, ...args]);
			let stdout = "";
			let stderr = "";
			child.stdout.on("data", (d) => (stdout += d));
			child.stderr.on("data", (d) => (stderr += d));
			child.on("close", (code) =>
				resolve({ code: code ?? -1, stdout, stderr }),
			);
		});
	}

	it("N_racing_reservers_never_exceed_the_daily_cap", async () => {
		// dailyCap 3.00 admits exactly 3 of 6 concurrent 1.00 reservations; a
		// lost update would let >3 through and overshoot the cap.
		const N = 6;
		const req = JSON.stringify(makeRequirement());
		const policy = JSON.stringify(POLICY);
		const results = await Promise.all(
			Array.from({ length: N }, (_, i) =>
				runWorker([dir, AGENT_ID, policy, req, `m${i}`, String(DAY1)]),
			),
		);
		// No worker crashed for a non-policy reason.
		for (const r of results) {
			expect(r.code === 0 || r.code === 3).toBe(true);
		}
		const ok = results.filter((r) => r.stdout.startsWith("OK "));
		const refused = results.filter(
			(r) => r.stdout === `ERR ${X402_ERROR.DAILY_CAP_EXCEEDED}`,
		);
		expect(ok.length).toBe(3);
		expect(refused.length).toBe(3);
		const sum = ok.reduce((s, r) => s + BigInt(r.stdout.slice(3)), 0n);
		expect(sum).toBe(3_000_000n);
		expect(sum <= 3_000_000n).toBe(true);
		expect(readDailySpent(dir, AGENT_ID, DAY1)).toBe(3_000_000n);
		expect(readPaidIds(dir).length).toBe(3); // exactly the 3 that reserved
	}, 30_000);
});
