// Daily spend journal (schema v2) + the reserve-under-lock commit. The journal
// is a worst-case loss bound, NOT a ledger: debits are permanent — there is no
// refund path. `reserveSpend` is the LAST local act before a payload is
// transmitted; after transmit nothing is written.

import * as fs from "node:fs";
import { join } from "node:path";
import { writeAtomic } from "../config.js";
import { validatePathId } from "../crypto/keys.js";
import { requirementCanonicalAmount } from "./assets.js";
import { X402Error, X402_ERROR } from "./errors.js";
import { enforcePolicy } from "./policy.js";
import { spendLockPath, withSpendLock } from "./spend-lock.js";
import type { PaymentPolicy, PaymentRequirements } from "./types.js";

/**
 * Journal schema v2 (interop-safe). Writers always emit `paidIds`; readers tolerate
 * its absence (a v1 journal written by an older client). UTC day rollover resets both
 * `spentCanonical` and `paidIds`.
 */
interface SpendJournal {
	day: string; // UTC YYYY-MM-DD bucket
	spentCanonical: string; // canonical micro-units, bigint string
	paidIds?: string[]; // message ids already reserved today (double-pay guard)
}

function journalPath(configDir: string, agentId: string): string {
	validatePathId(agentId, "agent ID");
	return join(configDir, "keys", agentId, "wallet-spend.json");
}

function utcDay(nowSeconds: number): string {
	return new Date(nowSeconds * 1000).toISOString().slice(0, 10);
}

/** Read today's journal; a prior-day (or missing/corrupt) journal reads as empty. */
function readJournal(
	path: string,
	day: string,
): { spent: bigint; paidIds: string[] } {
	try {
		const j = JSON.parse(fs.readFileSync(path, "utf-8")) as SpendJournal;
		if (j.day === day) {
			return { spent: BigInt(j.spentCanonical), paidIds: j.paidIds ?? [] };
		}
	} catch {}
	return { spent: 0n, paidIds: [] };
}

function writeJournal(
	configDir: string,
	agentId: string,
	journal: SpendJournal,
): void {
	fs.mkdirSync(join(configDir, "keys", agentId), {
		recursive: true,
		mode: 0o700,
	});
	writeAtomic(journalPath(configDir, agentId), JSON.stringify(journal));
}

/** Today's spend in canonical micro-units (0 if the journal is a prior day). */
export function readDailySpent(
	configDir: string,
	agentId: string,
	nowSeconds: number = Date.now() / 1000,
): bigint {
	return readJournal(journalPath(configDir, agentId), utcDay(nowSeconds)).spent;
}

/**
 * Add a spend to today's bucket (day-rollover resets), atomic write, preserving
 * `paidIds`. Retained for status displays and tests only — NO payment flow calls it;
 * every pay site reserves through {@link reserveSpend} under the lock instead.
 */
export function recordSpend(
	configDir: string,
	agentId: string,
	canonicalAmount: bigint,
	nowSeconds: number = Date.now() / 1000,
): void {
	const day = utcDay(nowSeconds);
	const { spent, paidIds } = readJournal(journalPath(configDir, agentId), day);
	writeJournal(configDir, agentId, {
		day,
		spentCanonical: (spent + canonicalAmount).toString(),
		paidIds,
	});
}

/** Options for {@link reserveSpend}. */
export interface ReserveSpendOptions {
	/** Message id of the quote — enables the ALREADY_PAID double-pay guard. */
	messageId?: string;
	/** Bypass the ALREADY_PAID guard to intentionally re-pay a message. */
	force?: boolean;
	/** Unix-seconds override for the UTC-day bucket (inject for tests). */
	nowSeconds?: number;
}

/**
 * Reserve a spend under the cross-process lock and return the reserved canonical
 * value. This is the LAST local act before transmit: acquire the lock,
 * compute the UTC-day bucket INSIDE the lock (a day computed before acquiring
 * could roll over while a contended acquire waits, clobbering the new day's total),
 * re-read the journal fresh (day rollover applies), refuse a same-message re-pay
 * (`ALREADY_PAID` unless `force`), re-run the FULL policy against the fresh spent
 * total (deny-by-default on a null policy, drift-proof), commit `spent + value` and
 * the message id, then release. Throws a typed {@link X402Error} on any refusal;
 * the debit is permanent once written.
 */
export async function reserveSpend(
	configDir: string,
	agentId: string,
	policy: PaymentPolicy | null,
	req: PaymentRequirements,
	opts: ReserveSpendOptions = {},
): Promise<bigint> {
	const jpath = journalPath(configDir, agentId);
	return withSpendLock(spendLockPath(configDir, agentId), async () => {
		const day = utcDay(opts.nowSeconds ?? Date.now() / 1000);
		const { spent, paidIds } = readJournal(jpath, day);
		if (opts.messageId && !opts.force && paidIds.includes(opts.messageId)) {
			throw new X402Error(
				X402_ERROR.ALREADY_PAID,
				`Payment already reserved for message ${opts.messageId} today`,
				{ messageId: opts.messageId },
			);
		}
		enforcePolicy(policy, req, spent);
		const value = requirementCanonicalAmount(req);
		const nextPaidIds =
			opts.messageId && !paidIds.includes(opts.messageId)
				? [...paidIds, opts.messageId]
				: paidIds;
		writeJournal(configDir, agentId, {
			day,
			spentCanonical: (spent + value).toString(),
			paidIds: nextPaidIds,
		});
		return value;
	});
}
