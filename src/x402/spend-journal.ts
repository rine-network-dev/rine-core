// Daily spend journal (schema v2) + the reserve-under-lock commit. The journal is a
// worst-case loss bound, NOT a ledger: debits are permanent, with no refund path.

import * as fs from "node:fs";
import { dirname, join } from "node:path";
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

/**
 * The spend journal exists but cannot be read as one, so today's spend is
 * unknown. Reading it as empty would reset the daily cap, so every payment is
 * refused until the file is repaired. `detail` replaces the default cause.
 */
export class CorruptSpendJournalError extends Error {
	constructor(
		readonly path: string,
		detail = "is not a valid spend journal, so today's spend is unknown; payments are refused until it is repaired",
	) {
		super(`${path} ${detail}`);
		this.name = "CorruptSpendJournalError";
	}
}

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const CANONICAL_AMOUNT_RE = /^\d+$/;
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function isSpendJournal(value: unknown): value is SpendJournal {
	if (typeof value !== "object" || value === null) return false;
	const j = value as Record<string, unknown>;
	return (
		typeof j.day === "string" &&
		DAY_RE.test(j.day) &&
		typeof j.spentCanonical === "string" &&
		CANONICAL_AMOUNT_RE.test(j.spentCanonical) &&
		(j.paidIds === undefined ||
			(Array.isArray(j.paidIds) &&
				j.paidIds.every((id) => typeof id === "string")))
	);
}

/** The day bucket a read lands in, and what it already holds. */
interface JournalBucket {
	day: string;
	spent: bigint;
	paidIds: string[];
}

/**
 * Read today's bucket: empty for a missing or prior-day journal. A journal dated
 * tomorrow is today's bucket (the clock moved back across UTC midnight). One dated
 * further ahead, not UTF-8 or unparseable, throws, so the daily cap never fails open.
 */
function readJournal(
	configDir: string,
	agentId: string,
	nowSeconds: number,
): JournalBucket {
	const path = journalPath(configDir, agentId);
	const day = utcDay(nowSeconds);
	let bytes: Buffer;
	try {
		bytes = fs.readFileSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		return { day, spent: 0n, paidIds: [] };
	}
	let journal: unknown;
	try {
		journal = JSON.parse(STRICT_UTF8.decode(bytes));
	} catch {
		throw new CorruptSpendJournalError(path);
	}
	if (!isSpendJournal(journal)) throw new CorruptSpendJournalError(path);
	if (journal.day > utcDay(nowSeconds + 86_400)) {
		throw new CorruptSpendJournalError(
			path,
			`is dated ${journal.day}, later than today's date ${day}, so check the system clock; payments are refused until the clock is right or the file is repaired`,
		);
	}
	if (journal.day < day) return { day, spent: 0n, paidIds: [] };
	return {
		day: journal.day,
		spent: BigInt(journal.spentCanonical),
		paidIds: journal.paidIds ?? [],
	};
}

function writeJournal(
	configDir: string,
	agentId: string,
	journal: SpendJournal,
): void {
	const path = journalPath(configDir, agentId);
	fs.mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	writeAtomic(path, JSON.stringify(journal));
}

/** Today's spend in canonical micro-units; throws {@link CorruptSpendJournalError} on an unreadable journal. */
export function readDailySpent(
	configDir: string,
	agentId: string,
	nowSeconds: number = Date.now() / 1000,
): bigint {
	return readJournal(configDir, agentId, nowSeconds).spent;
}

/**
 * Add a spend to today's bucket, preserving `paidIds`. For status displays and tests
 * only: every pay site reserves through {@link reserveSpend} under the lock instead.
 */
export function recordSpend(
	configDir: string,
	agentId: string,
	canonicalAmount: bigint,
	nowSeconds: number = Date.now() / 1000,
): void {
	const { day, spent, paidIds } = readJournal(configDir, agentId, nowSeconds);
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
 * value: the LAST local act before transmit. Inside the lock it reads today's bucket
 * fresh (a day computed before a contended acquire could roll over), refuses a
 * same-message re-pay (`ALREADY_PAID` unless `force`), re-runs the full policy
 * against that total (deny-by-default on a null policy), then commits `spent + value`
 * and the message id. Throws a typed {@link X402Error} on any refusal.
 */
export async function reserveSpend(
	configDir: string,
	agentId: string,
	policy: PaymentPolicy | null,
	req: PaymentRequirements,
	opts: ReserveSpendOptions = {},
): Promise<bigint> {
	return withSpendLock(spendLockPath(configDir, agentId), async () => {
		const now = opts.nowSeconds ?? Date.now() / 1000;
		const { day, spent, paidIds } = readJournal(configDir, agentId, now);
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
