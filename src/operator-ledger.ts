/**
 * The durable record of operator statements an agent has accepted: which row
 * carried each nonce, whether its text has been shown to a model, and the digest
 * of the ciphertext that was classified.
 *
 * One small JSON file per agent in the config dir, written under a cross-process
 * lock because the wake path and a tool path can run in different processes on
 * the same dir. The Python twin (`rine._operator_ledger`) reads and writes the
 * same file. Losing the file weakens replay protection only: the freshness window
 * still bounds how old a replayed statement can be. A file that is there but cannot
 * be read is a different case and fails closed: it is never read as empty and
 * overwritten, so the caller treats the row as data until someone looks.
 */

import * as fs from "node:fs";
import { join } from "node:path";
import { writeAtomic } from "./config.js";
import { type FileLockTiming, withFileLock } from "./file-lock.js";
import {
	OPERATOR_FUTURE_SKEW_MS,
	OPERATOR_WINDOW_MS,
} from "./operator-statement.js";

/** What the ledger remembers about one nonce. */
export interface LedgerEntry {
	readonly rowId: string;
	/** Hex SHA-256 of the row's `encrypted_payload` as it was classified. */
	readonly digest: string;
	/** True once a model has been shown the text. A wake alone never sets it. */
	readonly rendered: boolean;
	/** The statement's `issued_at` in epoch milliseconds, for expiry. */
	readonly issuedAtMs: number;
}

/** Whose ledger, and where it lives. */
export interface LedgerLoc {
	readonly configDir: string;
	readonly agentId: string;
}

/**
 * The critical section is one small read and one atomic write, so a holder older than
 * `staleMs` is dead. `staleMs` is longer than `timeoutMs` on purpose: a waiter gives up
 * (and the row is treated as data) before it would take a live holder's lock and let two
 * writers lose each other's entries.
 */
const LEDGER_LOCK: FileLockTiming = {
	staleMs: 30_000,
	timeoutMs: 10_000,
	pollMs: 50,
};

/** Agent ids are compared without regard to case, so one agent has one ledger whatever case its id was typed in. */
function ledgerPath(loc: LedgerLoc): string {
	const stem = (loc.agentId || "default")
		.toLowerCase()
		.replace(/[^A-Za-z0-9._-]/g, "_")
		.slice(0, 128);
	return join(loc.configDir, `operator_ledger_${stem}.json`);
}

function isEntry(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unreadable(path: string): Error {
	return new Error(
		`${path} is not a readable operator ledger; move it aside to start a new one`,
	);
}

/** The stored entries; a missing file reads as empty, and one that is present but malformed throws. */
function readEntries(path: string): Map<string, LedgerEntry> {
	const entries = new Map<string, LedgerEntry>();
	let text: string;
	try {
		text = fs.readFileSync(path, "utf-8");
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === "ENOENT") return entries;
		throw err;
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw unreadable(path);
	}
	const stored = isEntry(parsed) ? parsed.entries : undefined;
	if (!isEntry(stored)) throw unreadable(path);
	for (const [nonce, raw] of Object.entries(stored)) {
		if (!isEntry(raw)) throw unreadable(path);
		const { row_id: rowId, digest, rendered, issued_ms: issuedAtMs } = raw;
		if (typeof rowId !== "string" || typeof digest !== "string")
			throw unreadable(path);
		if (typeof rendered !== "boolean" || typeof issuedAtMs !== "number")
			throw unreadable(path);
		entries.set(nonce, { rowId, digest, rendered, issuedAtMs });
	}
	return entries;
}

function serialise(entries: ReadonlyMap<string, LedgerEntry>): string {
	// fromEntries defines own keys, so a nonce named `__proto__` is stored like any other.
	const stored = Object.fromEntries(
		[...entries].map(([nonce, e]) => [
			nonce,
			{
				row_id: e.rowId,
				digest: e.digest,
				rendered: e.rendered,
				issued_ms: e.issuedAtMs,
			},
		]),
	);
	return JSON.stringify({ v: 1, entries: stored });
}

/**
 * Read the ledger, run `change` on it and write it back when `change` altered it,
 * all under the lock. Entries whose statement is older than the window can no
 * longer be replayed as a new instruction, so they are dropped on the way in.
 * The lock wait is asynchronous, so a sibling process holding it does not freeze the
 * caller's event loop. Rejects when the lock, the read or the write fails: the caller
 * decides what that means.
 */
export function updateLedger<T>(
	loc: LedgerLoc,
	nowMs: number,
	change: (entries: Map<string, LedgerEntry>) => T,
): Promise<T> {
	const path = ledgerPath(loc);
	return withFileLock(`${path}.lock`, LEDGER_LOCK, async () => {
		const entries = readEntries(path);
		const horizon = nowMs - OPERATOR_WINDOW_MS - OPERATOR_FUTURE_SKEW_MS;
		for (const [nonce, e] of entries)
			if (e.issuedAtMs < horizon) entries.delete(nonce);
		const before = serialise(entries);
		const result = change(entries);
		const after = serialise(entries);
		if (after !== before) writeAtomic(path, after);
		return result;
	});
}
