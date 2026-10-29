/**
 * The retry schedule of one escrow file the server has not yet taken.
 *
 * A file the server cannot take yet (a bare 403 or 404, a mis-attributed
 * refusal) is kept and retried, but not at the pace of every pass: each failure
 * doubles the wait before the next try, starting from the heartbeat interval and
 * capped at a day, and the sixteenth failure gives the file up — its epoch
 * recorded as lost, then the file deleted — instead of retrying for ever. The
 * state is a sidecar beside the file it counts, so a restart keeps it and it
 * follows the file when the file is given up:
 *   <file stem>.attempts   {"attempts":3,"next_try":<unix seconds>,"last":"403 escrow_no_seat"}
 *
 * The Python twin is `rine/_mls/escrow_retry.py`; the two read each other's
 * sidecars, so the key names and the unit (seconds) are shared.
 */
import * as fs from "node:fs";
import { writeAtomic } from "./config.js";
import { MLS_HEARTBEAT_MIN_INTERVAL_MS } from "./mls-heartbeat-interval.js";

/** After this many retryable refusals the file is given up: its epoch recorded as lost, then deleted. */
export const MAX_ATTEMPTS = 16;

/** Cap of the exponential delay: one day. */
const MAX_BACKOFF_S = 24 * 60 * 60;

const ATTEMPTS_SUFFIX = ".attempts";

/** One file's retry state. */
export interface AttemptRecord {
	/** Retryable refusals so far. */
	attempts: number;
	/** Unix seconds; the file is not tried before this. */
	nextTry: number;
	/** The last answer, e.g. `"403"` or `"403 escrow_no_seat"`. */
	last: string;
}

/** The sidecar path of a file: its own path with the extension swapped. */
function attemptsPath(filePath: string): string {
	return filePath.replace(/\.[^./]+$/, ATTEMPTS_SUFFIX);
}

/** The file's retry state, or `undefined` when absent, unreadable or malformed. */
export function readAttempts(filePath: string): AttemptRecord | undefined {
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(attemptsPath(filePath), "utf-8"));
	} catch {
		return undefined;
	}
	const { attempts, next_try: nextTry, last } = (raw ?? {}) as Record<string, unknown>;
	if (!Number.isSafeInteger(attempts) || typeof nextTry !== "number" || typeof last !== "string") {
		return undefined;
	}
	return { attempts: attempts as number, nextTry, last };
}

/** Whether the file may be tried at `nowS` (unix seconds): a file with no record always may. */
export function isDue(filePath: string, nowS: number): boolean {
	const record = readAttempts(filePath);
	return record === undefined || nowS >= record.nextTry;
}

/** Whether the file has used up its retries and must be given up. */
export function isExhausted(record: AttemptRecord | undefined): boolean {
	return record !== undefined && record.attempts >= MAX_ATTEMPTS;
}

/** The delay after `attempts` retryable refusals, capped at {@link MAX_BACKOFF_S}. */
function retryDelayS(attempts: number): number {
	return Math.min(
		MAX_BACKOFF_S,
		(MLS_HEARTBEAT_MIN_INTERVAL_MS / 1000) * 2 ** (attempts - 1),
	);
}

function write(filePath: string, record: AttemptRecord): void {
	writeAtomic(
		attemptsPath(filePath),
		JSON.stringify({
			attempts: record.attempts,
			next_try: record.nextTry,
			last: record.last,
		}),
	);
}

/** Record one retryable refusal and push the file's next try out. */
export function noteFailure(filePath: string, last: string, nowS: number): AttemptRecord {
	const attempts = (readAttempts(filePath)?.attempts ?? 0) + 1;
	const record = { attempts, nextTry: nowS + retryDelayS(attempts), last };
	write(filePath, record);
	return record;
}

/** Forget the file's state once the file is done. Missing is success. */
export function clearAttempts(filePath: string): void {
	fs.rmSync(attemptsPath(filePath), { force: true });
}
