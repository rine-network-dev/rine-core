/**
 * The operator statement: the one field a Fleet console send adds to the payload
 * it already signs and seals, which says what that message is for.
 *
 * The signature binds domain, recipient and payload, and nothing about time or
 * purpose, so a replayed or relabelled row would verify as the operator's own.
 * Putting purpose, recipient, a nonce and an instant inside the signed payload
 * lets the receiving plugin decide authority from signed bytes alone. The row's
 * `type` is unsigned and is never read for this.
 */

import { instantMicros } from "./crypto/instant.js";

/** The payload key that carries the statement. */
export const OPERATOR_STATEMENT_KEY = "rine.operator";

/** The only purpose that confers operator class. */
export const OPERATOR_COMMAND_PURPOSE = "operator.command";

/** How long after `issued_at` a statement still counts as a new instruction (24 hours). */
export const OPERATOR_WINDOW_MS = 24 * 60 * 60 * 1000;

/** How far ahead of the reader's clock `issued_at` may be before the statement is refused (5 minutes). */
export const OPERATOR_FUTURE_SKEW_MS = 5 * 60 * 1000;

/** What a nonce may look like: a hex or base64url digest, safe as a file key. */
const NONCE_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

const STATEMENT_VERSION = 1;

/** A well-formed operator statement, not yet held against any pin or clock. */
export interface OperatorStatement {
	readonly purpose: string;
	readonly agent: string;
	readonly nonce: string;
	/** `issued_at` as epoch milliseconds. */
	readonly issuedAtMs: number;
}

const INSTANT_FIELDS =
	/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/;

/**
 * Whether the instant's fields are a real calendar time. `Date.parse` rolls
 * 30 February over and reads `24:00:00` as midnight; the Python twin rejects both,
 * and a statement is signed data, so neither stack accepts what the other refuses.
 */
function isCalendarInstant(text: string): boolean {
	const m = INSTANT_FIELDS.exec(text);
	if (m === null) return false;
	const [year, month, day, hour, minute, second] = m
		.slice(1, 7)
		.map(Number) as [number, number, number, number, number, number];
	const offsetHour = Number(m[7] ?? 0);
	const offsetMinute = Number(m[8] ?? 0);
	const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
	return (
		year >= 1 &&
		month >= 1 &&
		month <= 12 &&
		day >= 1 &&
		day <= daysInMonth &&
		hour <= 23 &&
		minute <= 59 &&
		second <= 59 &&
		offsetHour <= 23 &&
		offsetMinute <= 59
	);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The statement a decrypted payload carries, or `null` for anything short of a
 * complete version-1 statement: no field, a wrong type, a nonce outside
 * {@link NONCE_PATTERN}, an `issued_at` that is not an RFC 3339 instant with an
 * offset. Unknown extra keys inside the statement are ignored.
 */
export function parseOperatorStatement(
	plaintext: string,
): OperatorStatement | null {
	let payload: unknown;
	try {
		payload = JSON.parse(plaintext);
	} catch {
		return null;
	}
	if (!isRecord(payload)) return null;
	const statement = payload[OPERATOR_STATEMENT_KEY];
	if (!isRecord(statement) || statement.v !== STATEMENT_VERSION) return null;
	const { purpose, agent, nonce, issued_at: issuedAt } = statement;
	if (typeof purpose !== "string" || typeof agent !== "string") return null;
	if (typeof nonce !== "string" || !NONCE_PATTERN.test(nonce)) return null;
	if (typeof issuedAt !== "string" || !isCalendarInstant(issuedAt)) return null;
	const micros = instantMicros(issuedAt);
	if (micros === undefined) return null;
	return { purpose, agent, nonce, issuedAtMs: Math.floor(micros / 1000) };
}

/**
 * `decrypted` without the statement key, so a stranger's own copy of the field
 * never reaches a model. Anything that is not a JSON object passes unchanged.
 */
export function stripOperatorStatement(decrypted: unknown): unknown {
	if (!isRecord(decrypted) || !(OPERATOR_STATEMENT_KEY in decrypted))
		return decrypted;
	const { [OPERATOR_STATEMENT_KEY]: _statement, ...rest } = decrypted;
	return rest;
}
