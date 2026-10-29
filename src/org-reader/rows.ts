/** One `GET /org/activity?include=payload` item, parsed once. Ids are kept exactly as the server sent them. */
import type { EncryptionVersion } from "../encryption-versions.js";
import { instantMicros } from "../crypto/instant.js";
import { strictFromBase64Url } from "./base64url.js";
import { type Json, isCount, isObject, isText } from "./guards.js";

const MICROS_PER_MINUTE = 60_000_000;
const MICROS_PER_SECOND = 1_000_000;
const OFFSET_RE = /(?:Z|([+-])(\d{2}):(\d{2}))$/;

/** The directions the server sends on an activity row: its schema is closed over these three. */
export type Direction = "sent" | "received" | "internal";

const DIRECTIONS: readonly Direction[] = ["sent", "received", "internal"];

/**
 * A field the server types as an open string: the known members are offered, and an unknown one (a retired
 * encryption version, a newer message type) is kept verbatim so it degrades instead of failing the read.
 */
type KnownOr<T extends string> = T | (string & {});

export interface Party {
	readonly agentId: string;
	readonly handle: string | null;
	readonly orgId: string;
	readonly own: boolean;
}

/** A feed item with its ciphertext decoded from base64url. */
export interface Row {
	readonly id: string;
	/** The server's ISO string, passed unchanged to the signature and validity checks. */
	readonly createdAt: string;
	/** Microseconds since the epoch: the sort key, with `id`. */
	readonly createdAtMicros: number;
	/** The offset `createdAt` was written in, for `pythonIsoformat`. */
	readonly offsetMinutes: number;
	readonly type: string;
	readonly direction: Direction;
	readonly sender: Party;
	readonly recipient: Party | null;
	readonly groupId: string | null;
	readonly groupHandle: string | null;
	readonly conversationId: string;
	readonly encryptionVersion: KnownOr<EncryptionVersion>;
	readonly ciphertext: Uint8Array;
	readonly selfCiphertext: Uint8Array | null;
	readonly keyGen: number | null;
}

/** A row that did not parse: the page goes on, and the row costs one gap when it has an id. */
export interface ParseFailure {
	readonly malformed: true;
	readonly id: string | null;
}

export function isParseFailure(
	result: Row | ParseFailure,
): result is ParseFailure {
	return "malformed" in result;
}

class Malformed extends Error {}

export function object(value: unknown): Json {
	if (!isObject(value)) throw new Malformed();
	return value;
}

function text(value: unknown): string {
	if (!isText(value)) throw new Malformed();
	return value;
}

function direction(value: unknown): Direction {
	const found = DIRECTIONS.find((known) => known === value);
	if (found === undefined) throw new Malformed();
	return found;
}

function bytes(value: unknown): Uint8Array {
	const decoded = strictFromBase64Url(text(value));
	if (decoded === undefined) throw new Malformed();
	return decoded;
}

function keyGen(value: unknown): number | null {
	if (value === undefined || value === null) return null;
	if (!isCount(value)) throw new Malformed();
	return value;
}

function parseParty(value: unknown): Party {
	const raw = object(value);
	const handle = raw.handle ?? null;
	if (handle !== null && typeof handle !== "string") throw new Malformed();
	if (typeof raw.own !== "boolean") throw new Malformed();
	return {
		agentId: text(raw.agent_id),
		handle,
		orgId: text(raw.org_id),
		own: raw.own,
	};
}

/** The UTC offset of an RFC 3339 instant, in minutes. */
function offsetOf(createdAt: string): number {
	const match = OFFSET_RE.exec(createdAt);
	if (match?.[1] === undefined) return 0;
	const minutes = Number(match[2]) * 60 + Number(match[3]);
	return match[1] === "-" ? -minutes : minutes;
}

function buildRow(rawRow: unknown): Row {
	const raw = object(rawRow);
	const payload = object(raw.payload);
	const createdAt = text(raw.created_at);
	const createdAtMicros = instantMicros(createdAt);
	if (createdAtMicros === undefined) throw new Malformed();
	const group =
		raw.group === null || raw.group === undefined ? null : object(raw.group);
	const ownCopy = payload.self_encrypted_payload;
	const groupHandle = group?.handle ?? null;
	if (groupHandle !== null && typeof groupHandle !== "string")
		throw new Malformed();
	return {
		id: text(raw.id),
		createdAt,
		createdAtMicros,
		offsetMinutes: offsetOf(createdAt),
		type: text(raw.type),
		direction: direction(raw.direction),
		sender: parseParty(raw.from),
		recipient:
			raw.to === null || raw.to === undefined ? null : parseParty(raw.to),
		groupId: group === null ? null : text(group.id),
		groupHandle,
		conversationId: text(raw.conversation_id),
		encryptionVersion: text(raw.encryption_version),
		ciphertext: bytes(payload.encrypted_payload),
		selfCiphertext:
			ownCopy === undefined || ownCopy === null || ownCopy === ""
				? null
				: bytes(ownCopy),
		keyGen: keyGen(payload.key_gen),
	};
}

/** Parse one activity item; a malformed one becomes a `ParseFailure` instead of throwing. */
export function parseRow(raw: unknown): Row | ParseFailure {
	try {
		return buildRow(raw);
	} catch (err) {
		if (!(err instanceof Malformed)) throw err;
		const id = isObject(raw) && typeof raw.id === "string" ? raw.id : null;
		return { malformed: true, id };
	}
}

/** The org's agent on this row: the sender when it is ours, else the recipient. */
export function ownAgentId(row: Row): string {
	return row.sender.own || row.recipient === null
		? row.sender.agentId
		: row.recipient.agentId;
}

export function partyToJson(party: Party): Record<string, unknown> {
	return { agent_id: party.agentId, handle: party.handle, own: party.own };
}

function pad(value: number, width: number): string {
	return String(value).padStart(width, "0");
}

/**
 * `datetime.isoformat()` as Python renders an aware time: the wall clock at the original offset,
 * `+HH:MM` rather than `Z`, and the microsecond field only when it is not zero.
 */
export function pythonIsoformat(micros: number, offsetMinutes: number): string {
	const local = micros + offsetMinutes * MICROS_PER_MINUTE;
	const seconds = Math.floor(local / MICROS_PER_SECOND);
	const fraction = local - seconds * MICROS_PER_SECOND;
	const wall = new Date(seconds * 1000).toISOString().slice(0, 19);
	const sign = offsetMinutes < 0 ? "-" : "+";
	const abs = Math.abs(offsetMinutes);
	const zone = `${sign}${pad(Math.floor(abs / 60), 2)}:${pad(abs % 60, 2)}`;
	return `${wall}${fraction === 0 ? "" : `.${pad(fraction, 6)}`}${zone}`;
}
