import { ed25519 } from "@noble/curves/ed25519.js";
import { ascii } from "./bytes.js";
import { verifyEd25519Strict } from "./ed25519-strict.js";
import { fromBase64Url, toBase64Url } from "./keys.js";

export type JcsValue = string | number;
export type JcsObject = { [key: string]: JcsValue };

export class JwsError extends Error {}

export const JwsTyp = {
	BranchCert: "rine-branch-cert+jws",
	AgentCert: "rine-agent-cert+jws",
	Assertion: "rine-assertion+jwt",
	RegisterPop: "rine-register-pop+jws",
} as const;
export type JwsTyp = (typeof JwsTyp)[keyof typeof JwsTyp];

const KEY_RE = /^[a-z_]{1,16}$/;
const MAX_SAFE = 9007199254740991;

const decoder = new TextDecoder();

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		return false;
	}
	const proto = Object.getPrototypeOf(value);
	return proto === Object.prototype || proto === null;
}

function quoteString(value: unknown): string {
	if (typeof value !== "string") {
		throw new JwsError("canonicalize: value must be a string or integer");
	}
	for (const char of value) {
		const code = char.codePointAt(0) ?? 0;
		if (code < 0x20 || code > 0x7e || char === '"' || char === "\\") {
			throw new JwsError(
				"canonicalize: string outside the printable-ASCII profile",
			);
		}
	}
	return `"${value}"`;
}

function canonicalValue(value: unknown): string {
	if (typeof value === "number") {
		if (!Number.isSafeInteger(value) || value < 0 || value > MAX_SAFE) {
			throw new JwsError("canonicalize: integer outside [0, 2^53)");
		}
		return String(value);
	}
	return quoteString(value);
}

/** Restricted JCS profile: plain objects of printable-ASCII strings and integers. */
export function canonicalize(value: unknown): string {
	if (!isPlainObject(value)) {
		throw new JwsError("canonicalize: top level must be a plain object");
	}
	const keys = Object.keys(value);
	for (const key of keys) {
		if (!KEY_RE.test(key)) {
			throw new JwsError(`canonicalize: key outside profile: ${key}`);
		}
	}
	keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
	const body = keys
		.map((key) => `${quoteString(key)}:${canonicalValue(value[key])}`)
		.join(",");
	return `{${body}}`;
}

export function isCanonicalText(text: string): boolean {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return false;
	}
	try {
		return canonicalize(parsed) === text;
	} catch {
		return false;
	}
}

const header = (typ: JwsTyp): JcsObject => ({ alg: "Ed25519", typ });

function decodePart(part: string): Uint8Array {
	const bytes = fromBase64Url(part);
	if (toBase64Url(bytes) !== part) {
		throw new JwsError("jws: part is not canonical base64url");
	}
	return bytes;
}

function signJwsRaw(headerText: string, payloadText: string, seed: Uint8Array): string {
	const input = `${toBase64Url(ascii(headerText))}.${toBase64Url(ascii(payloadText))}`;
	return `${input}.${toBase64Url(ed25519.sign(ascii(input), seed))}`;
}

export function signJws(typ: JwsTyp, payload: JcsObject, seed: Uint8Array): string {
	return signJwsRaw(canonicalize(header(typ)), canonicalize(payload), seed);
}

export function verifyJws(
	compact: string,
	publicKey: Uint8Array,
	typ: JwsTyp,
): JcsObject {
	const parts = compact.split(".");
	if (parts.length !== 3) {
		throw new JwsError("jws: expected 3 parts");
	}
	const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
	const headerText = decoder.decode(decodePart(headerPart));
	if (headerText !== canonicalize(header(typ))) {
		throw new JwsError("jws: header is not the exact expected bytes");
	}
	const input = ascii(`${headerPart}.${payloadPart}`);
	if (!verifyEd25519Strict(publicKey, input, decodePart(signaturePart))) {
		throw new JwsError("jws: bad signature");
	}
	const payloadText = decoder.decode(decodePart(payloadPart));
	if (!isCanonicalText(payloadText)) {
		throw new JwsError("jws: payload is not canonical");
	}
	return JSON.parse(payloadText) as JcsObject;
}
