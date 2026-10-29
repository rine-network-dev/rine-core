import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE } from "@noble/curves/utils.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { concat } from "./bytes.js";

const Point = ed25519.Point;
type EdPoint = InstanceType<typeof Point>;

const POINT_SIZE = 32;
const SIGNATURE_SIZE = 64;
const GROUP_ORDER = Point.Fn.ORDER;

const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

/**
 * Decodes a canonical, non-small-order Ed25519 point (order not dividing 8), or throws. A
 * cofactorless verifier accepts signatures under a small-order key or `R`, so the strict profile
 * refuses them explicitly.
 */
function strictPoint(encoded: Uint8Array, label: string): EdPoint {
	if (encoded.length !== POINT_SIZE) {
		throw new Error(`strict ed25519: ${label} must be 32 bytes`);
	}
	const text = toHex(encoded);
	let point: EdPoint;
	try {
		point = Point.fromHex(text, true);
	} catch {
		throw new Error(`strict ed25519: ${label} is not a valid point encoding`);
	}
	if (point.toHex() !== text) {
		throw new Error(`strict ed25519: ${label} is not a canonical encoding`);
	}
	if (point.multiplyUnsafe(8n).is0()) {
		throw new Error(`strict ed25519: ${label} has small order`);
	}
	return point;
}

/** Rejects public keys that are not canonical Ed25519 point encodings or that have small order. */
export function assertStrictEd25519PublicKey(publicKey: Uint8Array): void {
	strictPoint(publicKey, "public key");
}

/**
 * Strict Ed25519 verification: a canonical, non-small-order key and `R`, `S < L`, and the
 * cofactorless equation `[S]B = R + [k]A` of RFC 8032. noble's own verifier checks the cofactored
 * equation even with `zip215: false`, which would accept an `R` the server and OpenSSL refuse.
 */
export function verifyEd25519Strict(
	publicKey: Uint8Array,
	message: Uint8Array,
	signature: Uint8Array,
): boolean {
	if (signature.length !== SIGNATURE_SIZE) return false;
	try {
		const a = strictPoint(publicKey, "public key");
		const rBytes = signature.subarray(0, POINT_SIZE);
		const r = strictPoint(rBytes, "R");
		const s = bytesToNumberLE(signature.subarray(POINT_SIZE));
		if (s >= GROUP_ORDER) return false;
		const k = bytesToNumberLE(sha512(concat(rBytes, publicKey, message))) % GROUP_ORDER;
		return Point.BASE.multiplyUnsafe(s).equals(r.add(a.multiplyUnsafe(k)));
	} catch {
		return false;
	}
}
