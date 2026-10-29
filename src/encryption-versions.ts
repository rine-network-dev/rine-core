/**
 * The `encryption_version` values a message row may carry, and the two
 * questions every surface asks of one.
 *
 * Twin of the server's `EncryptionVersion` (`src/rine/encryption_versions.py`),
 * which is where the values are defined. They live here because every
 * TypeScript surface reads a row by them: a surface that spelled them out
 * again was one more place to edit for a new version, and one more answer to
 * "is this ciphertext I open" that could drift from the rest.
 */
import { CLEARTEXT_ENCRYPTION_VERSION } from "./a2a-cleartext.js";
import { ENCRYPTION_VERSION_HYBRID_V2 } from "./crypto/hybrid.js";

/** Every `encryption_version` the server stores, by the server enum's names. */
export const ENCRYPTION_VERSIONS = Object.freeze({
	HPKE_HYBRID_V2: ENCRYPTION_VERSION_HYBRID_V2,
	SENDER_KEY_V1: "sender-key-v1",
	MLS_V1: "mls-v1",
	NONE: CLEARTEXT_ENCRYPTION_VERSION,
} as const);

/** One of the {@link ENCRYPTION_VERSIONS} values. */
export type EncryptionVersion =
	(typeof ENCRYPTION_VERSIONS)[keyof typeof ENCRYPTION_VERSIONS];

/** The versions a group message is sealed under, one per group regime. */
export type GroupEncryptionVersion =
	| typeof ENCRYPTION_VERSIONS.SENDER_KEY_V1
	| typeof ENCRYPTION_VERSIONS.MLS_V1;

const DECRYPTABLE_VERSIONS: ReadonlySet<string> = new Set([
	ENCRYPTION_VERSIONS.HPKE_HYBRID_V2,
	ENCRYPTION_VERSIONS.SENDER_KEY_V1,
	ENCRYPTION_VERSIONS.MLS_V1,
]);

/**
 * Is this an encryption version a read may attempt at all?
 *
 * A payload carrying one of these that still fails is a FAILURE; a payload
 * carrying anything else was never ciphertext this build opens, and saying so
 * is a different answer. 🔴 It is what keeps an A2A artifact
 * (`encryption_version: "none"`) dispatching as cleartext — a gate that asked
 * "is the payload non-empty" instead would try to decrypt it.
 *
 * A caller that can ask `openInbound` or `probeReadability` should: they apply
 * this gate and every refusal after it. This predicate is for a surface that
 * runs its own decrypt and must decide the same thing first.
 */
export function isDecryptableVersion(
	version: string | null | undefined,
): boolean {
	return version != null && DECRYPTABLE_VERSIONS.has(version);
}

/**
 * Is this a group seal, under either regime?
 *
 * The version alone. A row is a group message only when it ALSO names its
 * group: the server sends neither without the other, and a caller that routes
 * on the version alone would send a 1:1 row down the group decrypt.
 */
export function isGroupEncryptionVersion(
	version: string | null | undefined,
): version is GroupEncryptionVersion {
	return (
		version === ENCRYPTION_VERSIONS.SENDER_KEY_V1 ||
		version === ENCRYPTION_VERSIONS.MLS_V1
	);
}
