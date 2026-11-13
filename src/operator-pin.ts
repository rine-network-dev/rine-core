/**
 * The operator pin: which agent is the operator's console seat, and the full
 * public key it signs with. Configuration the agent cannot write supplies it.
 *
 * The key is compared in full, as bytes. A fingerprint of it, however it is
 * truncated, is a weaker statement: 48 bits can be ground to a collision.
 */

import { fromBase64Url, toBase64Url } from "./crypto/keys.js";
import { sameAgentId } from "./crypto/agent-keys.js";

/** The seat the agent trusts as its operator. */
export interface OperatorPin {
	/** The seat's agent id, a UUID. */
	readonly agentId: string;
	/** The seat's 32-byte Ed25519 public key as unpadded base64url, the form the key endpoint serves. */
	readonly signingKey: string;
	/**
	 * The seat's handle, when the host knows it. It drives only the look-alike check
	 * ({@link looksLikeSeat}); authority compares the id and the key, never a handle.
	 */
	readonly handle?: string;
}

/** Characters in an agent or group handle (`name@org.rine.network`, `#group@org`). */
const OUTSIDE_HANDLE = /[^A-Za-z0-9#@._-]/g;

/** The longest handle shown to a model or compared with a pin; anything longer is cut. */
const MAX_HANDLE_LENGTH = 128;

/** The local part Rine Fleet gives the operator console seat. */
const SEAT_LOCAL_PART = "ops";

const ED25519_KEY_BYTES = 32;
const UUID_PATTERN =
	/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Whether `fromAgentId` is the pinned seat. Ids only: a handle is never compared. */
export function pinMatchesSender(
	pin: OperatorPin,
	fromAgentId: string,
): boolean {
	return (
		UUID_PATTERN.test(pin.agentId.trim().toLowerCase()) &&
		sameAgentId(pin.agentId, fromAgentId)
	);
}

/**
 * Whether `verifyingKey`, the key that verified a signature, is the pinned key.
 *
 * Fails closed on every input that is not a real key: a missing verifying key, a
 * pin that is not canonical unpadded base64url of exactly 32 bytes, or a length
 * mismatch. The pin never compares equal to nothing.
 */
export function pinMatchesKey(
	pin: OperatorPin,
	verifyingKey: Uint8Array | null,
): boolean {
	if (verifyingKey === null || verifyingKey.length !== ED25519_KEY_BYTES)
		return false;
	const pinned = fromBase64Url(pin.signingKey);
	if (
		pinned.length !== ED25519_KEY_BYTES ||
		toBase64Url(pinned) !== pin.signingKey
	)
		return false;
	let difference = 0;
	for (let i = 0; i < ED25519_KEY_BYTES; i += 1) {
		difference |= (pinned[i] ?? 0) ^ (verifyingKey[i] ?? 0);
	}
	return difference === 0;
}

/**
 * A handle as it may appear in a wake line or be compared with the pinned seat handle: every
 * character the server would not have issued becomes `_`, and the length is capped.
 */
export function cleanHandle(handle: string): string {
	return handle.replace(OUTSIDE_HANDLE, "_").slice(0, MAX_HANDLE_LENGTH);
}

/**
 * Whether `handle`, a sender handle, is written like the operator's console seat. Needs a
 * pin: with none, nothing is the operator's, so no handle is treated as its look-alike. A
 * handle matches when it equals the pinned seat handle or, whatever the pin carries, when its
 * local part is `ops`. Both handles go through {@link cleanHandle} and compare
 * case-insensitively, so a long or out-of-set seat handle still matches the same sender
 * handle. Only a display decision: a look-alike shows the sender's agent id instead of its handle.
 */
export function looksLikeSeat(pin: OperatorPin | null, handle: string): boolean {
	if (pin === null) return false;
	const lowered = cleanHandle(handle).toLowerCase();
	const pinned =
		pin.handle === undefined ? "" : cleanHandle(pin.handle.trim()).toLowerCase();
	if (pinned !== "" && lowered === pinned) return true;
	const at = lowered.indexOf("@");
	return (at === -1 ? lowered : lowered.slice(0, at)) === SEAT_LOCAL_PART;
}
