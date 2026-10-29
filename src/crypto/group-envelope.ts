/**
 * The authenticity check every group read ends in, whichever regime opened the
 * ciphertext. Internal to rine-core: the package exports only the error it
 * throws, {@link GroupAuthenticityError}.
 */
import type { HttpClient } from "../http.js";
import { verifyEnvelopeSender } from "./agent-keys.js";
import { decodeEnvelope } from "./envelope.js";
import {
	type DecryptResult,
	GroupAuthenticityError,
	type VerificationStatus,
	isAuthenticityFailure,
} from "./message.js";

/**
 * One group row as a read opens it: the reader and the group, the ciphertext,
 * and the server-authenticated facts the authenticity check is held to.
 */
export interface GroupRow {
	configDir: string;
	recipientAgentId: string;
	groupId: string;
	/** The row's `encrypted_payload`, decoded from base64url. */
	encrypted: Uint8Array;
	client: HttpClient;
	/** The row's server-authenticated `from_agent_id`. */
	fromAgentId: string;
	/** The row's server `created_at`. */
	createdAt: string | undefined;
}

/**
 * Refuse an inauthentic group message. Unlike the 1:1 path, a group transcript
 * never carries a degraded turn — tampered bytes and a misattributed author both
 * throw a {@link GroupAuthenticityError}.
 */
function assertGroupAuthenticity(status: VerificationStatus): void {
	if (!isAuthenticityFailure(status)) return;
	throw new GroupAuthenticityError(status);
}
/**
 * Turn a signed inner envelope into a decrypt result, refusing anything the
 * row's server-authenticated sender did not sign.
 *
 * The one place a group envelope becomes an answer, whichever regime unwrapped
 * it and whether it came from a live ratchet or from the read cache. That
 * matters for the cache: a replay is verified exactly like a first read, so
 * nothing about the row's attribution is remembered from the read before.
 */
export async function authenticateEnvelope(
	innerEnvelope: Uint8Array,
	client: HttpClient,
	fromAgentId: string,
	groupId: string,
	createdAt: string | undefined,
): Promise<DecryptResult> {
	const decoded = decodeEnvelope(innerEnvelope);
	const plaintext = new TextDecoder("utf-8", { fatal: true }).decode(
		decoded.payload,
	);
	const verification = await verifyEnvelopeSender(
		decoded,
		client,
		fromAgentId,
		{ kind: "GroupSig", groupId },
		createdAt,
	);
	assertGroupAuthenticity(verification.verificationStatus);
	return { plaintext, senderKid: decoded.kid, ...verification };
}
