/**
 * The money paths' sender gate.
 *
 * `rine pay`, `rine fulfill` and their MCP twins all act on a body the
 * counterparty authored — a quote before an authorization is signed against it,
 * a payment before it is settled. The 1:1 decrypt reports an authenticity
 * failure instead of throwing, so this is the ONE place that turns that verdict
 * into a typed refusal for all four; a verdict nobody reads is the same as no
 * verdict at all.
 *
 * What it stops: a third party can re-seal a verbatim signed quote or payment
 * (sealing needs only the recipient's public key) and post it under its own
 * agent id. The server authenticates that sender honestly, so the settlement,
 * the receipt and the goods follow the re-sealer while the signature inside the
 * envelope names someone else.
 */

import {
	type MessageDecryptResult,
	isRefusedDecrypt,
} from "../crypto/message.js";
import { X402Error, X402_ERROR } from "./errors.js";

/**
 * The decrypted body of an x402 message, or a typed `INAUTHENTIC_SENDER`
 * refusal when its envelope was not signed by the message's
 * server-authenticated sender.
 *
 * `senderAgentId` is that sender — the same id the decrypt was bound to — and is
 * named in the error alongside the kid the envelope actually carried, so each
 * surface can report who signed what. A `verified` or `unverifiable` verdict
 * passes: the latter means the check could not run, which is a lookup outcome
 * rather than a verdict on the author.
 */
export function requireAuthenticPlaintext(
	decrypted: MessageDecryptResult,
	senderAgentId: string,
	messageId: string,
): string {
	const status = decrypted.verificationStatus;
	if (status === "sender-mismatch") {
		throw new X402Error(
			X402_ERROR.INAUTHENTIC_SENDER,
			`Message ${messageId} was signed by ${decrypted.senderKid}, not by the agent the server authenticated as its sender (${senderAgentId}) — refusing to act on a re-sealed message`,
			{ verificationStatus: status, senderKid: decrypted.senderKid },
		);
	}
	// An authenticity failure withholds the body, so a missing one is the same
	// refusal and never a reason to fall through to the payload.
	if (isRefusedDecrypt(decrypted)) {
		throw new X402Error(
			X402_ERROR.INAUTHENTIC_SENDER,
			`Message ${messageId} carries no body signed by ${senderAgentId}, the agent the server authenticated as its sender — refusing to act on it`,
			{ verificationStatus: status, senderKid: decrypted.senderKid },
		);
	}
	return decrypted.plaintext;
}
