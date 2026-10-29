/**
 * The money paths' sender gate.
 *
 * `rine pay`, `rine fulfill`, their MCP twins and the SDK payer and payee all
 * act on a body the counterparty authored — a quote before an authorization is
 * signed against it, a payment before it is settled. The 1:1 decrypt reports a
 * verdict instead of throwing, so this is the ONE place that turns it into a
 * typed refusal for every money path; a verdict nobody reads is the same as no
 * verdict at all.
 *
 * What it stops: a third party can re-seal a verbatim signed quote or payment
 * (sealing needs only the recipient's public key) and post it under its own
 * agent id. The server authenticates that sender honestly, so the settlement,
 * the receipt and the goods follow the re-sealer while the signature inside the
 * envelope names someone else. A hostile server can go further and forge a quote
 * under any agent while the sender's key cannot be read — so "payable" means
 * `verified`, and nothing weaker.
 */

import {
	type MessageDecryptResult,
	type VerificationStatus,
	isRefusedDecrypt,
} from "../crypto/message.js";
import { X402Error, X402_ERROR } from "./errors.js";

/** The part of a decrypt outcome the money gate reads, whatever surface produced it. */
export interface SenderVerdict {
	verificationStatus: VerificationStatus;
	senderKid?: string | null;
	/** Set when the row did not open: its status then reports the failure, not a signature check that could not run. */
	decryptError?: string | null;
	/** A cleartext A2A row: nothing was sealed, so no key lookup could ever vouch for its author. */
	a2aCleartext?: boolean;
}

/**
 * Throws a typed refusal unless the envelope was signed by the message's
 * server-authenticated sender (`verified`).
 *
 * `senderAgentId` is that sender — the same id the decrypt was bound to; a row
 * with none can never verify — and is named in the error alongside the kid the envelope actually carried, so each
 * surface can report who signed what. `unverifiable` is refused too, but under
 * its own code: the check could not run, so nothing vouches for the author, yet
 * nothing says the author is wrong either. `SENDER_UNVERIFIABLE` is retryable —
 * the same message passes once the sender's key can be read — while
 * `INAUTHENTIC_SENDER` is final. Only a row that opened, has an authenticated
 * sender and is not cleartext A2A gets the retryable code: a row that failed to
 * decrypt, has no sender, or never carried a signature cannot pass on a retry.
 */
export function requireVerifiedSender(
	verdict: SenderVerdict,
	senderAgentId: string | null | undefined,
	messageId: string,
): void {
	const sender = senderAgentId ?? "no authenticated sender";
	const status = verdict.verificationStatus;
	if (status === "verified") return;
	const details = { verificationStatus: status, senderKid: verdict.senderKid };
	const retryable =
		senderAgentId && !verdict.decryptError && !verdict.a2aCleartext;
	if (status === "unverifiable" && retryable) {
		throw new X402Error(
			X402_ERROR.SENDER_UNVERIFIABLE,
			`Message ${messageId} cannot be verified as signed by ${sender}, the agent the server authenticated as its sender (its signing key could not be checked) — nothing was paid or settled; retry once the key lookup works`,
			details,
		);
	}
	if (status === "sender-mismatch") {
		throw new X402Error(
			X402_ERROR.INAUTHENTIC_SENDER,
			`Message ${messageId} was signed by ${verdict.senderKid}, not by the agent the server authenticated as its sender (${sender}) — refusing to act on a re-sealed message`,
			details,
		);
	}
	const why = verdict.a2aCleartext
		? "it was posted in cleartext and carries no signature"
		: verdict.decryptError
			? "it did not decrypt"
			: "its signature does not check out";
	throw new X402Error(
		X402_ERROR.INAUTHENTIC_SENDER,
		`Message ${messageId} is not verified as signed by ${sender}, the agent the server authenticated as its sender (${why}) — refusing to act on it`,
		details,
	);
}

/**
 * The decrypted body of an x402 message, or a typed refusal
 * (`SENDER_UNVERIFIABLE` or `INAUTHENTIC_SENDER`) unless it is `verified` as
 * signed by `senderAgentId`.
 */
export function requireVerifiedPlaintext(
	decrypted: MessageDecryptResult,
	senderAgentId: string,
	messageId: string,
): string {
	requireVerifiedSender(decrypted, senderAgentId, messageId);
	// A verified decrypt carries a body, but the type cannot say so: fail closed on a bodiless one.
	if (isRefusedDecrypt(decrypted)) {
		throw new X402Error(
			X402_ERROR.INAUTHENTIC_SENDER,
			`Message ${messageId} carries no body signed by ${senderAgentId} — refusing to act on it`,
			{ verificationStatus: decrypted.verificationStatus, senderKid: decrypted.senderKid },
		);
	}
	return decrypted.plaintext;
}
