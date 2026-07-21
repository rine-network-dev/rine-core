/**
 * Quote-ref resolution — load the ONE quote a payment answers.
 *
 * The payer stamps the answered quote's message id into the SIGNED payload
 * `extensions[X402_QUOTE_REF_KEY]`. Here the payee turns that id back into the
 * payee-authored `accepts[]` it must reconcile against, proving the referenced
 * message is genuinely a quote THIS payee issued in THIS conversation before
 * trusting a byte of it. This is I/O-shaped (fetch + self-decrypt) and shared by
 * every payee surface, keeping `reconcile.ts` pure.
 */

import type { MessageRead } from "../api-types.js";
import { decryptMessage } from "../crypto/message.js";
import type { HttpClient } from "../http.js";
import { X402Error, X402_ERROR } from "./errors.js";
import { X402_MESSAGE_TYPE } from "./message-types.js";
import { parseX402Payload } from "./parse.js";
import {
	type PaymentPayload,
	type PaymentRequired,
	type PaymentRequirements,
	X402_QUOTE_REF_KEY,
} from "./types.js";

/** The referenced quote's message id and its payee-authored `accepts[]`. */
export interface ReferencedQuote {
	messageId: string;
	accepts: PaymentRequirements[];
}

/**
 * Resolve the payment's `extensions[X402_QUOTE_REF_KEY]` to the payee's own quote.
 * Fetches that message by id, proves it is (a) an `x402_payment_required`, (b)
 * issued by THIS payee (`from_agent_id == payee` — the real binding), (c) in the
 * SAME conversation, decrypts it via the payee self-seal, and returns its
 * `accepts[]`. Any missing / unresolvable / not-payee-issued / cross-conversation
 * / unopenable ref is a typed `NO_QUOTE` (fail closed) — a payer can neither forge
 * nor omit its way past the binding.
 */
export async function loadReferencedQuote(params: {
	payment: PaymentPayload;
	client: HttpClient;
	configDir: string;
	payeeAgentId: string;
	conversationId: string;
}): Promise<ReferencedQuote> {
	const { payment, client, configDir, payeeAgentId, conversationId } = params;
	const ref = payment.extensions?.[X402_QUOTE_REF_KEY];
	if (typeof ref !== "string" || ref === "") {
		throw new X402Error(
			X402_ERROR.NO_QUOTE,
			`Payment carries no ${X402_QUOTE_REF_KEY} — cannot bind it to a payee-issued quote (fail closed; use explicit expected terms for an out-of-band quote)`,
		);
	}
	let quoteMsg: MessageRead;
	try {
		quoteMsg = (await client.get(`/messages/${ref}`, {}, {
			"X-Rine-Agent": payeeAgentId,
		})) as MessageRead;
	} catch (err) {
		throw new X402Error(
			X402_ERROR.NO_QUOTE,
			`Referenced quote ${ref} is unresolvable: ${err instanceof Error ? err.message : String(err)}`,
		);
	}
	if (
		quoteMsg.type !== X402_MESSAGE_TYPE.PAYMENT_REQUIRED ||
		quoteMsg.from_agent_id !== payeeAgentId ||
		quoteMsg.conversation_id !== conversationId
	) {
		throw new X402Error(
			X402_ERROR.NO_QUOTE,
			`Referenced message ${ref} is not a payee-issued quote in this conversation (type/from/conversation mismatch) — refusing to settle`,
			{ type: quoteMsg.type, fromAgentId: quoteMsg.from_agent_id ?? null },
		);
	}
	const sealed = quoteMsg.self_encrypted_payload;
	if (!sealed) {
		throw new X402Error(
			X402_ERROR.NO_QUOTE,
			`Referenced quote ${ref} has no self-sealed copy the payee can reopen (legacy pre-self-seal) — refusing to settle`,
		);
	}
	let plaintext: string;
	try {
		const decrypted = await decryptMessage(configDir, payeeAgentId, sealed, client);
		if (decrypted.verificationStatus === "invalid") {
			throw new X402Error(
				X402_ERROR.NO_QUOTE,
				`Referenced quote ${ref} failed sender-signature verification — refusing to settle`,
			);
		}
		plaintext = decrypted.plaintext;
	} catch (err) {
		if (err instanceof X402Error) throw err;
		throw new X402Error(
			X402_ERROR.NO_QUOTE,
			`Referenced quote ${ref} could not be decrypted by the payee — refusing to settle`,
		);
	}
	const quote = parseX402Payload(quoteMsg.type, plaintext) as PaymentRequired;
	return { messageId: ref, accepts: quote.accepts };
}
