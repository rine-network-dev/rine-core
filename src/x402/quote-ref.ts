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

import { ACTING_AGENT_HEADER } from "../actor.js";
import type { MessageRead } from "../api-types.js";
import { decryptMessage, isRefusedDecrypt } from "../crypto/message.js";
import type { HttpClient } from "../http.js";
import { parsesAsUuid } from "../resolve-handle.js";
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
	// 🔴 Before the first request, not after it: `ref` is the payer's own plaintext
	// and it is about to be interpolated into a URL path. Every other guard in this
	// function runs on the RESPONSE, so an unchecked ref decides WHICH endpoint the
	// payee's own credentials are spent on — and the server has GETs that mutate
	// (`/agents/{id}/mls/welcomes` consumes what it returns), so a traversal here is
	// not a read, it is a write the payee is tricked into signing for.
	//
	// `parsesAsUuid` and not the strict `UUID_RE`: the server types this path
	// parameter `uuid.UUID` (`GET /messages/{message_id}`), which has always taken
	// the dashless, `urn:uuid:` and braced spellings too. A pre-flight is only ever
	// allowed to refuse what the wire would have refused anyway, so refusing one of
	// those here would be a capability removal wearing a validation fix. What it
	// buys is the alphabet: every spelling it admits is hex digits, dashes, braces
	// and the two prefixes, so none can carry a `/`, a `?` or a `#` — the ref can no
	// longer name an endpoint other than this one.
	// Twin: `parses_as_uuid` in `rine-sdk/src/rine/x402/quote_ref.py`.
	if (!parsesAsUuid(ref)) {
		throw new X402Error(
			X402_ERROR.NO_QUOTE,
			`Referenced quote ${ref} is not a message id — refusing to settle`,
		);
	}
	let quoteMsg: MessageRead;
	try {
		quoteMsg = (await client.get(`/messages/${ref}`, {}, {
			[ACTING_AGENT_HEADER]: payeeAgentId,
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
		// The guard above proved `from_agent_id == payeeAgentId`, so the payee's own
		// id IS this row's server-authenticated sender.
		const decrypted = await decryptMessage(
			configDir,
			payeeAgentId,
			sealed,
			client,
			payeeAgentId,
			quoteMsg.to_agent_id,
			quoteMsg.created_at,
		);
		if (isRefusedDecrypt(decrypted)) {
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
