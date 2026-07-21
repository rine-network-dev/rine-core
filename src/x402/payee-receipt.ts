/**
 * Shared payee receipt-plane helpers — the ONE place a payee turns a
 * settlement outcome into an in-thread `rine.v1.x402_receipt` reply, and the ONE
 * snake_case projection of the reconciled quote for a surface's wire result.
 *
 * CLI (`rine fulfill`) and MCP (`rine_fulfill`) previously each hand-rolled a
 * byte-identical `sendReceipt` and `matched_quote` object literal; both now import
 * these. The helpers depend only on rine-core's own `HttpClient` (never a package-
 * specific client), so hosting them here drags no surface coupling into core.
 */

import type { MessageRead } from "../api-types.js";
import { fetchRecipientKeys } from "../crypto/agent-keys.js";
import { encryptMessage } from "../crypto/message.js";
import type { HttpClient } from "../http.js";
import { buildReceiptMessage } from "./messages.js";
import type { MatchedQuote } from "./payee-settle.js";
import type { SettlementResponse } from "./types.js";

/** The snake_case wire shape of a reconciled quote surfaced on a fulfill result. */
export interface MatchedQuoteWire {
	message_id: string | null;
	amount: string;
	asset: string;
	network: string;
}

/**
 * Project a {@link MatchedQuote} into its snake_case wire shape (CLI JSON / MCP
 * tool return). `message_id` is `null` for an operator `--expect` override.
 */
export function matchedQuoteToWire(match: MatchedQuote): MatchedQuoteWire {
	return {
		message_id: match.quoteMessageId,
		amount: match.amount,
		asset: match.asset,
		network: match.network,
	};
}

/**
 * Build the `x402_receipt` message from a settlement body, HPKE-encrypt it to the
 * PAYER (the payment's original sender), and reply in-thread as the payee. The
 * payee holds no payer wallet — only its own E2EE keys to encrypt the receipt. The
 * settlement's `network` is the facilitator's verbatim slug, echoed through
 * unchanged. `emitMarker` toggles the cleartext `{status, rail}` marker.
 */
export async function sendReceipt(params: {
	client: HttpClient;
	configDir: string;
	payeeAgentId: string;
	payerAgentId: string;
	messageId: string;
	receiptBody: SettlementResponse;
	emitMarker: boolean;
}): Promise<MessageRead> {
	const built = buildReceiptMessage(params.receiptBody, {
		emitMarker: params.emitMarker,
	});
	const recipientKeys = await fetchRecipientKeys(
		params.client,
		params.payerAgentId,
	);
	const encrypted = await encryptMessage(
		params.configDir,
		params.payeeAgentId,
		recipientKeys.encryption,
		built.payload,
		recipientKeys.pqEncryption,
	);
	const body: Record<string, unknown> = {
		type: built.type,
		content_type: built.content_type,
		payload_schema: built.payload_schema,
		...encrypted,
	};
	if (built.metadata) body.metadata = built.metadata;
	return (await params.client.post(
		`/messages/${params.messageId}/reply`,
		body,
		{ "X-Rine-Agent": params.payeeAgentId },
	)) as MessageRead;
}
