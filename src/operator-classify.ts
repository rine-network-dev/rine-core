/**
 * The six-condition classifier that decides whether a message is from the
 * agent's operator. Plugin code runs it, never the model, and the same function
 * serves the wake path and the read path so the two cannot disagree.
 *
 * A message is operator class only when all six hold:
 *  1. it verified, and it is a 1:1 message;
 *  2. `from_agent_id` is the pinned seat's id (never a handle);
 *  3. the key that verified the signature is the pinned key, compared in full;
 *  4. the SIGNED purpose is `operator.command` and the signed agent is this one
 *     (the row's `type` is unsigned and is never read);
 *  5. `issued_at` is inside the window and not more than five minutes ahead, and the server
 *     did not mark the row `context_only` (any value: the sender is held, or the row was
 *     sent before the recipient's last resume, so it is the operator's past word whatever
 *     its `issued_at`);
 *  6. the ledger has not seen the nonce on a different row or ciphertext.
 *
 * Every input is required. A pin that is absent is an explicit `null`, so a
 * missing value can never compare equal to a missing value.
 */

import { bytesToHex } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { sameAgentId } from "./crypto/agent-keys.js";
import { ENCRYPTION_VERSION_HYBRID_V2 } from "./crypto/hybrid.js";
import { isRefusedDecrypt } from "./crypto/message.js";
import type {
	ClassReason,
	OperatorContext,
	OperatorRowInput,
	OperatorVerdict,
	SenderClass,
} from "./operator-classify-types.js";
import { type LedgerEntry, updateLedger } from "./operator-ledger.js";
import {
	pinMatchesKey,
	pinMatchesSender,
} from "./operator-pin.js";
import {
	OPERATOR_COMMAND_PURPOSE,
	OPERATOR_FUTURE_SKEW_MS,
	OPERATOR_WINDOW_MS,
	parseOperatorStatement,
} from "./operator-statement.js";

export type {
	ClassReason,
	OperatorContext,
	OperatorRowInput,
	OperatorVerdict,
	SenderClass,
} from "./operator-classify-types.js";
export { UNOPENED_VERDICT } from "./operator-classify-types.js";

function verdict(
	senderClass: SenderClass,
	reason: ClassReason,
): OperatorVerdict {
	return { senderClass, reason };
}

function digestOf(encryptedPayload: string): string {
	return bytesToHex(sha256(new TextEncoder().encode(encryptedPayload)));
}

function isContextOnly(value: string | null | undefined): boolean {
	return typeof value === "string" && value.length > 0;
}

/** Condition 6: the ledger's say, recorded in the same locked step. */
function decideByLedger(
	entries: Map<string, LedgerEntry>,
	ctx: OperatorContext,
	row: OperatorRowInput,
	nonce: string,
	issuedAtMs: number,
): OperatorVerdict {
	const digest = digestOf(row.encryptedPayload);
	const seen = entries.get(nonce);
	if (seen === undefined) {
		entries.set(nonce, {
			rowId: row.rowId,
			digest,
			rendered: row.rendersText,
			issuedAtMs,
		});
		return verdict("operator", "new");
	}
	if (seen.rowId !== row.rowId) {
		ctx.warn(
			`operator statement nonce seen on row ${seen.rowId} arrived again on row ${row.rowId}: a replay`,
		);
		return verdict("other", "replay");
	}
	if (seen.digest !== digest) {
		ctx.warn(
			`row ${row.rowId} carries a different ciphertext than the one classified earlier`,
		);
		return verdict("other", "substituted");
	}
	if (seen.rendered) return verdict("operator_history", "already_rendered");
	if (row.rendersText) entries.set(nonce, { ...seen, rendered: true });
	return verdict("operator", "redelivered");
}

/** Classify one received row. Never rejects: a ledger that cannot be consulted is `other`. */
export async function classifyOperatorRow(
	ctx: OperatorContext,
	row: OperatorRowInput,
): Promise<OperatorVerdict> {
	const { pin } = ctx;
	const { result } = row;
	if (pin === null) return verdict("other", "no_pin");
	if (row.encryptionVersion !== ENCRYPTION_VERSION_HYBRID_V2)
		return verdict("other", "not_direct");
	if (
		result === null ||
		isRefusedDecrypt(result) ||
		!result.verified ||
		result.verificationStatus !== "verified"
	) {
		return verdict("other", "not_verified");
	}
	if (!pinMatchesSender(pin, row.fromAgentId))
		return verdict("other", "wrong_sender");
	if (!pinMatchesKey(pin, result.verifyingKey))
		return verdict("other", "wrong_key");
	const statement = parseOperatorStatement(result.plaintext);
	if (statement === null) return verdict("other", "no_statement");
	if (statement.purpose !== OPERATOR_COMMAND_PURPOSE)
		return verdict("other", "wrong_purpose");
	if (!sameAgentId(statement.agent, ctx.selfAgentId))
		return verdict("other", "wrong_recipient");
	const now = ctx.now();
	if (statement.issuedAtMs > now + OPERATOR_FUTURE_SKEW_MS)
		return verdict("other", "future");
	const contextOnly = isContextOnly(row.contextOnly);
	if (!contextOnly && now - statement.issuedAtMs > OPERATOR_WINDOW_MS)
		return verdict("operator_history", "expired");
	try {
		// A context row still goes through the ledger, so its nonce is spent: the same statement
		// replayed in a later row, sent after the resume, is refused as a replay.
		return await updateLedger(
			{ configDir: ctx.configDir, agentId: ctx.selfAgentId },
			now,
			(entries) => {
				const decided = decideByLedger(
					entries,
					ctx,
					row,
					statement.nonce,
					statement.issuedAtMs,
				);
				return contextOnly && decided.senderClass === "operator"
					? verdict("operator_history", "context_only")
					: decided;
			},
		);
	} catch (err) {
		ctx.warn(
			`operator ledger unavailable, treating the row as data: ${err instanceof Error ? err.message : String(err)}`,
		);
		return verdict("other", "ledger_unavailable");
	}
}
