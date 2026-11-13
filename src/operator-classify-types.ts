// The shapes the operator classifier takes and returns.
import type { MessageDecryptResult } from "./crypto/message.js";
import type { OperatorPin } from "./operator-pin.js";

/** How a message reaches a model: as the operator's word, as the operator's past word, or as data. */
export type SenderClass = "operator" | "operator_history" | "other";

/** Why a row got its class: the condition that failed, or how it passed. */
export type ClassReason =
	| "new"
	| "redelivered"
	| "expired"
	| "already_rendered"
	| "no_pin"
	| "not_direct"
	| "not_verified"
	| "wrong_sender"
	| "wrong_key"
	| "no_statement"
	| "wrong_purpose"
	| "wrong_recipient"
	| "context_only"
	| "future"
	| "replay"
	| "substituted"
	| "ledger_unavailable"
	| "control_frame";

export interface OperatorVerdict {
	readonly senderClass: SenderClass;
	readonly reason: ClassReason;
}

/** What the classifier needs about this agent, fixed for a surface's lifetime. */
export interface OperatorContext {
	/** The pinned seat, or `null` when none is configured, disabled or unreadable. */
	readonly pin: OperatorPin | null;
	/** This agent's own id: the statement must be addressed to it. */
	readonly selfAgentId: string;
	/** Where the ledger lives. */
	readonly configDir: string;
	/** The reader's clock in epoch milliseconds. */
	readonly now: () => number;
	/** Where a replay or a ledger failure is reported. */
	readonly warn: (message: string) => void;
}

/** One received row, as opened. */
export interface OperatorRowInput {
	readonly rowId: string;
	readonly fromAgentId: string;
	readonly encryptionVersion: string;
	readonly encryptedPayload: string;
	/** The decrypt outcome, or `null` for a row that could not be opened at all. */
	readonly result: MessageDecryptResult | null;
	/**
	 * The row's `context_only` as the server sent it: `null` or absent when the row is not held,
	 * any string when it is. Any set value demotes the row to context, including values a newer
	 * server adds.
	 */
	readonly contextOnly?: string | null;
	/** True when this call hands the text to a model, which is what uses up a statement. */
	readonly rendersText: boolean;
}

/** The verdict for a row that was never opened, or whose open was refused. */
export const UNOPENED_VERDICT: OperatorVerdict = {
	senderClass: "other",
	reason: "not_verified",
};
