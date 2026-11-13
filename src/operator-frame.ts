/**
 * The one place a model-facing row learns its sender class and its notice.
 *
 * Every row a surface hands a model goes through {@link frameRow}, on every arm
 * including a refused or unreadable one. The class and the notice are written
 * last, so a value the server or the sender put under the same key is
 * overwritten, and the sender's own `rine.operator` field is removed from the
 * decrypted body so a stranger's copy never reaches a model.
 */

import {
	OPERATOR_CONTENT_NOTICE,
	OPERATOR_HISTORY_NOTICE,
	UNTRUSTED_CONTENT_NOTICE,
	isGroupInvite,
	isHiddenFromModel,
} from "./control-frames.js";
import {
	type OperatorContext,
	type OperatorRowInput,
	type OperatorVerdict,
	type SenderClass,
	classifyOperatorRow,
} from "./operator-classify.js";
import { stripOperatorStatement } from "./operator-statement.js";

/** The notice that frames a row of this class. */
export function noticeForClass(senderClass: SenderClass): string {
	switch (senderClass) {
		case "operator":
			return OPERATOR_CONTENT_NOTICE;
		case "operator_history":
			return OPERATOR_HISTORY_NOTICE;
		case "other":
			return UNTRUSTED_CONTENT_NOTICE;
	}
}

/** A row with its class and its notice. */
export type FramedRow<R> = Omit<R, "sender_class" | "notice" | "decrypted"> & {
	decrypted?: unknown;
	sender_class: SenderClass;
	notice: string;
};

/**
 * A copy of `row` carrying `sender_class` and `notice` for `verdict`, with the
 * statement field stripped from `decrypted`. The caller's row is not changed.
 */
export function frameRow<R extends object>(
	row: R,
	verdict: OperatorVerdict,
): FramedRow<R> {
	const framed: Record<string, unknown> = {
		...(row as Record<string, unknown>),
	};
	if ("decrypted" in framed)
		framed.decrypted = stripOperatorStatement(framed.decrypted);
	framed.sender_class = verdict.senderClass;
	framed.notice = noticeForClass(verdict.senderClass);
	return framed as FramedRow<R>;
}

/**
 * {@link classifyOperatorRow} for a row of message type `type` that is about to be shown
 * to a model. A key-material frame and a group invite never show the sender's words, so
 * they are data and use up no statement, on every surface alike.
 */
export function classifyShown(
	ctx: OperatorContext,
	type: string,
	row: OperatorRowInput,
): Promise<OperatorVerdict> {
	if (isHiddenFromModel(type) || isGroupInvite(type))
		return Promise.resolve({ senderClass: "other", reason: "control_frame" });
	return classifyOperatorRow(ctx, row);
}
