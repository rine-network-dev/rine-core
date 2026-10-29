/** What one read call returns: the messages of a feed page, plus the problems found outside any one message. */
import type { VerificationStatus } from "../crypto/message.js";
import { type ReadFinding, type ReadGap, findingToJson, gapToJson } from "./gaps.js";
import { type Row, partyToJson, pythonIsoformat } from "./rows.js";

/**
 * One feed row, opened or explained. `text` is set only for a row whose sender signature
 * verified, and `verification` is null then. `gap` is set when the row could not be opened. A
 * row that opened but failed verification has neither, except a key distribution, which
 * carries a typed gap too: its `verification` says why the text is withheld.
 */
export interface ReadMessage {
	readonly row: Row;
	readonly text: string | null;
	readonly verification: VerificationStatus | null;
	readonly equivocation: boolean;
	readonly epoch: number | null;
	readonly gap: ReadGap | null;
	/** Which message this is inside its group, for duplicate detection; never serialised. */
	readonly slot: string | null;
	/** The signed envelope bytes the slot opened to, compared between duplicates. */
	readonly envelope: Uint8Array | null;
}

/** An empty message for a row; fields the caller sets override the defaults. */
export function readMessage(
	row: Row,
	fields: Partial<Omit<ReadMessage, "row">> = {},
): ReadMessage {
	return {
		row,
		text: null,
		verification: null,
		equivocation: false,
		epoch: null,
		gap: null,
		slot: null,
		envelope: null,
		...fields,
	};
}

/** Epoch-level findings explain no single message, but an operator must see them; each names its group. */
export interface ReadPage {
	readonly items: readonly ReadMessage[];
	readonly nextCursor: string | null;
	readonly findings: readonly ReadFinding[];
}

export function messageToJson(message: ReadMessage): Record<string, unknown> {
	const { row } = message;
	return {
		id: row.id,
		created_at: pythonIsoformat(row.createdAtMicros, row.offsetMinutes),
		type: row.type,
		direction: row.direction,
		from: partyToJson(row.sender),
		to: row.recipient === null ? null : partyToJson(row.recipient),
		group:
			row.groupId === null
				? null
				: { id: row.groupId, handle: row.groupHandle },
		conversation_id: row.conversationId,
		encryption_version: row.encryptionVersion,
		epoch: message.epoch,
		text: message.text,
		verification: message.verification,
		equivocation: message.equivocation,
		gap: message.gap === null ? null : gapToJson(message.gap),
	};
}

export function pageToJson(page: ReadPage): Record<string, unknown> {
	return {
		items: page.items.map(messageToJson),
		findings: page.findings.map(findingToJson),
		next_cursor: page.nextCursor,
	};
}
