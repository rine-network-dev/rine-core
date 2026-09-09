/**
 * One thread row: pick the ciphertext this caller can open, decrypt it, and say
 * what the row renders as — including, for the one failure that has a remedy,
 * the sentence a render may decide to print.
 *
 * The row half of `thread.ts`, split from it for that module's file-size
 * budget. `thread.ts` owns the RENDER (how many rows, and how often a refusal
 * repeats itself); this owns the ROW. Nothing here is exported from the package
 * — `thread.ts` re-exports the public names.
 */

import type { HttpClient } from "../http.js";
import { decryptGroupMessageWithRecovery } from "../sender-key-ops.js";
import { asSenderKeyUnavailable } from "../sender-key-words.js";
import {
	GroupAuthenticityError,
	type VerificationStatus,
	decryptMessage,
	isRefusedDecrypt,
} from "./message.js";
import { renderThreadText } from "./thread-text.js";

/** Sentinel for a row the caller cannot decrypt — identical across all surfaces. */
export const THREAD_UNAVAILABLE = "[unavailable]";

/** A row of the both-sided thread, as the server returns it (subset we read). */
export interface ThreadRow {
	type: string;
	encrypted_payload: string;
	encryption_version?: string;
	self_encrypted_payload?: string | null;
	direction?: "sent" | "received";
	sender_handle?: string | null;
	/**
	 * The row's server-authenticated sender, which the envelope's own claim of
	 * authorship is checked against. A row listed without it renders as
	 * `unverifiable`: the envelope is never accepted as its own witness.
	 */
	from_agent_id?: string | null;
	group_id?: string | null;
	content_type?: string | null;
	created_at: string;
}

/** One rendered turn — mirrors the SDK `ThreadEntry` shape. */
export interface ThreadRowEntry {
	direction: "sent" | "received";
	sender_handle: string | null;
	text: string;
	verification_status: VerificationStatus;
	type: string;
	created_at: string;
}

/**
 * One rendered turn, plus the refusal this row would explain if it turns out to
 * be the first in its render to carry the no-sender-key cause.
 *
 * The tiering cannot be decided in here: "the first row" is a fact about the
 * ROW ORDER the caller holds, and this function sees one row and no order. So
 * the row reports its cause and the render spends it in order. (The render also
 * decrypts one row at a time — see `decryptThreadRows` — but the split does not
 * rest on that: it would be needed just the same if the rows were concurrent,
 * which is how they used to arrive.)
 */
export interface ClassifiedRow {
	readonly entry: ThreadRowEntry;
	/** The full sentence for a row sealed under a key this agent lacks, else null. */
	readonly explanation: string | null;
}

/** Decrypt one row with the caller's own keys and classify it. Never throws. */
export async function classifyThreadRow(
	configDir: string,
	agentId: string,
	row: ThreadRow,
	client: HttpClient,
): Promise<ClassifiedRow> {
	const direction = row.direction ?? "received";
	const senderHandle = row.sender_handle ?? null;
	const isGroup = row.group_id != null;

	// A `sent` row's sender is the caller. With neither that nor the row's own
	// `from_agent_id` there is nothing to check the envelope's claim against, so the
	// turn is unverifiable rather than quietly trusted.
	const fromAgentId =
		row.from_agent_id ?? (direction === "sent" ? agentId : null);
	if (fromAgentId == null) {
		return sealed(
			entry(direction, senderHandle, THREAD_UNAVAILABLE, "unverifiable", row),
		);
	}

	// A sent 1:1 row with no self-blob is a legacy (pre-self-seal) send the caller
	// can never re-open — degrade rather than feed an empty payload to the decrypt.
	if (direction === "sent" && !isGroup && row.self_encrypted_payload == null) {
		return sealed(
			entry(direction, senderHandle, THREAD_UNAVAILABLE, "unverifiable", row),
		);
	}

	// Pick the ciphertext the caller can open: the self-sealed copy for a sent 1:1
	// row, the recipient/group ciphertext otherwise.
	const ciphertext =
		direction === "sent" && !isGroup
			? (row.self_encrypted_payload as string)
			: row.encrypted_payload;

	try {
		const result = isGroup
			? await decryptGroupMessageWithRecovery(
					client,
					configDir,
					agentId,
					row.group_id as string,
					ciphertext,
					fromAgentId,
				)
			: await decryptMessage(
					configDir,
					agentId,
					ciphertext,
					client,
					fromAgentId,
				);

		// Fail-closed: tampered bytes and a turn signed by someone other than the
		// row's sender are both inauthentic — the decrypt withholds the text and the
		// row degrades exactly like a decrypt failure, keeping the status so the
		// reason survives to the caller.
		if (isRefusedDecrypt(result)) {
			return sealed(
				entry(
					direction,
					senderHandle,
					THREAD_UNAVAILABLE,
					result.verificationStatus,
					row,
				),
			);
		}
		return sealed(
			entry(
				direction,
				senderHandle,
				renderThreadText(result.plaintext, row.content_type),
				result.verificationStatus,
				row,
			),
		);
	} catch (err) {
		// A group decrypt refuses an untrusted author by throwing, so its verdict
		// arrives on the error — keep it, or an active misattribution is reported as
		// the transient key-lookup miss every other failure here is.
		const status =
			err instanceof GroupAuthenticityError
				? err.verificationStatus
				: "unverifiable";
		// The one failure in this catch that has a move to offer, and the one the
		// recovery has already had its turn at: `decryptGroupMessageWithRecovery`
		// throws the translated verdict, so what arrives here is recognised by its
		// CODE and never by its words. `[unavailable]` named neither cause nor move.
		// The status stays `unverifiable`: it is true (no signature was ever
		// checked), it is a closed four-value enum, and the cause now rides in the
		// text where a reader is.
		const unavailable = asSenderKeyUnavailable(err, row.group_id ?? undefined);
		return {
			entry: entry(direction, senderHandle, THREAD_UNAVAILABLE, status, row),
			explanation: unavailable?.message ?? null,
		};
	}
}

/** A row with no no-sender-key refusal to explain — every other cause. */
function sealed(rendered: ThreadRowEntry): ClassifiedRow {
	return { entry: rendered, explanation: null };
}

function entry(
	direction: "sent" | "received",
	sender_handle: string | null,
	text: string,
	verification_status: VerificationStatus,
	row: ThreadRow,
): ThreadRowEntry {
	return {
		direction,
		sender_handle,
		text,
		verification_status,
		type: row.type,
		created_at: row.created_at,
	};
}
