/**
 * Shared both-sided thread-row decrypt + render, used by the CLI (`rine thread`)
 * and the MCP `rine_thread` tool. Both call into `@rine-network/core` directly
 * (NOT the ts-sdk), so this is the ONE place that encapsulates the
 * "pick self vs recipient vs group ciphertext → decrypt → render `{text}` or
 * `[unavailable]`, fail-closed on a bad signature" logic. It mirrors the ts-sdk
 * `resources/thread.ts:renderRow` contract byte-for-byte so every surface renders
 * the same transcript.
 *
 * For each row returned by `GET /conversations/{id}/messages` we pick
 * the ciphertext the caller can actually open with its OWN keys:
 *
 *   - `direction === "sent"`     → `self_encrypted_payload` (sealed to self)
 *   - `direction === "received"` → `encrypted_payload` (sealed to the caller)
 *   - group rows (`group_id` set) → the normal group decrypt (self-read via cache)
 *
 * An undecryptable row never throws: a sent 1:1 row with no self-blob (legacy,
 * pre-self-seal), any decrypt failure, or an INVALID sender signature degrades to
 * `text: "[unavailable]"`. Fail-closed on authenticity matches the SDKs (a forged
 * or tampered turn never enters the transcript as trusted content).
 */

import type { HttpClient } from "../http.js";
import { decryptGroupMessageWithRecovery } from "../sender-key-ops.js";
import { type VerificationStatus, decryptMessage } from "./message.js";

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
 * Decrypt one thread row with the caller's own keys and render it to a
 * role-tagged entry. Never throws.
 */
export async function decryptThreadRow(
	configDir: string,
	agentId: string,
	row: ThreadRow,
	client: HttpClient,
): Promise<ThreadRowEntry> {
	const direction = row.direction ?? "received";
	const senderHandle = row.sender_handle ?? null;
	const isGroup = row.group_id != null;

	// A sent 1:1 row with no self-blob is a legacy (pre-self-seal) send the caller
	// can never re-open — degrade rather than feed an empty payload to the decrypt.
	if (direction === "sent" && !isGroup && row.self_encrypted_payload == null) {
		return entry(direction, senderHandle, THREAD_UNAVAILABLE, "unverifiable", row);
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
				)
			: await decryptMessage(configDir, agentId, ciphertext, client);

		// Fail-closed: an invalid sender signature is an authenticity failure, not
		// trusted content — degrade exactly like a decrypt failure.
		if (result.verificationStatus === "invalid") {
			return entry(direction, senderHandle, THREAD_UNAVAILABLE, "invalid", row);
		}
		return entry(
			direction,
			senderHandle,
			renderThreadText(result.plaintext, row.content_type),
			result.verificationStatus,
			row,
		);
	} catch {
		// decryptMessage/decryptGroupMessage throw on a crypto/key failure — the
		// row is simply unavailable to this caller.
		return entry(direction, senderHandle, THREAD_UNAVAILABLE, "unverifiable", row);
	}
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

/**
 * Render a decrypted plaintext string to the human-readable body, mirroring the
 * ts-sdk `decryptEnvelope`→`autoParsePlaintext` + `renderText` chain byte-for-byte
 * so every surface renders the same transcript.
 *
 * Parsing is content-type-gated, exactly like the SDK: only an
 * `application/json` body (the default when `content_type` is null/undefined) is
 * `JSON.parse`d; any other content type (e.g. `text/plain`) is surfaced verbatim,
 * even if it happens to look like JSON. Connectors wrap the body as
 * `{ "text": "…" }`; that string is surfaced directly. Any other JSON shape is
 * re-`JSON.stringify`d (normalizing whitespace) to match the SDK's `renderText`.
 */
export function renderThreadText(
	plaintext: string,
	contentType?: string | null,
): string {
	const ct = contentType ?? "application/json";
	if (ct !== "application/json") return plaintext;
	let parsed: unknown;
	try {
		parsed = JSON.parse(plaintext);
	} catch {
		// Bytes claimed JSON but didn't parse — surface the raw string, like the SDK.
		return plaintext;
	}
	if (typeof parsed === "string") return parsed;
	if (
		parsed != null &&
		typeof parsed === "object" &&
		typeof (parsed as { text?: unknown }).text === "string"
	) {
		return (parsed as { text: string }).text;
	}
	return JSON.stringify(parsed);
}
