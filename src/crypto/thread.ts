/**
 * Shared both-sided thread-row decrypt + render, used by the CLI (`rine thread`)
 * and the MCP `rine_thread` tool. Both call into `@rine-network/core` directly
 * (NOT the ts-sdk), so this is the ONE place that encapsulates the
 * "pick self vs recipient vs group ciphertext → decrypt → render `{text}` or
 * `[unavailable]`, fail-closed on a bad signature" logic. Every turn renders as
 * the ts-sdk `resources/thread.ts:renderRow` renders it — same text, same
 * verification status, including which authenticity failure closed the row — so
 * one transcript reads identically on every surface.
 *
 * For each row returned by `GET /conversations/{id}/messages` we pick
 * the ciphertext the caller can actually open with its OWN keys:
 *
 *   - `direction === "sent"`     → `self_encrypted_payload` (sealed to self)
 *   - `direction === "received"` → `encrypted_payload` (sealed to the caller)
 *   - group rows (`group_id` set) → the normal group decrypt (self-read via cache)
 *
 * An undecryptable row never throws: a sent 1:1 row with no self-blob (legacy,
 * pre-self-seal), any decrypt failure, a row with no server-authenticated sender
 * to check the envelope against, or a failed authenticity check degrades to
 * `text: "[unavailable]"`. Fail-closed on authenticity matches the SDKs (a turn
 * that was tampered with, or signed by someone other than the sender the server
 * authenticated, never enters the transcript as trusted content).
 *
 * The one exception is the row sealed under a sender key this agent does not
 * hold, which is the only failure here with something for the reader to do
 * about it: it says so instead, once per render (`sender-key-explain.ts`).
 */

import type { HttpClient } from "../http.js";
import {
	type SenderKeyExplainer,
	senderKeyExplainer,
} from "../sender-key-explain.js";
import {
	type ClassifiedRow,
	type ThreadRow,
	type ThreadRowEntry,
	classifyThreadRow,
} from "./thread-row.js";

// The row module is not on the package's export map; this is its public face.
export { THREAD_UNAVAILABLE } from "./thread-row.js";
export type { ThreadRow, ThreadRowEntry } from "./thread-row.js";
export { renderThreadText } from "./thread-text.js";

/**
 * Decrypt one thread row with the caller's own keys and render it to a
 * role-tagged entry. Never throws.
 *
 * A caller that asked for ONE row, so the no-sender-key refusal renders in
 * full: there is no second row for it to repeat itself on. A render of N rows
 * calls {@link decryptThreadRows} instead, which explains once and marks the
 * rest.
 */
export async function decryptThreadRow(
	configDir: string,
	agentId: string,
	row: ThreadRow,
	client: HttpClient,
): Promise<ThreadRowEntry> {
	return tiered(
		await classifyThreadRow(configDir, agentId, row, client),
		senderKeyExplainer(),
	);
}

/**
 * Decrypt a whole render of thread rows — the plural call IS the render
 * boundary.
 *
 * Every surface that shows a transcript maps over rows, so "have I explained
 * this yet" would have been hand-rolled once per surface, in packages that
 * cannot see each other. Handing them the plural instead keeps that state
 * created, spent and dropped inside one call: a caller cannot hold it wrong
 * because there is nothing to hold. Rows stay concurrent; only the tiering is
 * ordered, so the paragraph lands on the first row that carries the cause and
 * not on whichever decrypt happened to finish first.
 */
export async function decryptThreadRows(
	configDir: string,
	agentId: string,
	rows: readonly ThreadRow[],
	client: HttpClient,
): Promise<ThreadRowEntry[]> {
	const classified = await Promise.all(
		rows.map((row) => classifyThreadRow(configDir, agentId, row, client)),
	);
	const explain = senderKeyExplainer();
	return classified.map((row) => tiered(row, explain));
}

function tiered(
	row: ClassifiedRow,
	explain: SenderKeyExplainer,
): ThreadRowEntry {
	if (row.explanation === null) return row.entry;
	return { ...row.entry, text: explain(row.explanation).line };
}
