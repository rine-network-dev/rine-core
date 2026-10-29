/**
 * The best-effort ACK and NACK a sync sends for each commit it handles
 * ({@link ./mls-ops-sync.js}). Neither may ever fail the sync.
 */
import { mlsAck, mlsNack } from "./crypto/mls-api.js";
import type { HttpClient } from "./http.js";

/** Fire-and-forget ACK; a failed ACK must never fail the sync. */
export async function emitAck(
	client: HttpClient,
	groupId: string,
	handshake: { id: string },
	extraHeaders?: Record<string, string>,
): Promise<void> {
	try {
		await mlsAck(client, groupId, { object_id: handshake.id }, extraHeaders);
	} catch {
		// best-effort: the commit still confirms once any peer ACKs
	}
}

/** Fire-and-forget NACK; a failed NACK must never fail the sync. */
export async function emitNack(
	client: HttpClient,
	groupId: string,
	handshake: { id: string; epoch: number | null },
	err: unknown,
	extraHeaders?: Record<string, string>,
): Promise<void> {
	const reason = err instanceof Error ? err.message : String(err);
	try {
		await mlsNack(
			client,
			groupId,
			{
				object_id: handshake.id,
				epoch: handshake.epoch ?? 0,
				reason: reason.slice(0, 256),
			},
			extraHeaders,
		);
	} catch {
		// best-effort: a timeout-based rollback still self-heals the group
	}
}
