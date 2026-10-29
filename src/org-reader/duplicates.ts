/** Repeated rows of one message slot. */
import { equalBytes } from "@noble/curves/utils.js";
import { ReadGapReason, gapOf } from "./gaps.js";
import { type ReadMessage, readMessage } from "./page.js";
import type { Row } from "./rows.js";

/** Oldest stored first; the id breaks a tie at the same microsecond. */
export function storedOrder(a: Row, b: Row): number {
	if (a.createdAtMicros !== b.createdAtMicros)
		return a.createdAtMicros - b.createdAtMicros;
	return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

function sameEnvelope(a: Uint8Array | null, b: Uint8Array | null): boolean {
	return a === null || b === null ? a === null && b === null : equalBytes(a, b);
}

/**
 * Keep the first stored row of each slot; later rows of it are `Duplicate`. A repeat whose
 * signed envelope differs from the first row's is equivocation, flagged on both rows: one slot
 * was given two different contents. Returns the messages in their input order.
 */
export function markDuplicates(
	messages: readonly ReadMessage[],
): ReadMessage[] {
	const out = [...messages];
	const order = out
		.map((_, position) => position)
		.sort((a, b) => storedOrder(out[a]!.row, out[b]!.row));
	const first = new Map<string, number>();
	for (const position of order) {
		const message = out[position]!;
		if (message.slot === null) continue;
		const keptAt = first.get(message.slot);
		if (keptAt === undefined) {
			first.set(message.slot, position);
			continue;
		}
		const kept = out[keptAt]!;
		const differs = !sameEnvelope(kept.envelope, message.envelope);
		if (differs) out[keptAt] = { ...kept, equivocation: true };
		out[position] = readMessage(message.row, {
			epoch: message.epoch,
			gap: gapOf(ReadGapReason.Duplicate),
			equivocation: differs,
		});
	}
	return out;
}
