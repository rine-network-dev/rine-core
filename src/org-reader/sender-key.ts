/**
 * Open (sender-key) group messages. A sender key reaches a member as a 1:1 distribution; the
 * reader rebuilds each ratchet from the distributions an org agent holds, so it reads an open
 * group from the first distribution its org received and not before. Distribution rows carry
 * chain keys and are consumed here, never shown.
 */
import { decodeEnvelope } from "../crypto/envelope.js";
import type { InnerEnvelope } from "../crypto/envelope.js";
import type { VerificationStatus } from "../crypto/message.js";
import { parseSenderKeyWire } from "../crypto/sender-key-wire.js";
import { chainKeyAt, openGroup } from "../crypto/sender-keys.js";
import type { SenderKeyState } from "../crypto/sender-keys.js";
import type { SigContext } from "../crypto/sign.js";
import { distributionState } from "./distribution.js";
import { isCryptoFailure } from "./guards.js";
import { noDistribution, ratchetGap, unreadable } from "./gaps.js";
import { type ReadMessage, readMessage } from "./page.js";
import type { Row } from "./rows.js";

/**
 * The reader derives forward from the nearest state it holds; an honest sender's chain is as
 * long as its message count (rotation caps it), so ten thousand steps costs milliseconds, while
 * an index a malicious server forged beyond it is refused as a RatchetGap and cannot make the
 * reader hash for long.
 */
export const ORG_READ_MAX_CHAIN_STEPS = 10_000;

/** What `SenderKeyReader.open` needs of the read context: the sender check on a decoded envelope. */
export interface SenderVerifier {
	verify(
		decoded: InnerEnvelope,
		sender: string,
		sigCtx: SigContext,
		createdAt: string,
	): Promise<{ text: string | null; verification: VerificationStatus | null }>;
}

/** The state at `index`, derived forward without keeping skipped keys. */
function stepTo(state: SenderKeyState, index: number): SenderKeyState {
	return {
		...state,
		chainKey: chainKeyAt(state, index),
		messageIndex: index,
		skippedKeys: {},
	};
}

/** The (sender key id, message index) a row's wire names, or null when it is malformed. */
function parseWire(wire: Uint8Array): { keyId: string; index: number } | null {
	try {
		return parseSenderKeyWire(wire);
	} catch (err) {
		if (isCryptoFailure(err)) return null;
		throw err;
	}
}

function slotKey(group: string, sender: string, keyId: string): string {
	return JSON.stringify([group, sender.toLowerCase(), keyId]);
}

/** Ratchet states rebuilt from distributions, keyed by (group, sender, sender key id). */
export class SenderKeyReader {
	readonly #verifier: SenderVerifier;
	readonly #states = new Map<string, Map<number, SenderKeyState>>();
	readonly #advanced = new Map<string, SenderKeyState>();
	readonly #wanted = new Map<string, number>();

	constructor(verifier: SenderVerifier) {
		this.#verifier = verifier;
	}

	/** Record, per (group, sender, key id), the lowest message index the page's rows need. */
	want(rows: readonly Row[]): void {
		for (const row of rows) {
			const parsed = parseWire(row.ciphertext);
			if (row.groupId === null || parsed === null) continue;
			const slot = slotKey(row.groupId, row.sender.agentId, parsed.keyId);
			const current = this.#wanted.get(slot);
			if (current === undefined || parsed.index < current)
				this.#wanted.set(slot, parsed.index);
		}
	}

	/** True when every wanted slot holds a state at or below its lowest wanted index. */
	satisfied(): boolean {
		for (const [slot, wanted] of this.#wanted) {
			const held = [...(this.#states.get(slot)?.keys() ?? [])];
			if (!held.some((index) => index <= wanted)) return false;
		}
		return true;
	}

	/** Rebuild states from opened 1:1 messages; only a verified distribution counts. */
	ingest(opened: readonly ReadMessage[]): void {
		for (const message of opened) {
			const state = distributionState(message);
			if (state === null) continue;
			const slot = slotKey(
				state.groupId,
				state.senderAgentId,
				state.senderKeyId,
			);
			const held = this.#states.get(slot) ?? new Map<number, SenderKeyState>();
			if (!held.has(state.messageIndex)) held.set(state.messageIndex, state);
			this.#states.set(slot, held);
		}
	}

	/** Open one sender-key row from the nearest state held at or below its index. */
	async open(row: Row): Promise<ReadMessage> {
		const parsed = parseWire(row.ciphertext);
		if (row.groupId === null || parsed === null)
			return readMessage(row, { gap: unreadable() });
		const { keyId, index } = parsed;
		const group = row.groupId;
		const sender = row.sender.agentId;
		const slot = slotKey(group, sender, keyId);
		const candidates = [...(this.#states.get(slot)?.values() ?? [])].filter(
			(state) => state.messageIndex <= index,
		);
		const advanced = this.#advanced.get(slot);
		if (advanced !== undefined && advanced.messageIndex <= index)
			candidates.push(advanced);
		const base = candidates.sort((a, b) => b.messageIndex - a.messageIndex)[0];
		if (base === undefined)
			return readMessage(row, { gap: noDistribution(sender) });
		if (index - base.messageIndex > ORG_READ_MAX_CHAIN_STEPS) {
			return readMessage(row, { gap: ratchetGap(sender, index) });
		}
		let inner: Uint8Array;
		let envelope: InnerEnvelope;
		let updated: SenderKeyState;
		try {
			const opened = await openGroup(
				new Map([[keyId, stepTo(base, index)]]),
				row.ciphertext,
			);
			inner = opened.innerEnvelope;
			updated = opened.updatedState;
			envelope = decodeEnvelope(inner);
		} catch (err) {
			if (!isCryptoFailure(err)) throw err;
			return readMessage(row, { gap: unreadable() });
		}
		const existing = this.#advanced.get(slot);
		if ((existing?.messageIndex ?? -1) < updated.messageIndex)
			this.#advanced.set(slot, updated);
		const verdict = await this.#verifier.verify(
			envelope,
			sender,
			{ kind: "GroupSig", groupId: group },
			row.createdAt,
		);
		return readMessage(row, {
			text: verdict.text,
			verification: verdict.verification,
			slot: JSON.stringify([group, keyId, index]),
			envelope: inner,
		});
	}
}
