/**
 * 1:1 messages. Each message exists as a copy sealed to the recipient and, from the sender's own
 * org, a copy sealed to the sender. The reader opens whichever copy sits with an agent of its org
 * and, when both do, compares them: a sender that signed two different envelopes for one message
 * is equivocating, and the flag says so.
 */
import { bytesToHex } from "@noble/curves/utils.js";
import type { VerifiedAgentKeys } from "../crypto/key-chain.js";
import { agentLabelBase, hkdfDerive } from "../crypto/derive-read.js";
import { type InnerEnvelope, decodeEnvelope } from "../crypto/envelope.js";
import { openHybrid } from "../crypto/hybrid.js";
import { pqKeyPairFromSeed } from "../crypto/keys.js";
import type { ReadContext } from "./context.js";
import { isCryptoFailure } from "./guards.js";
import {
	type ReadGap,
	ReadGapReason,
	gapOf,
	keysUnavailable,
	unreadable,
} from "./gaps.js";
import { isKeyReadError, isKeysUnavailable } from "./key-errors.js";
import { type ReadMessage, readMessage } from "./page.js";
import type { Party, Row } from "./rows.js";

/** A copy is tried under at most this many key generations, newest first. */
export const MAX_GENERATIONS = 64;

interface Candidate {
	readonly party: Party;
	readonly ciphertext: Uint8Array;
	/** The one generation the copy was sealed under, when the row says; else every generation is tried. */
	readonly onlyGen: number | null;
}

function generations(
	keys: VerifiedAgentKeys,
	onlyGen: number | null,
): number[] {
	if (onlyGen !== null) return [onlyGen];
	const oldest = Math.max(0, keys.keyGen - (MAX_GENERATIONS - 1));
	return Array.from(
		{ length: keys.keyGen - oldest + 1 },
		(_, i) => keys.keyGen - i,
	);
}

/** Open one copy as `agentId`: its plaintext, or the gap that says why not. */
async function openCopy(
	ctx: ReadContext,
	agentId: string,
	ciphertext: Uint8Array,
	onlyGen: number | null,
): Promise<Uint8Array | ReadGap> {
	let keys: VerifiedAgentKeys;
	try {
		keys = await ctx.client.agentKeys(agentId);
	} catch (err) {
		if (!isKeyReadError(err)) throw err;
		return isKeysUnavailable(err) ? keysUnavailable() : unreadable();
	}
	const bRead = ctx.key.branchRead(keys.branch);
	for (const gen of generations(keys, onlyGen)) {
		// Only the private halves open a copy; the derive-time public keys would cost two more keygens.
		const base = agentLabelBase(agentId, gen);
		const x25519Private = hkdfDerive(bRead, `${base}/x25519`, 32);
		const mlKemSeed = hkdfDerive(bRead, `${base}/ml-kem-768`, 64);
		const mlKem = pqKeyPairFromSeed(mlKemSeed);
		try {
			return openHybrid(x25519Private, mlKem.privateKey, ciphertext, {
				kind: "AgentMessage",
				recipientAgentId: agentId,
			});
		} catch (err) {
			// Sealed under another generation, or not to this agent: try the next.
			if (!isCryptoFailure(err)) throw err;
		} finally {
			x25519Private.fill(0);
			mlKemSeed.fill(0);
			mlKem.privateKey.fill(0);
		}
	}
	return unreadable();
}

/** KeysUnavailable, then Unreadable, then the first failure, then OutOfScope. */
function firstFailure(failures: readonly ReadGap[]): ReadGap {
	const ofReason = (reason: ReadGapReason) =>
		failures.find((gap) => gap.reason === reason);
	return (
		ofReason(ReadGapReason.KeysUnavailable) ??
		ofReason(ReadGapReason.Unreadable) ??
		failures[0] ??
		gapOf(ReadGapReason.OutOfScope)
	);
}

function candidatesOf(
	ctx: ReadContext,
	row: Row,
	recipient: Party,
): Candidate[] {
	const found: Candidate[] = [];
	if (ctx.isOwn(recipient))
		found.push({ party: recipient, ciphertext: row.ciphertext, onlyGen: null });
	if (ctx.isOwn(row.sender) && row.selfCiphertext !== null)
		found.push({
			party: row.sender,
			ciphertext: row.selfCiphertext,
			onlyGen: row.keyGen,
		});
	return found;
}

/**
 * Open one 1:1 row from the copies that sit with agents of the reader's org. A copy that fails
 * on its own never hides a copy the key can open.
 */
export async function openDirect(
	ctx: ReadContext,
	row: Row,
): Promise<ReadMessage> {
	const { recipient } = row;
	if (recipient === null) return readMessage(row, { gap: unreadable() });
	const copies: Uint8Array[] = [];
	const failures: ReadGap[] = [];
	for (const { party, ciphertext, onlyGen } of candidatesOf(
		ctx,
		row,
		recipient,
	)) {
		const opened = await openCopy(ctx, party.agentId, ciphertext, onlyGen);
		if (opened instanceof Uint8Array) copies.push(opened);
		else failures.push(opened);
	}
	const [first] = copies;
	if (first === undefined)
		return readMessage(row, { gap: firstFailure(failures) });
	let envelope: InnerEnvelope;
	try {
		envelope = decodeEnvelope(first);
	} catch (err) {
		if (!isCryptoFailure(err)) throw err;
		return readMessage(row, { gap: unreadable() });
	}
	const verdict = await ctx.verify(
		envelope,
		row.sender.agentId,
		{ kind: "MessageSig", recipientAgentId: recipient.agentId },
		row.createdAt,
	);
	return readMessage(row, {
		text: verdict.text,
		verification: verdict.verification,
		equivocation: new Set(copies.map(bytesToHex)).size > 1,
	});
}
