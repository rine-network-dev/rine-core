/**
 * Closed (MLS) group messages, read by escrow. A message is opened with the epoch secrets an org
 * agent escrowed, never with a member's own state. Nothing the escrow decrypts is trusted until the
 * MLS framing signature's leaf key is shown to be an `mls` key of the agent the server says sent
 * it: an escrow only proves the bytes are a member's, not whose.
 */
import { bytesToHex, equalBytes } from "@noble/curves/utils.js";
import { type InnerEnvelope, decodeEnvelope } from "../crypto/envelope.js";
import { mlsGroupIdBytes } from "../crypto/mls.js";
import { mlsMessageHeader } from "../crypto/mls-header.js";
import type { ReadContext } from "./context.js";
import { isCryptoFailure } from "./guards.js";
import { EscrowBook, type GoodCopy } from "./escrow-book.js";
import {
	type ReadFinding,
	type ReadGap,
	ReadGapReason,
	findingKey,
	keysUnavailable,
	memberRejected,
	noEscrow,
	unreadable,
} from "./gaps.js";
import {
	type Opened,
	resolve,
	siblingFailures,
	unopenedGap,
} from "./mls-attempt.js";
import { type EpochReaderCache, tryCopies } from "./mls-open.js";
import { type MlsKeySet, isMlsKey, mlsKeySet } from "./mls-signer.js";
import { type ReadMessage, readMessage } from "./page.js";
import type { Row } from "./rows.js";

/** Whether the group id a header names is the one the row's group has. */
function namesGroup(headerGroup: Uint8Array, groupId: string): boolean {
	try {
		return equalBytes(headerGroup, mlsGroupIdBytes(groupId));
	} catch (err) {
		if (!isCryptoFailure(err)) throw err;
		return false; // an id that is no UUID names no group
	}
}

/** Opens closed-group rows; holds the escrow books of one read and shares the epoch readers across reads. */
export class MlsReader {
	/** Epoch-level problems found while opening, each reported once. */
	readonly findings: ReadFinding[] = [];
	readonly #ctx: ReadContext;
	readonly #readers: EpochReaderCache;
	readonly #books = new Map<string, EscrowBook>();
	/** `null` records a transient failure, so one outage costs one request per agent. */
	readonly #signers = new Map<string, Promise<MlsKeySet | null>>();
	readonly #reported = new Set<string>();
	readonly #plaintexts = new Set<readonly GoodCopy[]>();

	constructor(ctx: ReadContext, readers: EpochReaderCache) {
		this.#ctx = ctx;
		this.#readers = readers;
	}

	/** Fetch the escrow rows covering every epoch these messages name. */
	async prepare(rows: readonly Row[]): Promise<void> {
		const spans = new Map<string, { min: number; max: number }>();
		for (const row of rows) {
			const header = mlsMessageHeader(row.ciphertext);
			if (row.groupId === null || row.groupId === "" || header === null)
				continue;
			const span = spans.get(row.groupId);
			if (span === undefined)
				spans.set(row.groupId, { min: header.epoch, max: header.epoch });
			else {
				span.min = Math.min(span.min, header.epoch);
				span.max = Math.max(span.max, header.epoch);
			}
		}
		for (const [groupId, { min, max }] of spans)
			this.#books.set(
				groupId,
				await EscrowBook.load(this.#ctx, groupId, min, max),
			);
	}

	async open(row: Row): Promise<ReadMessage> {
		const { groupId } = row;
		const header = mlsMessageHeader(row.ciphertext);
		const book = groupId === null ? undefined : this.#books.get(groupId);
		if (
			groupId === null ||
			header === null ||
			book === undefined ||
			!namesGroup(header.groupId, groupId)
		)
			return readMessage(row, { gap: unreadable() });
		const { epoch } = header;
		const copies = await book.copies(epoch);
		this.#plaintexts.add(copies.good);
		this.#report(groupId, copies.bad);
		if (copies.empty) return readMessage(row, { epoch, gap: noEscrow(epoch) });
		if (copies.good.length === 0)
			return readMessage(row, { epoch, gap: unopenedGap(epoch, copies) });
		const trial = tryCopies(
			this.#readers,
			{
				groupId,
				group: header.groupId,
				epoch,
				message: row.ciphertext.subarray(1),
			},
			copies.good,
		);
		const { attempt, panicked } = trial;
		const gap = resolve(epoch, row, attempt, copies);
		if (gap !== null) {
			// A panic leaves "no copy matched the fork" unknowable; it names nobody.
			const stopped =
				panicked && gap.reason === ReadGapReason.ForkUnmatched
					? unreadable(epoch)
					: gap;
			return readMessage(row, { epoch, gap: stopped });
		}
		const opened = attempt.opened!;
		this.#report(groupId, siblingFailures(epoch, opened.copy.copy.fp, attempt));
		const message = await this.#verified(row, groupId, epoch, opened);
		if (message.gap === null) trial.keep();
		return message;
	}

	/** Zero the escrow plaintexts this read held. The epoch-reader cache keeps copies of its own. */
	release(): void {
		for (const good of this.#plaintexts)
			for (const { plaintext } of good) plaintext.fill(0);
		this.#plaintexts.clear();
	}

	async #verified(
		row: Row,
		groupId: string,
		epoch: number,
		opened: Opened,
	): Promise<ReadMessage> {
		const signers = await this.#signerKeys(row.sender.agentId);
		if (signers === null)
			return readMessage(row, { epoch, gap: keysUnavailable(epoch) });
		if (!isMlsKey(signers, opened.signerPublicKey))
			return readMessage(row, { epoch, gap: memberRejected(epoch) });
		let envelope: InnerEnvelope;
		try {
			envelope = decodeEnvelope(opened.envelope);
		} catch (err) {
			if (!isCryptoFailure(err)) throw err;
			return readMessage(row, { epoch, gap: unreadable() });
		}
		const verdict = await this.#ctx.verify(
			envelope,
			row.sender.agentId,
			{ kind: "GroupSig", groupId },
			row.createdAt,
		);
		return readMessage(row, {
			text: verdict.text,
			verification: verdict.verification,
			epoch,
			slot: JSON.stringify([
				groupId,
				epoch,
				bytesToHex(opened.copy.copy.fp),
				opened.senderIndex,
				opened.generation,
			]),
			envelope: opened.envelope,
		});
	}

	/** The sender's `mls` keys, read once per read; `null` when they could not be fetched just now. */
	#signerKeys(agentId: string): Promise<MlsKeySet | null> {
		const name = agentId.toLowerCase();
		let keys = this.#signers.get(name);
		if (keys === undefined) {
			keys = mlsKeySet(this.#ctx, agentId);
			this.#signers.set(name, keys);
		}
		return keys;
	}

	#report(groupId: string, gaps: readonly ReadGap[]): void {
		for (const gap of gaps) {
			const finding = { groupId, gap };
			const mark = findingKey(finding);
			if (!this.#reported.has(mark)) {
				this.#reported.add(mark);
				this.findings.push(finding);
			}
		}
	}
}
