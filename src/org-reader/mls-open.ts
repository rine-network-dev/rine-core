/**
 * Opening one closed-group message with an escrowed epoch's secrets: the cache of epoch readers,
 * the trial of every good copy, and the routing of the native core's error codes.
 */
import { bytesToHex } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { EpochReader, type OpenedMessage } from "@rine-network/mls";
import { MLS_ERR_PANIC, mlsErrorCode } from "../crypto/mls-errors.js";
import type { GoodCopy } from "./escrow-book.js";
import { escrowInvalid } from "./gaps.js";
import { Attempt, type Opened } from "./mls-attempt.js";

/** Epoch readers kept across reads, least recently used out first. */
export const EPOCH_READER_CACHE_SIZE = 512;

/** The codes the epoch reader raises for an input it refuses; any other code is a copy that does not fit. */
const EpochReaderCode = {
	MemberRejected: "RINE_MLS_MEMBER_REJECTED",
	GenerationTooFar: "RINE_MLS_GENERATION_TOO_FAR",
	InvalidEscrow: "RINE_MLS_INVALID_ESCROW",
} as const;

/** The message to open and the epoch it names. */
export interface MlsTarget {
	readonly groupId: string;
	/** The group's raw id, as the message header names it. */
	readonly group: Uint8Array;
	readonly epoch: number;
	/** The MLS PrivateMessage bytes, without the leading version tag. */
	readonly message: Uint8Array;
}

/** How trying every good copy ended; `panicked` is a copy the native core aborted on, which accuses nobody. */
export interface Trial {
	readonly attempt: Attempt;
	readonly panicked: boolean;
	/** Put the readers that opened into the cache; the caller does so once the epoch ended without a gap. */
	keep(): void;
}

interface Held {
	readonly reader: EpochReader;
	/** The escrow plaintext the reader was built from: a rebuild needs it on a later read too. */
	readonly plaintext: Uint8Array;
}

/**
 * Epoch readers that opened a message, keyed by the copy they were built from. A reader advances a
 * sender's ratchet as it opens, so a later read of an earlier message rebuilds it from the plaintext
 * kept here. An epoch no copy opened is never put in, so a later escrow upload is seen on the next read.
 */
export class EpochReaderCache {
	readonly #held = new Map<string, Held>();
	readonly #capacity: number;

	constructor(capacity = EPOCH_READER_CACHE_SIZE) {
		this.#capacity = capacity;
	}

	get size(): number {
		return this.#held.size;
	}

	get(key: string): Held | undefined {
		const held = this.#held.get(key);
		if (held !== undefined) {
			this.#held.delete(key);
			this.#held.set(key, held);
		}
		return held;
	}

	set(key: string, held: Held): void {
		const replaced = this.#held.get(key);
		if (replaced !== undefined && replaced.plaintext !== held.plaintext)
			replaced.plaintext.fill(0);
		this.#held.delete(key);
		this.#held.set(key, held);
		for (const [oldest, evicted] of this.#held) {
			if (this.#held.size <= this.#capacity) break;
			evicted.plaintext.fill(0);
			this.#held.delete(oldest);
		}
	}

	/** Zero every kept plaintext and drop every reader. */
	clear(): void {
		for (const held of this.#held.values()) held.plaintext.fill(0);
		this.#held.clear();
	}
}

/** A copy's identity: a different plaintext under the same fingerprint is a different copy. */
function cacheKey(target: MlsTarget, copy: GoodCopy): string {
	return JSON.stringify([
		target.groupId,
		target.epoch,
		bytesToHex(copy.copy.fp),
		copy.copy.uploader,
		bytesToHex(sha256(copy.plaintext)),
	]);
}

/**
 * Open with the cached reader, and once more with one rebuilt from the escrow if that fails. A
 * message behind the cached reader's ratchet needs a rebuilt one; a refused framing signature is
 * final either way. A reader built just now has nothing to rebuild from, so its failure stands.
 */
function openOne(
	cache: EpochReaderCache,
	target: MlsTarget,
	copy: GoodCopy,
	kept: Array<() => void>,
): Opened {
	const key = cacheKey(target, copy);
	const cached = cache.get(key);
	const build = (plaintext: Uint8Array) =>
		EpochReader.fromEscrow(target.group, target.epoch, plaintext);
	let reader = cached?.reader ?? build(copy.plaintext);
	let message: OpenedMessage;
	try {
		message = reader.open(target.message);
	} catch (err) {
		if (
			cached === undefined ||
			mlsErrorCode(err) === EpochReaderCode.MemberRejected
		)
			throw err;
		reader = build(cached.plaintext);
		message = reader.open(target.message);
	}
	kept.push(() =>
		cache.set(key, {
			reader,
			plaintext: cached?.plaintext ?? copy.plaintext.slice(),
		}),
	);
	return {
		envelope: message.envelope,
		senderIndex: message.senderIndex,
		generation: message.generation,
		signerPublicKey: message.signerPublicKey,
		copy,
	};
}

/**
 * Try every good copy: the first success wins and the rest are audited against it. The native
 * core's error code decides what a failure means; an error without a code (a missing binding on a
 * stale addon, a defect) is not a verdict about the message and is thrown on.
 */
export function tryCopies(
	cache: EpochReaderCache,
	target: MlsTarget,
	good: readonly GoodCopy[],
): Trial {
	const attempt = new Attempt();
	const kept: Array<() => void> = [];
	let panicked = false;
	for (const copy of good) {
		try {
			const opened = openOne(cache, target, copy, kept);
			attempt.opened ??= opened;
		} catch (err) {
			const code = mlsErrorCode(err);
			if (code === null) throw err;
			if (code === EpochReaderCode.MemberRejected) attempt.rejected.push(copy);
			else if (code === EpochReaderCode.GenerationTooFar) attempt.tooFar = true;
			else if (code === EpochReaderCode.InvalidEscrow)
				attempt.invalid.push(escrowInvalid(target.epoch, copy.copy.uploader));
			else if (code === MLS_ERR_PANIC) panicked = true;
			else attempt.mismatched.push(copy);
		}
	}
	return {
		attempt,
		panicked,
		keep: () => {
			for (const set of kept) set();
		},
	};
}
