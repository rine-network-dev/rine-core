/**
 * What the reader knows about sender-key distributions across reads. A verified distribution never
 * changes, so keeping the ones seen spares an active open group a walk of the org's distribution
 * history on every poll.
 */
import { SENDER_KEY_DISTRIBUTION_TYPE } from "../control-frames.js";
import type { ReadContext } from "./context.js";
import { openDirect } from "./direct.js";
import { distributionState } from "./distribution.js";
import type { ReadMessage } from "./page.js";
import { type Row, isParseFailure, parseRow } from "./rows.js";
import type { SenderKeyReader } from "./sender-key.js";

/**
 * Distribution pages one read may walk. A sender-key row whose distribution the org never held
 * is never satisfied, so the scan would walk the org's whole history on every page view and
 * spend the reader's request budget; past this bound the row reads as `NoDistribution`.
 */
const MAX_DISTRIBUTION_PAGES = 20;
/** Verified distributions kept across reads, the one seen longest ago out first. */
const DISTRIBUTION_CACHE_SIZE = 4096;
const PAGE_LIMIT = 100;

export interface DistributionCacheOptions {
	readonly capacity?: number;
	readonly maxPages?: number;
}

export class DistributionCache {
	/** Verified distribution messages by row id. */
	readonly #kept = new Map<string, ReadMessage>();
	readonly #ctx: ReadContext;
	readonly #capacity: number;
	readonly #maxPages: number;

	constructor(ctx: ReadContext, options: DistributionCacheOptions = {}) {
		this.#ctx = ctx;
		this.#capacity = options.capacity ?? DISTRIBUTION_CACHE_SIZE;
		this.#maxPages = options.maxPages ?? MAX_DISTRIBUTION_PAGES;
	}

	get size(): number {
		return this.#kept.size;
	}

	clear(): void {
		this.#kept.clear();
	}

	/**
	 * Give `senderKeys` the distributions `rows` need: the ones kept from earlier reads, the ones
	 * this page carried, and, unless the kept ones already cover every row, the org's distribution
	 * rows walked from the newest. Returns how many walked items did not parse.
	 */
	async learn(
		senderKeys: SenderKeyReader,
		rows: readonly Row[],
		carried: readonly ReadMessage[],
	): Promise<number> {
		const before = [...this.#kept.values()];
		for (const message of carried) this.#remember(message);
		if (rows.length === 0) return 0;
		senderKeys.ingest(before);
		senderKeys.want(rows);
		const covered = before.length > 0 && senderKeys.satisfied();
		senderKeys.ingest(carried);
		return covered ? 0 : this.#walk(senderKeys);
	}

	/** Walk the distribution rows, newest first, until every wanted slot is covered or the bound is reached. */
	async #walk(senderKeys: SenderKeyReader): Promise<number> {
		let cursor: string | null = null;
		let dropped = 0;
		for (let pages = 0; pages < this.#maxPages; pages++) {
			// The type narrows the scan; `distributionState` still needs the content to agree.
			const page = await this.#ctx.client.activity({
				cursor,
				limit: PAGE_LIMIT,
				type: SENDER_KEY_DISTRIBUTION_TYPE,
			});
			const opened: ReadMessage[] = [];
			for (const item of page.items) {
				const row = parseRow(item);
				if (isParseFailure(row)) {
					dropped++;
					continue;
				}
				this.#ctx.pinRow(row);
				opened.push(
					this.#remember(
						this.#kept.get(row.id) ?? (await openDirect(this.#ctx, row)),
					),
				);
			}
			senderKeys.ingest(opened);
			cursor = page.nextCursor;
			if (senderKeys.satisfied() || cursor === null) break;
		}
		return dropped;
	}

	/** Keep a verified distribution; anything else is opened afresh each time. */
	#remember(message: ReadMessage): ReadMessage {
		if (distributionState(message) === null) return message;
		this.#kept.delete(message.row.id);
		this.#kept.set(message.row.id, message);
		for (const oldest of this.#kept.keys()) {
			if (this.#kept.size <= this.#capacity) break;
			this.#kept.delete(oldest);
		}
		return message;
	}
}
