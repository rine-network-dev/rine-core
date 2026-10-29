/**
 * The org reader. `OrgReader.read` turns one page of the org feed into messages the org can
 * show: opened and sender-verified, or explained by one typed gap. It holds a read secret and
 * nothing else: no signing key, no custody import, and the only principal it authenticates as is
 * `reader:`. Reads are serialised, and what it learns across reads (the epoch readers that
 * opened, the sender-key distributions it verified) is kept bounded, so polling does not re-walk
 * history.
 */
import { ENCRYPTION_VERSIONS } from "../encryption-versions.js";
import {
	type ActivityQuery,
	ReaderClient,
	type ReaderClientOptions,
} from "./client.js";
import { ReadContext } from "./context.js";
import { DistributionCache } from "./distribution-cache.js";
import { distributionState } from "./distribution.js";
import { openDirect } from "./direct.js";
import { markDuplicates, storedOrder } from "./duplicates.js";
import { TokenBucket } from "./fetch-budget.js";
import { unreadable } from "./gaps.js";
import type { ReadKey } from "./keys.js";
import { labelDistribution } from "./label.js";
import { EpochReaderCache } from "./mls-open.js";
import { MlsReader } from "./mls.js";
import { type OrgSummary, fetchOrgSummary } from "./org-summary.js";
import { type ReadMessage, type ReadPage, readMessage } from "./page.js";
import { type Row, isParseFailure, parseRow } from "./rows.js";
import { SenderKeyReader } from "./sender-key.js";

export const DEFAULT_LIMIT = 50;

export interface OrgReaderOptions extends Omit<ReaderClientOptions, "signer"> {
	readonly key: ReadKey;
	/** Agents the caller created for this org, known without asking the server. */
	readonly ownAgents?: Iterable<string>;
}

/** A page, plus how many items the server sent that did not parse and left no id to name them by. */
export interface OrgPage extends ReadPage {
	readonly dropped: number;
}

/** Every reader in the process draws from this one budget unless it is given its own. */
const PROCESS_BUCKET = new TokenBucket();

/** A feed item that did not parse stands in as a row of its id alone, so it reads as `Unreadable`. */
function unparsedRow(id: string): Row {
	return {
		id,
		createdAt: "1970-01-01T00:00:00.000000Z",
		createdAtMicros: 0,
		offsetMinutes: 0,
		type: "",
		direction: "received",
		sender: { agentId: "", handle: null, orgId: "", own: false },
		recipient: null,
		groupId: null,
		groupHandle: null,
		conversationId: "",
		encryptionVersion: "",
		ciphertext: new Uint8Array(),
		selfCiphertext: null,
		keyGen: null,
	};
}

export class OrgReader {
	readonly #ctx: ReadContext;
	readonly #readers = new EpochReaderCache();
	readonly #distributions: DistributionCache;
	#tail: Promise<unknown> = Promise.resolve();

	constructor({ key, ownAgents, ...options }: OrgReaderOptions) {
		const client = new ReaderClient({
			...options,
			signer: key.signer,
			bucket: options.bucket ?? PROCESS_BUCKET,
		});
		this.#ctx = new ReadContext({ client, key, ownAgents });
		this.#distributions = new DistributionCache(this.#ctx);
	}

	/** Wait for the read in flight, then zero the read secret and drop everything kept across reads. */
	async close(): Promise<void> {
		await this.#tail;
		this.#readers.clear();
		this.#distributions.clear();
		this.#ctx.key.dispose();
	}

	/** The org this reader reads, from `GET /whoami`; it draws on the same request budget as `read`. */
	org(): Promise<OrgSummary> {
		return fetchOrgSummary(this.#ctx.client.client);
	}

	/** One read at a time: a poll and a filter change never share a ratchet-advancing epoch reader. */
	read(query: ActivityQuery = {}): Promise<OrgPage> {
		const run = this.#tail.then(() => this.#read(query));
		this.#tail = run.catch(() => undefined);
		return run;
	}

	async #read(query: ActivityQuery): Promise<OrgPage> {
		const ctx = this.#ctx;
		const page = await ctx.client.activity({
			...query,
			limit: query.limit ?? DEFAULT_LIMIT,
		});
		const parsed = page.items.map(parseRow);
		let dropped = 0;
		const rows: Row[] = [];
		for (const item of parsed) {
			if (!isParseFailure(item)) rows.push(item);
			else if (item.id !== null) rows.push(unparsedRow(item.id));
			else dropped++;
		}
		for (const row of rows) ctx.pinRow(row);
		const direct = new Map<string, ReadMessage>();
		for (const row of rows)
			if (row.encryptionVersion === ENCRYPTION_VERSIONS.HPKE_HYBRID_V2)
				direct.set(row.id, await openDirect(ctx, row));
		const consumed = [...direct.values()].filter(
			(message) => distributionState(message) !== null,
		);
		const consumedIds = new Set(consumed.map((message) => message.row.id));
		const shown = rows.filter((row) => !consumedIds.has(row.id));
		const ofVersion = (version: string) =>
			shown.filter((row) => row.encryptionVersion === version);
		const mls = new MlsReader(ctx, this.#readers);
		try {
			await mls.prepare(ofVersion(ENCRYPTION_VERSIONS.MLS_V1));
			const senderKeys = new SenderKeyReader(ctx);
			dropped += await this.#distributions.learn(
				senderKeys,
				ofVersion(ENCRYPTION_VERSIONS.SENDER_KEY_V1),
				consumed,
			);
			// Oldest first, so the first row of a repeated slot is the one that was stored first.
			const opened = new Map<string, ReadMessage>();
			for (const row of [...shown].sort(storedOrder))
				opened.set(
					row.id,
					labelDistribution(await this.#open(row, mls, senderKeys, direct)),
				);
			const items = markDuplicates(
				shown.map(
					(row) =>
						opened.get(row.id) ?? readMessage(row, { gap: unreadable() }),
				),
			);
			return {
				items,
				nextCursor: page.nextCursor,
				findings: mls.findings,
				dropped,
			};
		} finally {
			mls.release();
		}
	}

	#open(
		row: Row,
		mls: MlsReader,
		senderKeys: SenderKeyReader,
		direct: ReadonlyMap<string, ReadMessage>,
	): Promise<ReadMessage> {
		switch (row.encryptionVersion) {
			case ENCRYPTION_VERSIONS.MLS_V1:
				return mls.open(row);
			case ENCRYPTION_VERSIONS.SENDER_KEY_V1:
				return senderKeys.open(row);
			case ENCRYPTION_VERSIONS.HPKE_HYBRID_V2:
				return Promise.resolve(
					direct.get(row.id) ?? readMessage(row, { gap: unreadable() }),
				);
			default:
				return Promise.resolve(readMessage(row, { gap: unreadable() }));
		}
	}
}
