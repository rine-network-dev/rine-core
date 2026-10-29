/**
 * One group's escrow rows, opened per epoch. A row is forged (nobody is named), invalid (its
 * uploader is named) or good; one good row reads an epoch and the bad rows beside it are
 * findings. An uploader whose key read failed only just now makes a copy neither.
 */
import { assertBranchName } from "../crypto/derive.js";
import { escrowReadKeys } from "../crypto/derive-read.js";
import {
	EscrowForgedError,
	EscrowInvalidError,
	openEscrow,
} from "../crypto/escrow-open.js";
import type { VerifiedAgentKeys } from "../crypto/key-chain.js";
import { seedOwnPins } from "../http.js";
import type { ReadContext } from "./context.js";
import { isCryptoFailure } from "./guards.js";
import { type EscrowCopy, parseCopy, type Entry } from "./escrow-copy.js";
import {
	type ReadGap,
	ReadGapReason,
	escrowForged,
	escrowInvalid,
	keysUnavailable,
	unreadable,
} from "./gaps.js";
import { isKeyReadError, isKeysUnavailable } from "./key-errors.js";

/** A copy that opened, with its EpochReadSecrets plaintext (the caller zeroes it). */
export interface GoodCopy {
	readonly copy: EscrowCopy;
	readonly plaintext: Uint8Array;
}

/** What an epoch's rows came to: those that opened, and a gap for each that did not. */
export interface EpochCopies {
	readonly good: readonly GoodCopy[];
	readonly bad: readonly ReadGap[];
	readonly empty: boolean;
	/** A copy whose uploader's keys could not be fetched just now: neither good nor bad. */
	readonly unavailable: boolean;
}

export class EscrowBook {
	private readonly opened = new Map<number, Promise<EpochCopies>>();

	private constructor(
		private readonly ctx: ReadContext,
		private readonly groupId: string,
		private readonly rows: ReadonlyMap<number, readonly Entry[]>,
		/** When a page or row cap ended the load early: epochs from here up may be missing rows. */
		private readonly coveredBelow: number,
	) {}

	/** Fetch the group's rows over `[minEpoch, maxEpoch]` once; epochs open on demand. */
	static async load(
		ctx: ReadContext,
		groupId: string,
		minEpoch: number,
		maxEpoch: number,
	): Promise<EscrowBook> {
		const { rows: raw, complete } = await ctx.client.escrowRows(
			groupId,
			minEpoch,
			maxEpoch,
		);
		const rows = new Map<number, Entry[]>();
		for (const entry of raw.map(parseCopy)) {
			if (entry.epoch === null) continue;
			const epochRows = rows.get(entry.epoch);
			if (epochRows) epochRows.push(entry);
			else rows.set(entry.epoch, [entry]);
		}
		// The server pages by epoch, so a cut-short walk may hold only part of its last epoch.
		const covered = complete ? Infinity : Math.max(0, ...rows.keys());
		return new EscrowBook(ctx, groupId, rows, covered);
	}

	/** What `epoch`'s rows came to, opened once. */
	copies(epoch: number): Promise<EpochCopies> {
		const opened = this.opened.get(epoch) ?? this.openEpoch(epoch);
		this.opened.set(epoch, opened);
		return opened;
	}

	private async openEpoch(epoch: number): Promise<EpochCopies> {
		const entries = this.rows.get(epoch) ?? [];
		const good: GoodCopy[] = [];
		const bad: ReadGap[] = [];
		let unavailable = false;
		if (epoch >= this.coveredBelow) bad.push(unreadable(epoch));
		else
			for (const entry of entries) {
				if ("malformed" in entry) bad.push(escrowForged(epoch));
				else {
					const opened = await this.openCopy(entry);
					if (opened instanceof Uint8Array)
						good.push({ copy: entry, plaintext: opened });
					else if (opened.reason === ReadGapReason.KeysUnavailable)
						unavailable = true;
					else bad.push(opened);
				}
			}
		return { good, bad, empty: entries.length + bad.length === 0, unavailable };
	}

	/** The plaintext, or the gap that says why not (`KeysUnavailable`: the uploader's keys were out of reach). */
	private async openCopy(copy: EscrowCopy): Promise<Uint8Array | ReadGap> {
		const { epoch, branch, uploader } = copy;
		const { client, key } = this.ctx;
		try {
			assertBranchName(branch);
		} catch (err) {
			if (!isCryptoFailure(err)) throw err;
			return escrowForged(epoch); // a hostile branch name
		}
		const { orgId } = key;
		seedOwnPins(client.client, { orgId, agentIds: [uploader.toLowerCase()] });
		let latest: VerifiedAgentKeys;
		let keys: VerifiedAgentKeys;
		try {
			latest = await client.agentKeys(uploader);
			keys =
				copy.uploaderKeyGen === latest.keyGen
					? latest
					: await client.agentKeys(uploader, copy.uploaderKeyGen);
		} catch (err) {
			if (!isKeyReadError(err)) throw err;
			return (isKeysUnavailable(err) ? keysUnavailable : unreadable)(epoch);
		}
		const escrowKeys = escrowReadKeys(key.branchRead(branch));
		try {
			return openEscrow(
				{
					orgId,
					branch,
					slot: { groupId: this.groupId, epoch, fp: copy.fp },
					uploader: { agentId: uploader, keyGen: copy.uploaderKeyGen },
					storedAt: copy.storedAt,
					sealed: copy.sealed,
					uploaderSig: copy.uploaderSig,
				},
				keys,
				escrowKeys,
				latest.keyGen,
			);
		} catch (err) {
			if (err instanceof EscrowInvalidError)
				return escrowInvalid(epoch, err.uploaderAgentId);
			if (err instanceof EscrowForgedError) return escrowForged(epoch);
			throw err;
		} finally {
			escrowKeys.escrowX25519.privateKey.fill(0);
			escrowKeys.escrowMlKem768.privateKey.fill(0);
			escrowKeys.reader.privateKey.fill(0);
		}
	}
}
