/**
 * Batches the delivery acknowledgements of a stream consumer.
 *
 * A stream consumer acks a row once it has settled, and a cold catch-up can
 * carry 200 rows. One `mark-delivered` request per row would spend the rate
 * limit, so settled ids are buffered and sent together: when the buffer reaches
 * the route's own cap, on any heartbeat (the caller calls {@link AckBatcher.flush}),
 * a short while after the last id was added, and on close.
 *
 * A lost flush costs nothing but a re-delivery: the row stays `new` and comes
 * back. So a failed flush is reported once, with the number of ids it carried,
 * and never throws into the stream loop. Every request is bounded, and so is
 * the final flush: a request that stalls must neither hold the batches behind
 * it nor a consumer's `break` for minutes.
 */

import { ACTING_AGENT_HEADER } from "./actor.js";
import type { HttpClient } from "./http.js";
import { raceDeadline } from "./timing.js";

/** The route's `max_length` for `message_ids`. */
const ACK_BATCH_MAX = 100;

/** Quiet time after the last added id before the buffer is sent. */
const ACK_BATCH_DELAY_MS = 250;

/** How long {@link AckBatcher.close} waits for the final batch before giving up. */
const ACK_CLOSE_TIMEOUT_MS = 5000;

/** How long one batch's request may take before it is given up as failed. */
const ACK_REQUEST_TIMEOUT_MS = 10_000;

export interface AckBatcherOptions {
	/** Sends one batch of ids; a rejection is reported through `onError`. */
	ack: (ids: string[]) => Promise<unknown>;
	/** Called once per failed batch, with how many ids it carried. */
	onError: (count: number, err: unknown) => void;
	/** Flush when the buffer reaches this many ids. */
	max?: number;
	/** Flush this long after the last added id. */
	delayMs?: number;
	/** Give up waiting for the final flush after this long. */
	closeTimeoutMs?: number;
	/** Report a batch as failed when its request has not answered after this long. */
	requestTimeoutMs?: number;
}

export interface AckBatcher {
	/** Queue one settled id. */
	add(id: string): void;
	/** Send what is buffered and resolve once every batch in flight has finished. */
	flush(): Promise<void>;
	/** Stop the timer and send what is left. Best effort, bounded in time; never throws. */
	close(): Promise<void>;
}

function isAbortError(err: unknown): boolean {
	return err instanceof Error && err.name === "AbortError";
}

/**
 * Mark rows delivered for `agentId`, acting as that agent. The one place the
 * route's body and acting-agent header are spelled out, shared by the by-id
 * reads and the stream batchers.
 */
export function markDeliveredAs(
	client: HttpClient,
	agentId: string,
	messageIds: readonly string[],
): Promise<{ marked: number }> {
	return client.markDelivered(agentId, [...messageIds], {
		[ACTING_AGENT_HEADER]: agentId,
	});
}

/**
 * The warning a stream consumer shows for a batch that failed, with the cause
 * after the fixed sentence so a persistent refusal (a 401, a 422) is not
 * hidden behind a message that reads like a blip.
 */
export function ackFailureNotice(count: number, err: unknown): string {
	const reason = err instanceof Error ? err.message : String(err);
	return `rine: could not mark ${count} message(s) delivered; they may be shown again (${reason})`;
}

export function createAckBatcher({
	ack,
	onError,
	max = ACK_BATCH_MAX,
	delayMs = ACK_BATCH_DELAY_MS,
	closeTimeoutMs = ACK_CLOSE_TIMEOUT_MS,
	requestTimeoutMs = ACK_REQUEST_TIMEOUT_MS,
}: AckBatcherOptions): AckBatcher {
	let buffer: string[] = [];
	let timer: ReturnType<typeof setTimeout> | undefined;
	// Batches go out one at a time, in the order they were cut.
	let tail: Promise<void> = Promise.resolve();

	const disarm = (): void => {
		if (timer !== undefined) clearTimeout(timer);
		timer = undefined;
	};

	// A reporter that throws must not reject `tail`, or every later flush with it.
	const report = (count: number, err: unknown): void => {
		try {
			onError(count, err);
		} catch {
			/* the warning channel itself failed; the ids stay new */
		}
	};

	const send = async (ids: string[]): Promise<void> => {
		try {
			await raceDeadline(ack(ids), requestTimeoutMs);
		} catch (err) {
			if (!isAbortError(err)) report(ids.length, err);
		}
	};

	const closeBounded = async (): Promise<void> => {
		try {
			await raceDeadline(flush(), closeTimeoutMs);
		} catch {
			// `flush` never rejects (`send` reports its own failures), so this is
			// the wait running out: what is still in flight stays new.
		}
	};

	const flush = (): Promise<void> => {
		disarm();
		if (buffer.length > 0) {
			const ids = buffer;
			buffer = [];
			tail = tail.then(() => send(ids));
		}
		return tail;
	};

	return {
		add(id) {
			buffer.push(id);
			if (buffer.length >= max) {
				void flush();
				return;
			}
			disarm();
			timer = setTimeout(() => void flush(), delayMs);
			timer.unref?.();
		},
		flush,
		close: closeBounded,
	};
}
