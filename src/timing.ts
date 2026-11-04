// Small timing primitives shared by the retry and reconnect loops.

/** Resolve after `ms` milliseconds. */
export function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Like {@link sleep}, but resolves early when `signal` fires, so a stop during
 * a backoff does not wait out the interval.
 */
export function sleepWithSignal(
	ms: number,
	signal?: AbortSignal,
): Promise<void> {
	if (!signal) return sleep(ms);
	if (ms <= 0 || signal.aborted) return Promise.resolve();
	return new Promise<void>((resolve) => {
		const onAbort = () => {
			clearTimeout(timer);
			resolve();
		};
		const timer = setTimeout(() => {
			signal.removeEventListener("abort", onAbort);
			resolve();
		}, ms);
		signal.addEventListener("abort", onAbort, { once: true });
	});
}

/** What {@link raceDeadline} rejects with when the work outlasts its time. */
export class DeadlineError extends Error {
	constructor(ms: number) {
		super(`no answer within ${Math.round(ms / 1000)}s`);
		this.name = "DeadlineError";
	}
}

/**
 * Settle with `work`, or reject with a {@link DeadlineError} once `ms` have
 * passed. The work is not cancelled; its late result is ignored. The timer is
 * cleared when the work settles and never keeps the process alive.
 */
export async function raceDeadline<T>(
	work: Promise<T>,
	ms: number,
): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const expired = new Promise<never>((_, reject) => {
		timer = setTimeout(() => reject(new DeadlineError(ms)), ms);
		timer.unref?.();
	});
	try {
		return await Promise.race([work, expired]);
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Proportional (±50%) jitter over a reconnect backoff window: a delay drawn
 * uniformly from half to one and a half times `backoffSeconds`, in milliseconds.
 */
export function jitteredDelayMs(backoffSeconds: number): number {
	return Math.round(backoffSeconds * (0.5 + Math.random()) * 1000);
}
