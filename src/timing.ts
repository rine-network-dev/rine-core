// Small timing primitives shared by the retry and reconnect loops.

/** Resolve after `ms` milliseconds. */
export function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Proportional (±50%) jitter over a reconnect backoff window: a delay drawn
 * uniformly from half to one and a half times `backoffSeconds`, in milliseconds.
 */
export function jitteredDelayMs(backoffSeconds: number): number {
	return Math.round(backoffSeconds * (0.5 + Math.random()) * 1000);
}
