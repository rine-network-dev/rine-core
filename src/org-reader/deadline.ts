/**
 * One request, its body read included, is abandoned after this long, so a stalled server is a transient
 * `ReaderNetworkError` rather than a hung poll.
 */
export const REQUEST_TIMEOUT_MS = 30_000;

/**
 * `transport` with a deadline signal on every call. The signal stays live while the budgeted fetch reads the
 * body, so a body that trickles or stalls is cut off too.
 */
export function withDeadline(
	transport: typeof fetch,
	timeoutMs = REQUEST_TIMEOUT_MS,
): typeof fetch {
	return (input, init) => {
		const timeout = AbortSignal.timeout(timeoutMs);
		const signal = init?.signal
			? AbortSignal.any([init.signal, timeout])
			: timeout;
		return transport(input, { ...init, signal });
	};
}
