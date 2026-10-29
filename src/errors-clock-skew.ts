import type { RineErrorBody } from "./errors.js";

/**
 * The `reason` the token mint adds to `invalid_client` once the assertion's
 * signature verified but its time window did not: the caller's clock is off.
 */
export const CLOCK_SKEW_REASON = "clock_skew";

/**
 * True when a failed response says the caller's clock is outside the window the
 * token mint accepts. Only a 401 can: any other status is an ordinary error.
 */
export function namesClockSkew(
	status: number,
	body: RineErrorBody | undefined,
): boolean {
	return (
		status === 401 &&
		body?.error === "invalid_client" &&
		body.reason === CLOCK_SKEW_REASON
	);
}
