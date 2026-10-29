/** The runtime shape guards every org-reader parser shares, so a hostile-input rule is fixed once. */

export type Json = Record<string, unknown>;

/** A plain JSON object: not null, not an array. */
export function isObject(value: unknown): value is Json {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isText(value: unknown): value is string {
	return typeof value === "string";
}

/** A non-negative safe integer. */
export function isCount(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/**
 * True for the failures the crypto callees raise on bytes that do not open: a plain `Error` (a
 * short or mis-versioned wire, a failed tag). A `TypeError`, `RangeError` or `ReferenceError` is
 * a defect in this code, not in the message, so it is not classified.
 */
export function isCryptoFailure(err: unknown): boolean {
	return (
		err instanceof Error &&
		!(
			err instanceof TypeError ||
			err instanceof RangeError ||
			err instanceof ReferenceError
		)
	);
}
