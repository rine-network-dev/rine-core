// RFC 3339 instants at the precision the server stamps them (microseconds).
// `Date.parse` stops at milliseconds, so two instants inside one millisecond would
// compare equal here and ordered on the Python side.
const INSTANT_RE =
	/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;
const MICRO_DIGITS = 6;

/** Microseconds since the epoch, or undefined for text that is not an RFC 3339 instant with an offset. */
export function instantMicros(text: string): number | undefined {
	const match = INSTANT_RE.exec(text);
	if (match === null) return undefined;
	const seconds = Date.parse(`${match[1]}${match[3]}`);
	if (Number.isNaN(seconds)) return undefined;
	const fraction = (match[2] ?? "").slice(0, MICRO_DIGITS).padEnd(MICRO_DIGITS, "0");
	return seconds * 1000 + Number(fraction);
}
