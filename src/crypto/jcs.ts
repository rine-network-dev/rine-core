// RFC 8785 (JSON Canonicalization Scheme) over the value kinds rine hashes: null, booleans, strings,
// integers, arrays and objects. The Python twin is the `jcs` package, which the backend hashes with.

export type JcsJson =
	| null
	| boolean
	| string
	| number
	| JcsJson[]
	| { [key: string]: JcsJson };

export class JcsError extends Error {}

const LONE_SURROGATE =
	/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function isPlainObject(value: object): boolean {
	const proto = Object.getPrototypeOf(value);
	return proto === Object.prototype || proto === null;
}

function quote(text: string): string {
	if (LONE_SURROGATE.test(text)) {
		throw new JcsError("jcs: string holds an unpaired surrogate");
	}
	return JSON.stringify(text);
}

function canonicalValue(value: unknown): string {
	if (value === null) return "null";
	switch (typeof value) {
		case "boolean":
			return value ? "true" : "false";
		case "string":
			return quote(value);
		case "number":
			if (!Number.isSafeInteger(value)) {
				throw new JcsError("jcs: numbers must be safe integers");
			}
			return String(value);
		case "object":
			if (Array.isArray(value)) {
				return `[${value.map(canonicalValue).join(",")}]`;
			}
			if (!isPlainObject(value)) {
				throw new JcsError("jcs: only plain objects are canonicalised");
			}
			return objectText(value as Record<string, unknown>);
		default:
			throw new JcsError(`jcs: ${typeof value} is not a JSON value`);
	}
}

function objectText(value: Record<string, unknown>): string {
	// The default sort compares UTF-16 code units, which is the order RFC 8785 asks for.
	const members = Object.keys(value)
		.sort()
		.map((key) => `${quote(key)}:${canonicalValue(value[key])}`);
	return `{${members.join(",")}}`;
}

/** The canonical text of `value`; throws {@link JcsError} for anything outside the supported kinds. */
export function canonicalize(value: JcsJson): string {
	return canonicalValue(value);
}
