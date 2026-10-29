// The dashed UUID shapes core checks ids against. Each check keeps its own case
// rule: key derivation and signed identifiers accept only the lowercase form the
// server issues, while path and lookup checks also take uppercase input.

/** The dashed 8-4-4-4-12 hex shape, unanchored, lowercase. */
export const UUID_PATTERN =
	"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

/** A canonical UUID: dashed and lowercase only. */
export const CANONICAL_UUID_RE = new RegExp(`^${UUID_PATTERN}$`);

/** A dashed UUID in either case. */
export const UUID_RE_ANY_CASE = new RegExp(`^${UUID_PATTERN}$`, "i");
