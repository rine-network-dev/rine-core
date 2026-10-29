import { validateSlug } from "./onboard.js";

/** `local@slug.rine.network` in any letter case; the local part may lead with the group `#`. */
const RINE_HANDLE = /^(#?[^@\s]+)@([a-z0-9-]+)\.rine\.network$/i;

/**
 * A handle as a person reads it: the org's own agents and groups bare (`sales`, `#ops`), another
 * org's as `local@slug`, and anything that is not exactly `<valid slug>.rine.network` (another
 * domain, a sub-domain, a lookalike suffix, a malformed handle) unchanged. Only shortens: clean the
 * text first.
 */
export function displayHandle(handle: string, ownSlug: string | null): string {
	const match = RINE_HANDLE.exec(handle);
	if (match === null) return handle;
	const [, local = "", rawSlug = ""] = match;
	const slug = rawSlug.toLowerCase();
	if (!validateSlug(slug)) return handle;
	return slug === ownSlug ? local : `${local}@${slug}`;
}

/** Who an agent is when no org is "own": the short form, never bare. */
export function identityHandle(handle: string): string {
	return displayHandle(handle, null);
}
