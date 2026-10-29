/**
 * One named profile in a `profiles.json`. It holds no secret: it
 * names a principal and the ids needed to find that principal's key files.
 * A runtime dir carries `agent:` and `branch:` principals only; the owner dir
 * carries the `org:` principal.
 */
export interface ProfileEntry {
	org_id: string;
	/** A principal string (`org:…`, `branch:…`, `agent:…`); see `principal.ts`. */
	principal: string;
	branch?: string;
	agent_id?: string;
	poll_url?: string;
}

/** `profiles.json`: { "profileName": ProfileEntry } */
export type Profiles = Record<string, ProfileEntry>;

export interface CachedToken {
	access_token: string;
	expires_at: number; // Unix timestamp seconds (float-compatible)
}

/** Token cache: { "<principal string>": { access_token, expires_at } } */
export type TokenCache = Record<string, CachedToken>;

export interface ApiError {
	detail: string | { msg: string; type: string }[];
	/** Structured error code for typed errors, e.g. "epoch_conflict". */
	error?: string;
}
