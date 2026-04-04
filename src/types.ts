/** Flat credential store: { "profileName": { client_id, client_secret } } */
export type Credentials = Record<string, CredentialEntry>;

export interface CredentialEntry {
	client_id: string;
	client_secret: string;
	poll_url?: string;
}

export interface CachedToken {
	access_token: string;
	expires_at: number; // Unix timestamp seconds (float-compatible)
}

/** Token cache: { "profileName": { access_token, expires_at } } */
export type TokenCache = Record<string, CachedToken>;

export interface ApiError {
	detail: string | { msg: string; type: string }[];
}
