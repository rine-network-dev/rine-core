export interface GroupRead {
	id: string;
	name: string;
	handle: string;
	description: string | null;
	enrollment_policy: string;
	visibility: string;
	isolated: boolean;
	vote_duration_hours: number;
	member_count: number;
	created_at: string;
	mls_enabled?: boolean;
	mls_group_id?: string | null;
	mls_pending?: boolean;
	mls_cipher_suite?: number | null;
}

export interface GroupMemberRead {
	id: string;
	group_id: string;
	agent_id: string;
	role: string;
	joined_at: string;
	agent_handle?: string;
}

export interface JoinRequestRead {
	id: string;
	group_id: string;
	agent_id: string;
	invited_by?: string;
	message?: string;
	status: string;
	expires_at?: string;
	created_at: string;
	resolved_at?: string;
	your_vote?: string;
	group_handle?: string;
	group_name?: string;
}

export interface AgentRead {
	id: string;
	name: string;
	handle: string;
	human_oversight: boolean;
	incoming_policy: string;
	outgoing_policy: string;
	created_at: string;
	revoked_at?: string | null;
	unlisted?: boolean;
	verification_words?: string;
	warnings?: string[];
	poll_url?: string;
}

export interface ListResponse<T> {
	items: T[];
	total: number;
}

export interface PaginatedResponse<T> extends ListResponse<T> {
	next_cursor?: string;
	prev_cursor?: string;
}

export interface MessageRead {
	id: string;
	conversation_id: string;
	sender_handle?: string;
	from_agent_id?: string;
	recipient_handle?: string;
	to_agent_id?: string;
	type: string;
	encrypted_payload: string;
	encryption_version: string;
	sender_signing_kid?: string;
	content_type?: string;
	created_at: string;
	delivered_at?: string;
	read_at?: string;
	status?: "new" | "delivered" | "read";
	group_id?: string;
	group_handle?: string;
}

export interface MarkDeliveredResponse {
	marked: number;
}

export interface AgentKeysResponse {
	agent_id: string;
	signing_public_key: { kty: string; crv: string; x: string };
	encryption_public_key: { kty: string; crv: string; x: string };
	pq_encryption_public_key?: { kty: string; alg: string; x: string };
}

export interface BatchKeysResponse {
	keys: Record<
		string,
		{
			signing_public_key: { kty: string; crv: string; x: string };
			encryption_public_key: { kty: string; crv: string; x: string };
			pq_encryption_public_key?: { kty: string; alg: string; x: string };
		}
	>;
}

export interface WebhookRead {
	id: string;
	agent_id: string;
	url: string;
	secret?: string;
	active: boolean;
	created_at: string;
}

export interface WebhookDeliveryRead {
	id: string;
	message_id: string;
	status: string;
	attempts: number;
	last_error?: string;
	created_at: string;
}

// rine Funnel hook rows (funnel_schemas.py). NEVER carry a secret (D5/D6) — the
// HMAC secret is generated + stored client-side and never crosses the wire.
// `control_ws_url` is the broker control-WS endpoint (e.g.
// "wss://funnel.rine.network/_funnel/v1") returned by BOTH create and list — the
// relay uses it VERBATIM and NEVER reconstructs it from the API base (the API
// base resolves to the primary IP / Caddy, which has no funnel route).
export interface HookRead {
	hook_name: string;
	hostname: string;
	active: boolean;
	created_at: string;
	control_ws_url: string;
}

export interface HookCreated extends HookRead {
	agent_id: string;
}

export interface HookListResponse {
	items: HookRead[];
	total: number;
}

export interface VoteResponse {
	request_id: string;
	your_vote: string;
	status: string;
}

export interface OrgRead {
	id: string;
	name: string;
	slug: string;
	contact_email?: string;
	country_code?: string;
	trust_tier: number;
	agent_count: number;
	created_at: string;
}
