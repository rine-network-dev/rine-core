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
	// Sender self-read copy, sealed to the sender's own key. Returned only to the
	// caller that sent the message (`from_agent_id == caller`); `null`/absent for a
	// recipient/None-caller read, and for non-1:1 (group) rows.
	self_encrypted_payload?: string | null;
	// Viewer-relative tag: `sent` when `from_agent_id == caller`, else `received`.
	direction?: "sent" | "received";
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

// Funnel TLS-termination tier — the TS mirror of the Python `FunnelTier` StrEnum
// (funnel_naming.py) and the single source of truth for the tier on this side of
// the wire. `zero_trust` → the relay terminates TLS (issues a
// per-agent wildcard cert + runs a local listener); `shared_edge` → the broker
// terminates (Phase B). The values are byte-identical to the Python enum and the
// DB `VARCHAR(16)` CHECK; no other spelling of a tier appears anywhere.
export type FunnelTier = "zero_trust" | "shared_edge";

// The exhaustive tier value set. `FUNNEL_TIERS` is the runtime witness of the
// `FunnelTier` union so a future third tier cannot silently drift across the
// language boundary — the contract test asserts this array EXACTLY equals the
// Python `FunnelTier` values.
export const FUNNEL_TIERS = [
	"zero_trust",
	"shared_edge",
] as const satisfies readonly FunnelTier[];

// rine Funnel hook rows (funnel_schemas.py). NEVER carry a secret — the
// HMAC secret is generated + stored client-side and never crosses the wire.
// `control_ws_url` is the broker control-WS endpoint (e.g.
// "wss://funnel.rine.network/_funnel/v1") returned by BOTH create and list — the
// relay uses it VERBATIM and NEVER reconstructs it from the API base (the API
// base resolves to the primary IP / Caddy, which has no funnel route).
// `termination` tells the relay whether IT terminates TLS (zero_trust) or the
// broker does (shared_edge) — it branches once at startup on this.
export interface HookRead {
	hook_name: string;
	hostname: string;
	active: boolean;
	created_at: string;
	control_ws_url: string;
	termination: FunnelTier;
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
