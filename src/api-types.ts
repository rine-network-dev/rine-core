import type { EncryptionVersion } from "./encryption-versions.js";

/**
 * A wire field whose known values are `T`. Any other string still type-checks,
 * so a value a newer server adds degrades instead of breaking a read, while
 * editors offer the known values.
 */
type KnownOr<T extends string> = T | (string & {});

type JoinRequestStatus = KnownOr<"pending" | "approved" | "denied" | "invited">;

type Vote = KnownOr<"approve" | "deny">;

export interface GroupRead {
	id: string;
	name: string;
	handle: string;
	description: string | null;
	enrollment_policy: KnownOr<"open" | "closed" | "majority" | "unanimity">;
	visibility: KnownOr<"public" | "private">;
	isolated: boolean;
	vote_duration_hours: number;
	member_count: number;
	created_at: string;
	mls_enabled?: boolean;
	mls_group_id?: string | null;
	mls_pending?: boolean;
	mls_cipher_suite?: number | null;
	// The group's running conversation — the id `rine thread` takes. A group's
	// thread is created lazily on its first post, so `null` is a fact —
	// "nothing has been said in this group yet" — and never an error, never a
	// missing feature, never "you may not read it". Render it as that sentence.
	//
	// Required rather than optional (unlike the `mls_*` fields above) because
	// the server emits the key on all four `GroupRead` routes even when the
	// value is null, and the SDK's zod mirror defaults it to `null`, so every
	// surface reads the same `string | null`. It is a POINTER, not an
	// authorisation: every read of the conversation it names is re-gated on
	// LIVE group membership at the moment of the read.
	conversation_id: string | null;
	// Which of the CALLER'S OWN agents hold a seat in this group — the question
	// `member_count` never answered. A key-scoped list is not proof that the
	// agent doing the asking may post: the group row said how many members the
	// group has, and nothing at all about whether any of them was yours.
	//
	// An empty array is a FACT, not an absence: no agent of this org is seated,
	// so a send would be refused and the remedy is an invitation rather than a
	// different header. Render it as that sentence, never as a blank.
	//
	// The values are agent UUIDs and are directly actionable — `X-Rine-Agent`
	// accepts an agent's UUID as readily as its handle, so an id from here can
	// be pasted into the header that makes the next call work.
	//
	// Purely additive, and it narrows nothing: `member_count` is still the whole
	// roster, `GET /groups` still lists every group the credential may see, and the
	// list names no agent outside the caller's own org.
	//
	// Optional, unlike `conversation_id` above: this field is newer than the
	// oldest server a current client can be pointed at, and the release order
	// (server first, clients after) makes "new client, old server" a real state
	// for the length of the hold. `undefined` therefore means "this deployment
	// does not report it", which is not the same fact as `[]`, and the `??`
	// guards on the rendering surfaces are live code rather than dead defence.
	member_agent_ids?: string[];
}

export interface GroupMemberRead {
	id: string;
	group_id: string;
	agent_id: string;
	role: KnownOr<"admin" | "member">;
	joined_at: string;
	agent_handle?: string;
	// Whether this roster row is one of the caller's own org's agents.
	//
	// A MARKER, never a filter. `GET /groups/{id}/members` still returns every
	// member of the group and `total` is still the whole roster, so a surface
	// that hid the rows where this is false would answer a question nobody
	// asked and would hide the co-members a group send actually reaches.
	//
	// Optional for the reason `member_agent_ids` is: a server that predates the
	// field omits the key, and `undefined` ("this build cannot tell you") is a
	// different fact from `false` ("not one of yours") — which is exactly the
	// distinction `memberRow` renders as an em dash.
	is_own_org?: boolean;
}

export interface JoinRequestRead {
	id: string;
	group_id: string;
	agent_id: string;
	invited_by?: string;
	message?: string;
	status: JoinRequestStatus;
	expires_at?: string;
	created_at: string;
	resolved_at?: string;
	your_vote?: Vote;
	// Where the vote stands. A request is decided by the members the group had
	// when it was filed and only by those still in it, so `electorate_size` is
	// the denominator BOTH bars come from — approvals and denials alike — and
	// `quorum_total_members` is reporting only. `VOTE_ELECTORATE_RULE`
	// (`./vote-words.js`) states that rule in the one sentence every surface
	// renders. `you_may_vote_reason` predicts what the vote route would answer:
	// `not_in_electorate`, `electorate_empty`, `bar_unreachable` and
	// `is_applicant` are 403s, `already_voted` a 409, `not_pending` a 422. All
	// null on an invitation, which nobody votes on; a server that predates the
	// electorate sends none of them.
	quorum_total_members?: number | null;
	electorate_size?: number | null;
	approvals?: number | null;
	denials?: number | null;
	approvals_needed?: number | null;
	// How many more denials would refuse this request, netted against the ones
	// cast. Null exactly when `approvals_needed` is — an invitation, a resolved
	// row, or an electorate with nothing left in it — because the rule is "no
	// bar is reachable", not "the number happens to be zero". Reported so a
	// standing denial's weight is legible: it is measured against a shrinking
	// electorate, so a departure can refuse a request nobody has voted on since.
	denials_needed?: number | null;
	you_may_vote?: boolean;
	you_may_vote_reason?: string;
	group_handle?: string;
	group_name?: string;
}

export interface AgentRead {
	id: string;
	name: string;
	/**
	 * The agent's handle, or `null` until its org has a slug — `POST /agents`
	 * only mints one when it does. Nullable here so the compiler carries the
	 * fact: a caller that prints `handle` unguarded names an agent by nothing
	 * the wire accepts.
	 */
	handle: string | null;
	human_oversight: boolean;
	incoming_policy: KnownOr<"accept_all" | "groups_only">;
	outgoing_policy: KnownOr<"send_all" | "groups_only">;
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
	// Open-ended: the server accepts any dotted namespaced type, not a fixed set.
	type: string;
	encrypted_payload: string;
	// Sender self-read copy, sealed to the sender's own key. Returned only to the
	// caller that sent the message (`from_agent_id == caller`); `null`/absent for a
	// recipient/None-caller read, and for non-1:1 (group) rows.
	self_encrypted_payload?: string | null;
	// Viewer-relative tag: `sent` when `from_agent_id == caller`, else `received`.
	direction?: "sent" | "received";
	encryption_version: KnownOr<EncryptionVersion>;
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
	mls_signing_public_key: { kty: string; crv: string; x: string };
	pq_encryption_public_key: { kty: string; alg: string; x: string };
	pq_signing_public_key: { kty: string; alg: string; x: string };
	org_id: string;
	org_signing_public_key: string;
	org_pq_signing_public_key: string;
	branch: string;
	branch_certificate: string;
	key_gen: number;
	agent_certificate: string;
	/** Present on history reads only: when this generation was replaced. */
	superseded_at?: string;
	/** When the agent, or its branch if earlier, was revoked; null while neither is. */
	revoked_at?: string | null;
}

export interface BatchKeysResponse {
	keys: Record<string, AgentKeysResponse>;
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
	status: KnownOr<"pending" | "processing" | "delivered" | "failed" | "dead">;
	attempts: number;
	last_error?: string;
	created_at: string;
}

// Funnel TLS-termination tier — the TS mirror of the Python `FunnelTier` StrEnum
// (src/rine/core/funnel_tier.py) and the single source of truth for the tier on
// this side of the wire. `zero_trust` → the relay terminates TLS (issues a
// per-agent wildcard cert + runs a local listener); `shared_edge` → the broker
// terminates (Phase B). The values are byte-identical to the Python enum and the
// `VARCHAR(16)` CHECK on `FunnelHook.termination` (the src/rine/db/models/
// package); no other spelling of a tier appears anywhere.
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
	your_vote: Vote;
	status: JoinRequestStatus;
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

/** `GET /whoami`: answers every principal kind, scoped to what the caller may see. */
export interface WhoAmIRead {
	org: OrgRead;
	principal: {
		kind: "org" | "branch" | "agent" | "org_reader" | "branch_reader";
		branch: string | null;
		agent_id: string | null;
	};
	agents: AgentRead[];
}
