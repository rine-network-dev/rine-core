/** Types of the org governance routes (`org-governance.ts`). */
/** What a delegated key may do. Mirrors `DelegateScope` on the server (`governance-codes.json`). */
export const DelegateScope = {
	EventsRead: "events:read",
	Suspend: "suspend",
	Freeze: "freeze",
	Resume: "resume",
	MetadataRead: "metadata:read",
	CounterpartyWrite: "counterparty:write",
	PolicyWrite: "policy:write",
} as const;
export type DelegateScope = (typeof DelegateScope)[keyof typeof DelegateScope];

/** Why an agent cannot act: the first hold that applies, or `null` when it is live. */
export type AgentHold = "org_frozen" | "branch_suspended" | "agent_suspended";

export interface AgentHoldView {
	agent_id: string;
	suspended: boolean;
	suspended_by_org_at: string | null;
	suspended_by_branch_at: string | null;
	resumed_at: string | null;
	changed: boolean;
}

export interface SuspensionView {
	hold: AgentHold | null;
	suspended_by_org_at: string | null;
	suspended_by_branch_at: string | null;
	branch_suspended_at: string | null;
	org_frozen_at: string | null;
	operator_frozen: boolean;
	queue_depth: number;
	oldest_queued_at: string | null;
	webhook_jobs_held: number;
	rotated_since_suspension: boolean;
	poll_token_set: boolean;
	webhooks: number;
}

export interface BranchHoldView {
	name: string;
	suspended_at: string | null;
	resumed_at: string | null;
	changed: boolean;
}

export interface OrgFreezeView {
	org_frozen_at: string | null;
	operator_frozen: boolean;
	unfrozen_at: string | null;
	changed: boolean;
}

export interface DelegateView {
	id: string;
	name: string;
	scopes: DelegateScope[];
	signing_public_key: string;
	key_id: string;
	created_at: string;
	revoked_at: string | null;
}

/** `GET /org/delegates` answers an object, so a later field can join the list. */
export interface DelegateListView {
	delegates: DelegateView[];
}

export interface AgentStateView {
	id: string;
	handle: string | null;
	branch: string | null;
	hold: AgentHold | null;
}

/** One `rine.org_event.v1` envelope, hash included. Kept loose: a newer server may add members. */
export type OrgEvent = Record<string, unknown> & {
	seq: number;
	hash: string;
	prev_hash: string;
};

/** The last pruned event: the first remaining event's `prev_hash` names `hash`. */
export interface RetentionFloor {
	chain_epoch: number;
	seq: number;
	hash: string;
}

export interface OrgEventsPage {
	events: OrgEvent[];
	next_after_seq: number;
	chain_epoch: number;
	retention_floor?: RetentionFloor | null;
}

/** The org's chain head as the server signed it; `sig` covers every member but `kid` and `sig`. */
export interface EventHead {
	domain: string;
	org_id: string;
	chain_epoch: number;
	seq: number;
	hash: string;
	server_time: string;
	nonce: string;
	unsequenced_oldest_seconds: number;
	retention_floor_seq: number;
	kid: string;
	sig: string;
}

export interface HeadKey {
	kid: string;
	alg: string;
	public_key: string;
	created_at: string;
	retired_at: string | null;
}

export interface HeadKeyList {
	keys: HeadKey[];
}

/** One message as the org saw it: envelope facts, never content. */
export interface MessageMetadata {
	seq: number;
	chain_epoch: number;
	message_id: string;
	created_at: string;
	direction: string;
	our_agent_ids: string[];
	peer_org_id: string | null;
	peer_agent_id: string | null;
	group_id: string | null;
	type: string;
	encryption_version: string;
	conversation_id: string;
}

export interface MetadataPage {
	rows: MessageMetadata[];
	next_after_seq: number;
	chain_epoch: number;
	retention_floor: { before: string | null };
}

export interface CounterpartyView {
	counterparty_org_id: string;
	first_seen: string;
	last_seen: string;
	first_direction: string;
	first_outbound_at: string | null;
	shares_group: boolean;
	sent_total: number;
	received_total: number;
	sent_30d: number;
	received_30d: number;
}

export interface CounterpartiesPage {
	counterparties: CounterpartyView[];
	next_cursor: string | null;
}

export interface CrossOrgGroup {
	group_id: string;
	owner_org_id: string;
	member_org_ids: string[];
	enrollment_policy: string;
}

export interface LogSettings {
	event_retention_days: number;
}
