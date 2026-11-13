/** Types of the org rules routes (`org-rules.ts`). Mirrors `src/rine/api/org_rule_models.py`. */
import type { ExposureSet } from "./agent-exposure.js";

export const PolicyRule = {
	NewAgents: "new_agents",
	ExternalOutbound: "external_outbound",
	ExternalInbound: "external_inbound",
	DirectoryListing: "directory_listing",
	WebhookHosts: "webhook_hosts",
	Funnel: "funnel",
	ActingAs: "acting_as",
	ExternalGroups: "external_groups",
} as const;
export type PolicyRule = (typeof PolicyRule)[keyof typeof PolicyRule];

export const RuleMode = { Off: "off", Report: "report", Enforce: "enforce" } as const;
export type RuleMode = (typeof RuleMode)[keyof typeof RuleMode];

/** The modes each rule takes; mirrors the server's `RULE_MODES`. `report` acts as `off` on every hot path. */
export const RULE_MODES: Readonly<Record<PolicyRule, readonly RuleMode[]>> = {
	new_agents: [RuleMode.Off, RuleMode.Enforce],
	external_outbound: [RuleMode.Off, RuleMode.Report, RuleMode.Enforce],
	external_inbound: [RuleMode.Off, RuleMode.Report, RuleMode.Enforce],
	directory_listing: [RuleMode.Off, RuleMode.Enforce],
	webhook_hosts: [RuleMode.Off, RuleMode.Enforce],
	funnel: [RuleMode.Off, RuleMode.Enforce],
	acting_as: [RuleMode.Off, RuleMode.Enforce],
	external_groups: [RuleMode.Off, RuleMode.Report, RuleMode.Enforce],
};

export const MessageDefault = { Deny: "deny", Allow: "allow" } as const;
export type MessageDefault = (typeof MessageDefault)[keyof typeof MessageDefault];

export const RuleDirection = { Outbound: "outbound", Inbound: "inbound" } as const;
export type RuleDirection = (typeof RuleDirection)[keyof typeof RuleDirection];

export const ScopeKind = { Org: "org", Branch: "branch", Agent: "agent" } as const;
export type ScopeKind = (typeof ScopeKind)[keyof typeof ScopeKind];

export const Decision = { Allow: "allow", Block: "block" } as const;
export type Decision = (typeof Decision)[keyof typeof Decision];

export const TypeClass = { KeyDistribution: "key_distribution", Other: "other" } as const;
export type TypeClass = (typeof TypeClass)[keyof typeof TypeClass];

/** The refusal codes of the rules (`error` of the 403; of the 422 for `domain_unproven` and `exposure_invalid`). */
export const RuleRefusal = {
	OutboundRefused: "outbound_refused",
	CounterpartyRefused: "counterparty_refused",
	WebhookHostRefused: "webhook_host_refused",
	ListingRefused: "listing_refused",
	FunnelRefused: "funnel_refused",
	ActingAsRestricted: "acting_as_restricted",
	TenantRestricted: "tenant_restricted",
	DomainUnproven: "domain_unproven",
	ExposureInvalid: "exposure_invalid",
	GroupRuleRefused: "group_rule_refused",
	GroupOwnerRefused: "group_owner_refused",
	GroupPostingRefused: "group_posting_refused",
} as const;
export type RuleRefusal = (typeof RuleRefusal)[keyof typeof RuleRefusal];

export interface ModeRule {
	mode: RuleMode;
}
export interface MessageRule extends ModeRule {
	default: MessageDefault;
}
export interface ListingRule extends ModeRule {
	max: ExposureSet;
}
export interface WebhookHostsRule extends ModeRule {
	allow: string[];
}
export interface ActingAsRule extends ModeRule {
	agents: string[];
}

/**
 * Every rule of one org; an absent rule reads off. `external_groups` is optional
 * on the wire: a server older than the group rule does not report it.
 */
export interface RuleSet {
	new_agents: ModeRule;
	external_outbound: MessageRule;
	external_inbound: MessageRule;
	directory_listing: ListingRule;
	webhook_hosts: WebhookHostsRule;
	funnel: ModeRule;
	acting_as: ActingAsRule;
	external_groups?: ModeRule;
}

/** The rules a write names; the others stay as they are. `max` takes the four flags. */
export type RulesPatch = Partial<RuleSet>;

/** What the enforced rules leave standing. */
export interface ExistingCounts {
	agents_above_ceiling: number;
	webhooks_outside: number;
	funnel_hooks: number;
	/** Groups our agents sit in and cannot post in: the rows of the group rule; 0 unless it enforces. */
	groups_unpostable?: number;
}

export interface PolicyView {
	version: number;
	updated_at: string | null;
	rules: RuleSet;
	/** True exactly when `external_groups` is enforce; message-rule surfaces say so while it is not. */
	groups_covered: boolean;
	existing: ExistingCounts;
}

export interface StopExistingResult {
	rule: PolicyRule;
	stopped: number;
	remaining: number;
}

export interface PreviewCounterparty {
	org_id: string;
	slug: string | null;
	messages: number;
	last_at: string;
}

export interface MessagePreview {
	kind: "messages";
	rule: PolicyRule;
	refused_messages: number;
	counterparties: number;
	top: PreviewCounterparty[];
	key_messages: number;
	window_days: number;
	since: string;
	not_counted: string[];
}

export interface ExistingPreview {
	kind: "existing";
	rule: PolicyRule;
	standing: keyof ExistingCounts | null;
	total: number;
	ids: string[];
	ids_more: number;
}

/** What enforcing `external_groups` would find over the org's groups, invitations and applications. */
export interface GroupsPreview {
	kind: "groups";
	rule: PolicyRule;
	groups: number;
	foreign_open_groups: number;
	invitations: number;
	applications: number;
}

export type PolicyPreview = MessagePreview | ExistingPreview | GroupsPreview;
