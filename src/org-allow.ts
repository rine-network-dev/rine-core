/**
 * Allow and block entries of the message rules, the counterparty lookup and domain proof.
 * An entry is keyed by direction, scope and counterparty; an identical write changes nothing.
 */
import type { HttpClient } from "./http.js";
import type { Decision, RuleDirection, ScopeKind } from "./org-rules-types.js";
import { UUID_RE_ANY_CASE } from "./uuid.js";

export interface AllowEntry {
	id: string;
	direction: RuleDirection;
	scope_kind: ScopeKind;
	scope_agent_id: string | null;
	counterparty_org_id: string;
	counterparty_agent_id: string | null;
	decision: Decision;
	groups: boolean;
	reason: string;
	decided_at: string;
	decided_by: string;
}

export interface AllowPage {
	entries: AllowEntry[];
	next_cursor: string | null;
}

/** The body of `PUT /org/allow`; `agent_id` absent is org-wide. A block cannot open groups. */
export interface AllowWrite {
	direction: RuleDirection;
	agent_id?: string;
	counterparty_org_id: string;
	counterparty_agent_id?: string;
	decision: Decision;
	groups?: boolean;
	reason: string;
}

export interface CounterpartyLookup {
	org_id: string;
	name: string;
	slug: string | null;
	tier: number;
	proven_domains: string[];
}

export const DomainStatus = {
	Pending: "pending",
	Proven: "proven",
	Lost: "lost",
} as const;
export type DomainStatus = (typeof DomainStatus)[keyof typeof DomainStatus];

/** A claimed domain, the TXT record that proves it and where the proof stands. */
export interface DomainView {
	domain: string;
	status: DomainStatus;
	txt_name: string;
	txt_value: string;
	created_at: string;
	verified_at: string | null;
	last_checked_at: string | null;
}

const ALLOW_PAGE = 200;

function entryId(id: string): string {
	if (!UUID_RE_ANY_CASE.test(id))
		throw new Error(`Invalid entry ID: must be a UUID, got '${id}'`);
	return id;
}

/** `GET /org/allow`: one page of entries, in id order. */
export async function fetchAllowPage(
	client: HttpClient,
	after?: string,
	direction?: RuleDirection,
): Promise<AllowPage> {
	return (await client.get("/org/allow", {
		limit: ALLOW_PAGE,
		...(after === undefined ? {} : { after }),
		...(direction === undefined ? {} : { direction }),
	})) as AllowPage;
}

/** Every entry, page by page. */
export async function fetchAllAllow(client: HttpClient): Promise<AllowEntry[]> {
	const all: AllowEntry[] = [];
	let after: string | undefined;
	do {
		const page = await fetchAllowPage(client, after);
		all.push(...page.entries);
		after = page.next_cursor ?? undefined;
	} while (after !== undefined);
	return all;
}

/** `PUT /org/allow`: write one entry. */
export async function putAllow(
	client: HttpClient,
	entry: AllowWrite,
): Promise<AllowEntry> {
	return (await client.put("/org/allow", entry)) as AllowEntry;
}

/** `DELETE /org/allow/{id}`: the reason is required as on a write and is not stored. */
export async function deleteAllow(
	client: HttpClient,
	id: string,
	reason: string,
): Promise<void> {
	await client.delete(`/org/allow/${entryId(id)}`, undefined, undefined, {
		reason,
	});
}

/** `GET /org/counterparties/lookup`: an org id, a handle, or a slug of an org already dealt with. */
export async function lookupCounterparty(
	client: HttpClient,
	ref: string,
): Promise<CounterpartyLookup> {
	return (await client.get("/org/counterparties/lookup", {
		ref,
	})) as CounterpartyLookup;
}

/** `POST /org/domains`: claim a domain; the answer carries the record to publish. */
export async function addDomain(
	client: HttpClient,
	domain: string,
): Promise<DomainView> {
	return (await client.post("/org/domains", { domain })) as DomainView;
}

/** `GET /org/domains`. */
export async function listDomains(client: HttpClient): Promise<DomainView[]> {
	return (await client.get("/org/domains")) as DomainView[];
}

/** `POST /org/domains/{domain}/verify`: a 422 `domain_unproven` while the record is missing. */
export async function verifyDomain(
	client: HttpClient,
	domain: string,
): Promise<DomainView> {
	return (await client.post(
		`/org/domains/${encodeURIComponent(domain)}/verify`,
	)) as DomainView;
}

/** `DELETE /org/domains/{domain}`. */
export async function removeDomain(
	client: HttpClient,
	domain: string,
): Promise<void> {
	await client.delete(`/org/domains/${encodeURIComponent(domain)}`);
}
