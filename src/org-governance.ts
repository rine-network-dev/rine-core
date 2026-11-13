/**
 * The org governance routes: suspend and resume an agent or a branch, freeze the org, the
 * delegated keys, the agent states a delegate reads, and the event log.
 * Each returns the server's view of the state it left; a repeat is `changed: false`, not an error.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { assertBranchName, toBase64Url } from "./crypto/index.js";
import type { HttpClient } from "./http.js";
import { normalizeHandle } from "./resolve-handle.js";
import { UUID_RE_ANY_CASE } from "./uuid.js";

import type { AgentRead } from "./api-types.js";
import {
	type AgentHoldView,
	type AgentStateView,
	type BranchHoldView,
	type DelegateListView,
	type DelegateScope,
	type DelegateView,
	type OrgEventsPage,
	type OrgFreezeView,
	type SuspensionView,
} from "./org-governance-types.js";

function agentId(id: string): string {
	if (!UUID_RE_ANY_CASE.test(id))
		throw new Error(`Invalid agent ID: must be a UUID, got '${id}'`);
	return id;
}

function branchSeg(name: string): string {
	return encodeURIComponent(assertBranchName(name));
}

/** `POST /agents/{id}/suspend`: org, a branch over its own agents, or a delegate with `suspend`. */
export async function suspendAgent(
	client: HttpClient,
	id: string,
): Promise<AgentHoldView> {
	return (await client.post(`/agents/${agentId(id)}/suspend`)) as AgentHoldView;
}

/** `POST /agents/{id}/resume`: clears only the caller's class of suspension. */
export async function resumeAgent(
	client: HttpClient,
	id: string,
): Promise<AgentHoldView> {
	return (await client.post(`/agents/${agentId(id)}/resume`)) as AgentHoldView;
}

/** `GET /agents/{id}/suspension`: the hold, the queue behind it and what to rotate before a resume. */
export async function getSuspension(
	client: HttpClient,
	id: string,
): Promise<SuspensionView> {
	return (await client.get(
		`/agents/${agentId(id)}/suspension`,
	)) as SuspensionView;
}

/** `POST /orgs/me/branches/{name}/suspend`: org or a delegate with `suspend`. */
export async function suspendBranch(
	client: HttpClient,
	name: string,
): Promise<BranchHoldView> {
	return (await client.post(
		`/orgs/me/branches/${branchSeg(name)}/suspend`,
	)) as BranchHoldView;
}

/** `POST /orgs/me/branches/{name}/resume`: org or a delegate with `resume`. */
export async function resumeBranch(
	client: HttpClient,
	name: string,
): Promise<BranchHoldView> {
	return (await client.post(
		`/orgs/me/branches/${branchSeg(name)}/resume`,
	)) as BranchHoldView;
}

/** `POST /org/freeze`: stop every agent in the org. */
export async function freezeOrg(client: HttpClient): Promise<OrgFreezeView> {
	return (await client.post("/org/freeze")) as OrgFreezeView;
}

/** `POST /org/unfreeze`: refused while rine itself holds the freeze. */
export async function unfreezeOrg(client: HttpClient): Promise<OrgFreezeView> {
	return (await client.post("/org/unfreeze")) as OrgFreezeView;
}

/** A fresh delegate keypair. The seed stays on this machine; only the public half is sent. */
export function newDelegateKey(): { seed: Uint8Array; publicKey: string } {
	const seed = crypto.getRandomValues(new Uint8Array(32));
	return { seed, publicKey: toBase64Url(ed25519.getPublicKey(seed)) };
}

/** `POST /org/delegates`: register a delegate's public key with the scopes it may use. */
export async function createDelegate(
	client: HttpClient,
	name: string,
	scopes: readonly DelegateScope[],
	signingPublicKey: string,
): Promise<DelegateView> {
	return (await client.post("/org/delegates", {
		name,
		scopes,
		signing_public_key: signingPublicKey,
	})) as DelegateView;
}

/** `GET /org/delegates`. */
export async function listDelegates(
	client: HttpClient,
): Promise<DelegateView[]> {
	return ((await client.get("/org/delegates")) as DelegateListView).delegates;
}

/** `DELETE /org/delegates/{id}`: the delegate's next request is a 401. */
export async function revokeDelegate(
	client: HttpClient,
	id: string,
): Promise<void> {
	await client.delete(`/org/delegates/${agentId(id)}`);
}

/** `GET /org/agents/states`: every agent's id, handle, branch and hold; what a delegate may read. */
export async function listAgentStates(
	client: HttpClient,
): Promise<AgentStateView[]> {
	return (await client.get("/org/agents/states")) as AgentStateView[];
}

/**
 * `GET /org/events`: one page of the tamper-evident log after `afterSeq`. With `chainEpoch` the
 * server answers 409 when the log has moved to another epoch (see `forkPointOf`).
 */
export async function fetchOrgEvents(
	client: HttpClient,
	afterSeq: number,
	limit?: number,
	chainEpoch?: number,
): Promise<OrgEventsPage> {
	return (await client.get("/org/events", {
		after_seq: afterSeq,
		...(limit === undefined ? {} : { limit }),
		...(chainEpoch === undefined ? {} : { chain_epoch: chainEpoch }),
	})) as OrgEventsPage;
}

/**
 * Find one agent by UUID, handle or unique name. Strict: a stop command never falls back to
 * "the only agent", because stopping the wrong one is worse than refusing.
 */
export function pickAgent(
	agents: readonly Pick<AgentRead, "id" | "name" | "handle">[],
	ref: string,
): string {
	if (UUID_RE_ANY_CASE.test(ref)) return ref.toLowerCase();
	const handle = normalizeHandle(ref);
	const hits = agents.filter(
		(a) =>
			(a.handle !== null && normalizeHandle(a.handle) === handle) ||
			a.name === ref,
	);
	const ids = [...new Set(hits.map((a) => a.id))];
	if (ids.length === 1) return ids[0] as string;
	throw new Error(
		ids.length === 0
			? `No agent matches '${ref}'. Use its UUID or full handle.`
			: `'${ref}' matches ${ids.length} agents. Use its UUID or full handle.`,
	);
}
