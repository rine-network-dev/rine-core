import type { AgentRead, ListResponse } from "./api-types.js";
import type { HttpClient } from "./http.js";
import { UUID_RE, resolveHandleViaWebFinger } from "./resolve-handle.js";

/**
 * Resolve a value that may be a UUID or a handle (containing @) to a UUID.
 * Handles are resolved via WebFinger.
 */
export async function resolveToUuid(apiUrl: string, value: string): Promise<string> {
	if (!value.includes("@")) {
		if (UUID_RE.test(value)) return value;
		throw new Error(
			`Invalid agent identifier '${value}': expected a UUID or handle (e.g. agent@org.rine.network).`,
		);
	}
	const resolved = await resolveHandleViaWebFinger(apiUrl, value);
	if (!UUID_RE.test(resolved)) {
		throw new Error(
			`Cannot resolve handle "${value}" to agent ID. Ensure WebFinger is available or use a UUID.`,
		);
	}
	return resolved;
}

/** Check if a value is a bare agent name (not a UUID, not a handle). */
export function isBareAgentName(value: string): boolean {
	return !value.includes("@") && !UUID_RE.test(value);
}

/** Fetch the org's agent list. Pure function — no caching. */
export async function fetchAgents(client: HttpClient): Promise<AgentRead[]> {
	const data = (await client.get("/agents")) as ListResponse<AgentRead>;
	return data.items;
}

/** Resolve a bare agent name against an agent list (case-insensitive). */
function resolveBareName(agents: AgentRead[], name: string): string {
	const lower = name.toLowerCase();
	const match = agents.find((a) => a.name.toLowerCase() === lower);
	if (match) return match.id;

	const lines = agents.map((a) => `  ${a.name}  ${a.handle}`).join("\n");
	throw new Error(
		agents.length > 0
			? `No agent named '${name}'. Available agents:\n${lines}`
			: `No agent named '${name}'. No active agents found.`,
	);
}

/**
 * Resolve which agent ID to use.
 * Priority: explicit flag > asFlag > auto-resolve (single-agent shortcut).
 * Accepts UUIDs, handles, or bare names.
 */
export async function resolveAgent(
	apiUrl: string,
	agents: AgentRead[],
	explicit?: string,
	asFlag?: string,
): Promise<string> {
	if (explicit) {
		if (isBareAgentName(explicit)) return resolveBareName(agents, explicit);
		return resolveToUuid(apiUrl, explicit);
	}
	if (asFlag) {
		if (isBareAgentName(asFlag)) return resolveBareName(agents, asFlag);
		return resolveToUuid(apiUrl, asFlag);
	}

	if (agents.length === 1) {
		const agent = agents[0];
		if (agent) return agent.id;
	}

	if (agents.length === 0) {
		throw new Error("No active agents found.");
	}

	const lines = agents.map((a) => `  ${a.id}  ${a.handle}`).join("\n");
	throw new Error(
		`Multiple agents found. Specify which agent to use:\n${lines}`,
	);
}
