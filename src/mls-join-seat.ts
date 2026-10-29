/**
 * What a join verb answers when the server says the agent is already a member.
 *
 * Such an agent is seated on the server, and a seated agent with no local state
 * (its Welcome was refused before the seat was reclaimed, or the state was
 * lost) is the one the join verb has to bring back. Every surface that joins
 * shares this, and renders a failed setup in its own words through a sink.
 */
import { ACTING_AGENT_HEADER } from "./actor.js";
import type { GroupMemberRead } from "./api-types.js";
import { fetchGroupMembers } from "./group-members.js";
import type { HttpClient } from "./http.js";
import {
	MlsMembershipOutcome,
	type MlsMembershipResult,
	establishAfterAlreadyAMember,
	isAlreadyAMember,
	mlsStateEstablished,
} from "./mls-join-establish.js";

/** Renders an establishment whose outcome is `failed`, in a surface's own words. */
export type MlsSetupFailureSink = (failed: MlsMembershipResult) => void;

/** Hand `result` to `onFailed` when its outcome is `failed`; any other result is silent. */
export function reportFailedSetup(
	result: MlsMembershipResult,
	onFailed: MlsSetupFailureSink,
): void {
	if (result.outcome === MlsMembershipOutcome.Failed) onFailed(result);
}

/** The join an `already_a_member` answer came back for. */
export interface AlreadyAMemberJoin {
	configDir: string;
	groupId: string;
	client: HttpClient;
	/** The joining agent; asked only once the answer is `already_a_member`. */
	actingAgent: () => Promise<string>;
}

/**
 * The member row of an agent whose join answered 409 `already_a_member`, once
 * its local state is established; `null` when the 409 should stand.
 *
 * The 409 stands for any other error, for an agent that cannot be resolved or
 * already holds state, for a setup that leaves the agent with none, and when
 * the members read does not name the agent. A setup that fails reaches
 * `onFailed` first. A refusal for the group is raised.
 *
 * The roster comes from the members route on `join.client`, or, for a surface
 * whose reads run through its own request pipeline, from its `readMembers`,
 * handed the acting agent's headers; the row returned is then the surface's own.
 */
export function seatedMemberAfterConflict(
	conflict: unknown,
	join: AlreadyAMemberJoin,
	onFailed: MlsSetupFailureSink,
): Promise<GroupMemberRead | null>;
export function seatedMemberAfterConflict<M extends { agent_id: string }>(
	conflict: unknown,
	join: AlreadyAMemberJoin,
	onFailed: MlsSetupFailureSink,
	readMembers: (headers: Record<string, string>) => Promise<readonly M[]>,
): Promise<M | null>;
export async function seatedMemberAfterConflict(
	conflict: unknown,
	join: AlreadyAMemberJoin,
	onFailed: MlsSetupFailureSink,
	readMembers: (
		headers: Record<string, string>,
	) => Promise<readonly { agent_id: string }[]> = (headers) =>
		fetchGroupMembers(join.client, join.groupId, headers),
): Promise<{ agent_id: string } | null> {
	// Checked before the actor lookup, which can read config or call the server,
	// so a join that failed for any other reason pays nothing for it.
	if (!isAlreadyAMember(conflict)) return null;
	let agentId: string;
	try {
		agentId = await join.actingAgent();
	} catch {
		return null;
	}
	const headers = { [ACTING_AGENT_HEADER]: agentId };
	const seated = await establishAfterAlreadyAMember(
		conflict,
		join.configDir,
		agentId,
		join.groupId,
		join.client,
		headers,
	);
	if (!seated) return null;
	reportFailedSetup(seated, onFailed);
	if (!mlsStateEstablished(seated)) return null;
	try {
		const members = await readMembers(headers);
		return members.find((m) => m.agent_id === agentId) ?? null;
	} catch {
		// The seat is on the server and the state is local, but no member row
		// came back to report, so the answer stays the one the server gave.
		return null;
	}
}
