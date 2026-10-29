import { type ApiGetPoster, performKeyRotation } from "./agent-rotate.js";
import type { AgentRead } from "./api-types.js";
import type { CustodyDirs } from "./custody.js";
import type { HttpClient } from "./http.js";
import type { RotationSettlement } from "./mls-seat-update.js";
import { settleRotation } from "./mls-seat-sweep.js";

/** A rotated agent, with what settling the rotation did on this host. */
export interface RotationReport extends RotationSettlement {
	agent: AgentRead;
}

/**
 * Rotate an agent's keys, then move its key packages and group seats to the new
 * generation from this host.
 *
 * The rotation is committed on the server by the time the settlement starts, so
 * nothing after it throws: a group that could not be moved is an entry in the
 * report, and the next MLS operation on a host that holds the state finishes it.
 */
export async function rotateAgentWithSeats(
	client: HttpClient & ApiGetPoster,
	dirs: CustodyDirs,
	agentId: string,
): Promise<RotationReport> {
	const agent = await performKeyRotation(client, dirs, agentId);
	const settlement = await settleRotation({
		configDir: dirs.configDir,
		agentId,
		client,
	});
	return { agent, ...settlement };
}
