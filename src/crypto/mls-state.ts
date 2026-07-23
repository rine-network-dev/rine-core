/**
 * An agent's local MLS group state, as rine's surfaces see it.
 *
 * The state itself — current epoch, retained epoch secrets, the KeyPackage
 * pool, the self-read cache — lives in the native core's store under
 * {@link mlsStoreRoot}. Nothing here reads or writes those files directly:
 * this module is the small read-only view the CLI, the MCP server and the TS
 * SDK use to answer "has this agent joined the MLS group yet?", plus the
 * explicit retirement of a group's state.
 */
import {
	type MlsGroup,
	loadMlsGroup,
	mlsGroupIdBytes,
	openMlsClient,
} from "./mls.js";

export interface MlsGroupState {
	groupId: string;
	epoch: number;
	/** The group's own suite, read from its group context — what the server stores as `mls_cipher_suite`. */
	cipherSuite: number;
}

function describe(groupId: string, group: MlsGroup): MlsGroupState {
	return {
		groupId,
		epoch: group.epoch(),
		cipherSuite: group.cipherSuite(),
	};
}

/**
 * This agent's state for one group, or null when it holds none — it was never
 * added, its Welcome has not been processed, or the group was retired.
 */
export function loadMlsState(
	configDir: string,
	agentId: string,
	groupId: string,
): MlsGroupState | null {
	const group = loadMlsGroup(openMlsClient(configDir, agentId), groupId);
	return group ? describe(groupId, group) : null;
}

/**
 * Retire one group's local state: current state, every retained epoch secret,
 * and the plaintext its self-read cache held.
 *
 * Not recoverable — the epoch secrets are the only copy and no peer can re-send
 * them, so rejoining is the only way back in. Retiring a group that was never
 * there is not an error.
 */
export function deleteMlsState(
	configDir: string,
	agentId: string,
	groupId: string,
): void {
	openMlsClient(configDir, agentId).deleteGroupState(mlsGroupIdBytes(groupId));
}
