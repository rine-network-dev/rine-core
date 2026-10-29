import type { HttpClient } from "./http.js";
import { addMlsGroupMembers } from "./mls-ops-admit.js";

export { syncMlsGroup } from "./mls-ops-sync.js";
export type { MlsSyncResult } from "./mls-ops-sync.js";
// The eager catch-up an ordinary successful group read runs. Separate from
// `syncMlsGroup` because it is rate-limited and never throws: it exists so that
// ordinary use keeps a member's epoch current, not so a caller can ask a
// question and get an answer — that is what the explicit sync verb is for.
export { catchUpMlsGroup } from "./mls-catchup.js";
export { externalJoinMlsGroup } from "./mls-external-join.js";
export { processMlsWelcomes } from "./mls-ops-join.js";
// The group-substitution guard the Welcome path runs. Exported beside the join
// verb so that a surface installing Welcomes can recognise a refusal without
// matching on message text.
//
// The TypeScript SDK is the surface that classifies with it: its decrypt retry
// (`rine-ts-sdk/src/resources/decrypt.ts`) reports a refused Welcome as one,
// rather than as the decrypt failure of whichever message triggered recovery,
// and its `establishJoinedMls` (`resources/groups-mls.ts`) re-raises a refusal
// out of `groups.join()`. The CLI and MCP join verbs reach the same refusal
// through `establishMlsMembership`, which lets it propagate.
export {
	MlsWelcomeRefusedError,
	isMlsWelcomeRefusedError,
} from "./mls-welcome-guard.js";
export type { WelcomeRefusalReason } from "./mls-welcome-guard.js";
export {
	addMlsGroupMembers,
	initMlsGroup,
	resumeMlsGroupAdmission,
} from "./mls-ops-admit.js";
export type {
	MlsAdmissionOutcome,
	MlsAdmissionResult,
	MlsAdmissionSkipReason,
	MlsReclamationDecline,
	MlsReclamationDeclineReason,
	MlsReclamationResult,
} from "./mls-admission.js";
// Leaf reclamation. The pass lives in its own module because it is a
// removal loop rather than an admission; the surface belongs here, beside the
// other MLS verbs.
export { orphanLeaves, reclaimOrphanLeaves } from "./mls-orphans.js";
export type { OrphanLeaf } from "./mls-orphans.js";
// Removal, in its own module for the same reason: it is a
// commit that must DECLARE its target, plus the path-only rescue for a target
// whose leaf is already gone, and neither belongs in an index of verbs.
export { removeMlsGroupMember } from "./mls-ops-removal.js";
export type { MlsRemovalCommit } from "./mls-ops-removal.js";
// The tree readers surfaces need to answer "which key is this agent's?" and
// "is that key seated?", so no surface keeps its own unchunked `GET
// /agents/keys` with its own idea of how the map is keyed.
export { fetchMlsIdentities, isSeated } from "./mls-admission-tree.js";
export {
	ensureMlsKeyPackages,
	publishMlsKeyPackages,
	replenishMlsKeyPackages,
} from "./mls-keypackages.js";
export type { MlsKeyPackageStatus } from "./mls-keypackages.js";
export {
	cutoverMlsKeyPackages,
	drainAndRepublishMlsKeyPackages,
	needsMlsKeyPackageCutover,
} from "./mls-cutover.js";
export type { MlsCutoverResult } from "./mls-cutover.js";

/**
 * Add a single member to an existing MLS group.
 *
 * One member is one batch, so this is {@link addMlsGroupMembers} over a list of
 * one, kept as its own verb because three shipped surfaces call it that way.
 * The plural form reports why a member was skipped; this one raises, because
 * that is what a caller naming a single agent expects and what it already did.
 *
 * A member whose leaf is already in the tree is a no-op rather than a failure —
 * the add path is a resume, and re-inviting somebody who is already there costs
 * neither a commit nor a KeyPackage.
 */
export async function addMlsGroupMember(
	configDir: string,
	agentId: string,
	groupId: string,
	memberAgentId: string,
	client: HttpClient,
	extraHeaders?: Record<string, string>,
): Promise<{ epoch: number }> {
	const result = await addMlsGroupMembers(
		configDir,
		agentId,
		groupId,
		[memberAgentId],
		client,
		extraHeaders,
	);
	const outcome = result.outcomes[0];
	if (outcome?.reason === "no_key_package") {
		throw new Error(`No key packages available for ${memberAgentId}`);
	}
	if (outcome?.reason === "key_package_not_current") {
		throw new Error(
			`${memberAgentId}'s claimable key package was minted under an earlier key generation, ` +
				"so no Welcome could be made; it publishes current ones on its next MLS operation — " +
				"invite it again after that.",
		);
	}
	if (outcome?.reason === "rejected_by_server") {
		throw new Error(
			`The server refused ${memberAgentId} as a Welcome recipient for group ${groupId}: ` +
				"they are revoked, gone, or not enrolled in this group.",
		);
	}
	return { epoch: result.epoch };
}
