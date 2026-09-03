import type { HttpClient } from "./http.js";
import { addMlsGroupMembers } from "./mls-ops-admit.js";

export { syncMlsGroup } from "./mls-ops-sync.js";
export type { MlsSyncResult } from "./mls-ops-sync.js";
// The eager catch-up an ordinary successful group read now runs. Separate from
// `syncMlsGroup` because it is rate-limited and never throws: it exists so that
// ordinary use keeps a member's epoch current, not so a caller can ask a
// question and get an answer — that is what the explicit sync verb is for.
export {
	catchUpMlsGroup,
	resetMlsCatchUpGate,
	MLS_CATCHUP_MIN_INTERVAL_MS,
} from "./mls-catchup.js";
export { externalJoinMlsGroup, processMlsWelcomes } from "./mls-ops-join.js";
// The group-substitution guard the Welcome path runs. Exported beside the join
// verb so that a surface installing Welcomes can recognise a refusal without
// matching on message text.
//
// 🔴 **No surface does yet.** Nothing outside this package imports any of the
// three (checked repo-wide over `rine-cli`, `rine-ts-sdk`, `rine-mcp`,
// `rine-openclaw`, `rine-mastra`, `rine-eve`), so today a refusal reaches an
// operator unclassified: `rine-ts-sdk/src/resources/decrypt.ts` catches it in
// the generic retry handler and reports it as a decrypt error on whichever
// message triggered recovery — which need not be a message for the refused
// group at all. This comment states an available capability, NOT a shipped one;
// do not read it as "surfaces classify refusals".
export {
	MlsWelcomeRefusedError,
	WELCOME_REFUSED_CODE,
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
// removal loop rather than an admission, and because this file is at the
// file-size ceiling; the surface belongs here, beside the other MLS verbs.
export { orphanLeaves, reclaimOrphanLeaves } from "./mls-orphans.js";
export type { OrphanLeaf } from "./mls-orphans.js";
// Removal, in its own module for the same reason: it is a
// commit that must DECLARE its target, plus the path-only rescue for a target
// whose leaf is already gone, and neither belongs in an index of verbs.
export { removeMlsGroupMember } from "./mls-ops-removal.js";
export type { MlsRemovalCommit } from "./mls-ops-removal.js";
// The tree readers surfaces need to answer "which key is this agent's?" and
// "is that key seated?". Unexported, they were copied — a single-id `GET
// /agents/keys` grew a second and a third home in the CLI and the TS SDK, each
// unchunked and each with its own idea of how the map is keyed.
export { fetchMlsIdentities, isSeated } from "./mls-admission-tree.js";
export {
	ensureMlsKeyPackages,
	// The predicate that tells "the server already holds all it will hold" apart
	// from a publish that genuinely failed — the distinction `KeyPackageTopUp`
	// encodes, and the reason it is on the barrel: a surface reaching for it and
	// not finding it hand-rolls a fourth copy of the string match this replaced.
	// The Python twin is `rine._mls.is_inventory_full`.
	isInventoryFull,
	publishMlsKeyPackages,
	replenishMlsKeyPackages,
	MLS_KEY_PACKAGE_LOW_WATER,
	MLS_KEY_PACKAGE_MAX_BATCH,
	MLS_KEY_PACKAGE_TARGET,
} from "./mls-keypackages.js";
export type { MlsKeyPackageStatus } from "./mls-keypackages.js";
// The heartbeat behind every MLS verb, and the pace a call site picks. 🔴
// `resetMlsHeartbeatGate` is deliberately NOT here: it clears the process-local
// floor, and a published test seam that defeats a rate limit gets used as one.
// Its home is `mls-heartbeat.js`, which this package's own tests import
// directly — the Python twin keeps `reset_mls_heartbeat_gate` inside the
// underscore-private `rine._mls` for the same reason.
export { mlsHeartbeat, MLS_HEARTBEAT_MIN_INTERVAL_MS } from "./mls-heartbeat.js";
export type { MlsActor, MlsHeartbeatPace } from "./mls-heartbeat.js";
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
	if (outcome?.reason === "rejected_by_server") {
		throw new Error(
			`The server refused ${memberAgentId} as a Welcome recipient for group ${groupId}: ` +
				"they are revoked, gone, or not enrolled in this group.",
		);
	}
	return { epoch: result.epoch };
}
