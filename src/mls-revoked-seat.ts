import type { MlsClient, MlsGroup } from "@rine-network/mls";
import {
	type AdmissionLedger,
	type AdmitContext,
	type MlsAdmissionResult,
	admissionKey,
	admissionResult,
	recordOutcome,
} from "./mls-admission.js";
import { runAdmission } from "./mls-admission-batch.js";
import { admitGroupPeers } from "./mls-allowed-tree.js";
import { agentIdOfIdentity } from "./mls-commit-admission.js";
import { emptyReport } from "./mls-escrow-report.js";

/**
 * Admit the group's peers, reading the key of every agent the ratchet tree holds
 * in the same request, and name the tree's leaves the server does not serve.
 *
 * `GET /agents/keys` omits an agent that was revoked on its own or through its
 * branch, and the roster omits it too, so a revoked agent's leaf is invisible to
 * the roster read. It stays in the tree until a member reclaims it, and every
 * Welcome minted at that tree names it, so the joiner can never verify the tree.
 * Every leaf but this agent's own must be served by the key read, whether or not
 * its keys live on this device (the tree's agents ride in that one read as
 * `alsoRead`): the joiner's core cannot verify what the server does not vouch
 * for, so a revoked sibling whose keys are still on this device is held, and a
 * live one is not. A leaf whose identity is not an agent id counts as
 * unserved for the same reason. This agent's own leaf is excluded by its leaf
 * index, never by the keys it holds.
 */
export async function admitGroupPeersChecked(
	ctx: AdmitContext,
	group: MlsGroup,
): Promise<string[]> {
	const own = group.currentMemberIndex();
	const inTree = new Set<string>();
	const unspelled: string[] = [];
	for (const leaf of group.memberIdentities()) {
		if (leaf.index === own) continue;
		const agentId = agentIdOfIdentity(leaf.identity);
		if (agentId === null) unspelled.push(new TextDecoder().decode(leaf.identity));
		else inTree.add(agentId);
	}
	const served = new Set(await admitGroupPeers(ctx, ctx.groupId, [...inTree]));
	return [
		...[...inTree].filter((agentId) => !served.has(admissionKey(agentId))),
		...unspelled,
	];
}

/**
 * Seat `pending` unless the tree holds a revoked agent's leaf.
 *
 * While `unserved` is not empty nobody is added: no KeyPackage is claimed and no
 * commit is posted, because a Welcome minted at this tree could never be opened
 * and the joiner's leaf would stand with no way to read. Each pending joiner is
 * reported skipped. The adder never removes the leaf itself; reclamation is a
 * separate act a member runs.
 */
export function admitUnlessHeld(
	ctx: AdmitContext,
	mls: MlsClient,
	unserved: string[],
	pending: string[],
	ledger: AdmissionLedger,
	seated: number,
	startEpoch: number,
): Promise<MlsAdmissionResult> {
	if (unserved.length === 0) {
		return runAdmission(ctx, mls, pending, ledger, seated, startEpoch);
	}
	for (const agentId of pending) {
		recordOutcome(ledger, agentId, "skipped", "revoked_seat_unreclaimed");
	}
	return Promise.resolve(admissionResult(ledger, startEpoch, 0, emptyReport()));
}
