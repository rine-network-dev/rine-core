import type { MlsClient } from "@rine-network/mls";
import {
	type AdmissionLedger,
	type AdmitContext,
	admissionKey,
	recordOutcome,
	requireGroup,
} from "./mls-admission.js";
import { fetchMlsIdentities, isSeated } from "./mls-admission-tree.js";
import type { Joiner } from "./mls-commit.js";

/**
 * The joiners a batch may still add, re-read after catching up on a lost epoch
 * race.
 *
 * 🔴 **The commit that won the race may have seated some of them itself.** A
 * KeyPackage claim is exclusive per PACKAGE, not per agent: a healthy agent
 * publishes ten, so a second admin claiming a different one admits that agent
 * just as validly. Rebuilding the Add over a leaf the tree now holds is a
 * duplicate identity, which RFC 9420 forbids and the native core refuses out of
 * the commit BUILDER — before the post, outside the retry's `try`, and so out
 * of the whole admission: no outcome is recorded for the batch, the ledger
 * loses every agent in it, and the batches after it never run. The verb's own
 * contract is that an admission never fails whole.
 *
 * Reported `already_in_group` and not `added`, which is what happened: this
 * client did not seat them, it lost to the client that did. Their claimed
 * KeyPackages are spent either way — a claim is consumed by the claiming, not
 * by the commit — and that is the ordinary cost of the race, not something to
 * recover.
 *
 * The tree is re-read through {@link requireGroup} rather than carried in,
 * because the catch-up has just adopted new state, and identities are re-read
 * from the server because a leaf is matched on the agent's signing key. An
 * agent the server names no key for stays in the batch: it is revoked or gone,
 * and both answers arrive properly named a step later, from the commit.
 */
export async function dropSeatedJoiners(
	ctx: AdmitContext,
	mls: MlsClient,
	joiners: Joiner[],
	ledger: AdmissionLedger,
): Promise<Joiner[]> {
	if (joiners.length === 0) return joiners;
	const group = requireGroup(mls, ctx.groupId);
	const identities = await fetchMlsIdentities(
		ctx.client,
		joiners.map((joiner) => joiner.agentId),
		ctx.extraHeaders,
	);
	return joiners.filter((joiner) => {
		const identity = identities.get(admissionKey(joiner.agentId));
		if (!identity || !isSeated(group, identity)) return true;
		recordOutcome(ledger, joiner.agentId, "skipped", "already_in_group");
		return false;
	});
}
