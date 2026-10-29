import { keyPackageSignatureKey } from "@rine-network/mls";
import { equalBytes } from "./crypto/bytes.js";
import { mlsFromBase64 } from "./crypto/mls-api.js";
import {
	type AdmissionLedger,
	type AdmitContext,
	admissionKey,
	recordOutcome,
} from "./mls-admission.js";
import { fetchVerifiedBatchKeys } from "./mls-admission-tree.js";
import type { Joiner } from "./mls-commit.js";
import { claimFoundingKeyPackages } from "./mls-founding.js";

/**
 * Claim one KeyPackage per member of this batch, keeping only the ones minted
 * under the key generation the agent currently signs with.
 *
 * A KeyPackage carries the leaf signature key its holder will sign with, and a
 * claim hands back whatever the server holds — including a package minted under
 * an earlier generation, which a rotation supersedes. Seating one would put a
 * leaf in the tree under a key the agent no longer holds, so the Welcome it
 * receives is one it can never open. The claimed package is spent either way:
 * the server hands it out once, so a stale one is dropped rather than re-claimed,
 * and the agent publishes current ones on its next MLS operation.
 *
 * The check is one batch read of the agents' chain-verified published keys, made
 * only when something was actually claimed: a batch whose pools were all empty
 * has nothing to compare and costs no read.
 */
export async function claimCurrentKeyPackages(
	ctx: AdmitContext,
	batch: string[],
	ledger: AdmissionLedger,
): Promise<Joiner[]> {
	const claimed = await claimFoundingKeyPackages(ctx.client, batch);
	const claimedPackages: { agentId: string; keyPackage: string }[] = [];
	for (const agentId of batch) {
		const keyPackage = claimed.get(admissionKey(agentId));
		// A member whose pool emptied between the readiness report and the claim
		// is left out, not treated as a failure.
		if (!keyPackage) {
			recordOutcome(ledger, agentId, "skipped", "no_key_package");
			continue;
		}
		claimedPackages.push({ agentId, keyPackage });
	}
	if (claimedPackages.length === 0) return [];

	const verified = await fetchVerifiedBatchKeys(
		ctx.client,
		claimedPackages.map((entry) => entry.agentId),
		ctx.extraHeaders,
	);
	const joiners: Joiner[] = [];
	for (const { agentId, keyPackage } of claimedPackages) {
		const bytes = mlsFromBase64(keyPackage);
		const published = verified.get(admissionKey(agentId))?.mls;
		if (!published || !equalBytes(keyPackageSignatureKey(bytes), published)) {
			recordOutcome(ledger, agentId, "skipped", "key_package_not_current");
			continue;
		}
		joiners.push({ agentId, keyPackage: bytes });
	}
	return joiners;
}
