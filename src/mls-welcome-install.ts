import type { MlsClient } from "@rine-network/mls";
import { mlsFromBase64 } from "./crypto/mls-api.js";
import { canonicalUuid } from "./crypto/derive.js";
import { isMlsError, isUnprocessableCommit } from "./crypto/mls-errors.js";
import { noteMlsStateChanged } from "./crypto/mls-state.js";
import { type MlsGroup, loadMlsGroup } from "./crypto/mls.js";
import type { HttpClient } from "./http.js";
import type { PeerActor } from "./mls-allowed.js";
import { admitRefusedPeers, refusedAgentId } from "./mls-commit-admission.js";
import { type EscrowReport, emptyReport } from "./mls-escrow-report.js";
import { settleAfterJoin } from "./mls-escrow-settle.js";
import { isPeerNotAdmitted, peerNotAdmittedRefusal } from "./mls-peer-refusal.js";
import { admitWelcomePeers } from "./mls-welcome-admission.js";
import {
	type MlsWelcomeRefusedError,
	refusalIsRetryable,
	welcomeRefusal,
} from "./mls-welcome-guard.js";
import type { WelcomeRelease } from "./mls-welcome-release.js";
import type { SpooledWelcome, WelcomeSpool } from "./mls-welcome-spool.js";

/**
 * How many members one Welcome open may chain-verify beyond the roster it was
 * admitted against.
 *
 * An honest Welcome misses only the members seated or removed since the roster
 * read. Its tree is not authenticated before the leaves are checked, so a forger
 * could name agents without end; a Welcome that needs more than this is unusable.
 */
const WELCOME_VERIFICATION_LIMIT = 64;

/** What one pass of {@link processMlsWelcomes} shares across the Welcomes it installs. */
export interface WelcomeInstallContext {
	spool: WelcomeSpool;
	release: WelcomeRelease;
	/** The acting-agent header rides in `actor.extraHeaders`. */
	actor: PeerActor & { extraHeaders: Record<string, string> };
	client: HttpClient;
	mls: MlsClient;
	configDir: string;
	agentId: string;
}

/** What became of one pending Welcome. */
export type WelcomeStep =
	/** Left on the spool, unopened or unverified, for the next pass. */
	| { kind: "waiting" }
	/** Not opened because the roster answered definitively; `discarded` is 1 when its bytes left the spool. */
	| { kind: "set-aside"; discarded: 0 | 1 }
	/** Unusable for good, so it left the spool and counts as discarded. */
	| { kind: "dropped" }
	| { kind: "installed"; groupId: string; escrow: EscrowReport }
	/** `discarded` is 1 when its bytes left the spool and an unscoped pass still counts them. */
	| { kind: "refused"; refusal: MlsWelcomeRefusedError; discarded: 0 | 1 };

/**
 * Admit the roster behind one spooled Welcome, open it, run the substitution
 * guard and, when it passes, settle the escrow and record the establishment.
 *
 * The native core refuses a leaf whose `(agent id, leaf key)` is not in the
 * allowed set, so the group's chain-verified peers are admitted before the
 * Welcome is opened, and what the roster read answered decides whether it is
 * opened at all. The spool is updated here; the caller only counts the outcome.
 */
export async function installWelcome(
	ctx: WelcomeInstallContext,
	{ path, delivery }: SpooledWelcome,
): Promise<WelcomeStep> {
	const { spool, release, actor, client, mls, configDir, agentId } = ctx;
	const rineGroupId = delivery.group_id;
	const admission = await admitWelcomePeers(actor, rineGroupId);
	switch (admission) {
		case "admitted":
			break;
		case "unreachable":
			// A read that failed transiently could succeed next pass; the Welcome
			// stays spooled and unopened, because the process-wide allowed set may
			// already hold a peer another group's roster read admitted, and opening
			// it now would install a group whose roster this agent could not read.
			return { kind: "waiting" };
		case "not-seated":
			// An invitation this agent has not accepted yet: the Welcome was minted
			// when it was invited, and accepting later needs these exact bytes. So
			// it is kept, unopened — opening it would install a group whose roster
			// this agent cannot read — and kept under the refused-entry bound, so
			// an invitation never accepted ages out with the invitation itself.
			spool.markRefused(path);
			return { kind: "set-aside", discarded: 0 };
		case "group-gone":
			// The group no longer exists, so no later pass can use this Welcome.
			spool.drop(path, release);
			return { kind: "set-aside", discarded: 1 };
		default: {
			const unhandled: never = admission;
			throw new Error(`unhandled welcome admission: ${String(unhandled)}`);
		}
	}
	// Decoded outside the try: a malformed entry fails the pass, as it always has.
	const blob = mlsFromBase64(delivery.blob);
	let group: MlsGroup;
	try {
		group = await admitRefusedPeers(
			actor,
			mls,
			() => mls.joinFromWelcome(blob),
			WELCOME_VERIFICATION_LIMIT,
		);
	} catch (err) {
		// The verification read of a member the tree holds failed. Nothing was
		// written and the key package half is intact, so the Welcome stays
		// spooled for the next pass, like an unreachable roster.
		if (!isMlsError(err)) return { kind: "waiting" };
		// A store I/O failure, a contained panic or a poisoned handle is THIS
		// process failing, not the Welcome being unusable — reporting it as an
		// install would replenish key packages and hand the caller a group id it
		// does not hold. `isUnprocessableCommit` is the vocabulary's own name for
		// that split. The Python twin catches by class the two codes a Welcome
		// can earn (`RINE_MLS_PROTOCOL`, `RINE_MLS_CIPHER_SUITE_MISMATCH`) and
		// the final peer refusal, which is a subclass of the first.
		if (!isUnprocessableCommit(err)) throw err;
		// A Welcome the server serves twice is one of these: `save()` consumed
		// the private half of the KeyPackage it was sealed to, so the second
		// attempt cannot find it. Local state settles which it was, and an
		// already-installed group is an outcome rather than a failure. A peer
		// refusal is raised after the key package lookup, so it is never a replay.
		if (!isPeerNotAdmitted(err) && loadMlsGroup(mls, rineGroupId) !== null) {
			spool.discard(path);
			return { kind: "installed", groupId: rineGroupId, escrow: emptyReport() };
		}
		// A different core or ciphersuite minted it, or its tree holds a member
		// that does not verify (the final peer refusal), and no later attempt
		// changes that. It leaves the spool, because a permanently unjoinable
		// Welcome must not fail every future pass, and it is counted rather than
		// thrown, because throwing would skip the key-package heartbeat and
		// discard the ids this pass DID install. The peer refusal is the one
		// that is also reported: it is the member's own seat that is stuck,
		// unless the leaf it names is this agent's own superseded one, which no
		// reclaim removes. That Welcome is only dropped. Read before the drop:
		// releasing the key package is a call on `mls` and clears the refusal.
		const ownLeaf = refusedAgentId(mls) === canonicalUuid(agentId, "agent id");
		spool.drop(path, release);
		if (isPeerNotAdmitted(err) && !ownLeaf) {
			return {
				kind: "refused",
				refusal: peerNotAdmittedRefusal(rineGroupId),
				discarded: 1,
			};
		}
		return { kind: "dropped" };
	}
	// A processed Welcome is an establishment: invalidate here, at the
	// mutation, so a "this agent holds no MLS state" answer taken before it
	// cannot survive the join that made it false.
	noteMlsStateChanged(configDir, agentId, rineGroupId);
	const refusal = await welcomeRefusal(
		client,
		mls,
		group,
		rineGroupId,
		actor.extraHeaders,
	);
	if (refusal) {
		// Retained, and now recorded as retained: `prune`'s count bound is over
		// exactly this population, so an entry that has earned a retryable
		// refusal is the only kind it may evict to cap the tax.
		if (refusalIsRetryable(refusal.reason)) spool.markRefused(path);
		else spool.drop(path, release);
		return { kind: "refused", refusal, discarded: 0 };
	}
	const escrow = await settleAfterJoin(actor, rineGroupId, group);
	spool.discard(path);
	return { kind: "installed", groupId: rineGroupId, escrow };
}
