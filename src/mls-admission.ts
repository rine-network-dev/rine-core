import type { MlsClient, MlsGroup } from "@rine-network/mls";
import { loadMlsGroup, noMlsStateError } from "./crypto/mls.js";
import type { HttpClient } from "./http.js";

/**
 * Why an agent named in a batched admission did not get a leaf.
 *
 * The same three reasons exist in the Python SDK
 * (`rine-sdk/src/rine/_mls/admission.py`) under the same names in snake_case,
 * and the two enums are one contract: a member added
 * to one is added to the other in the same commit.
 */
export type MlsAdmissionSkipReason =
	/** The agent's KeyPackage pool was empty at claim time. Not an error. */
	| "no_key_package"
	/** `memberIndex()` already resolves — this is a resume, not a failure. */
	| "already_in_group"
	/** The server refused this recipient; the batch was retried without them. */
	| "rejected_by_server";

export interface MlsAdmissionOutcome {
	agentId: string;
	status: "added" | "skipped";
	reason?: MlsAdmissionSkipReason;
}

/**
 * What a batched admission did, per member.
 *
 * There is one outcome per requested id and `added` counts the `"added"` ones,
 * because an admission never fails whole: one bad recipient costs
 * that recipient their seat, never the other 31 theirs. Refusing the batch
 * would have been a regression on the single-add path this replaces, at 32x
 * the blast radius.
 */
export interface MlsAdmissionResult {
	/** The group's epoch after the last accepted commit. */
	epoch: number;
	/** How many commits it took. */
	commits: number;
	added: number;
	/** One per requested id, in request order. */
	outcomes: MlsAdmissionOutcome[];
	/**
	 * What leaf reclamation did, when the caller asked for it. Absent when it
	 * was not asked for — never a zeroed report, so "nobody ran it" and "it ran
	 * and found nothing" stay distinguishable.
	 */
	reclamation?: MlsReclamationResult;
}

/**
 * Why leaf reclamation declined to act on the orphan set it could see.
 *
 * * `identity_unknown` — an agent the group entitles to a seat has no readable
 *   signing key, so its leaf cannot be told apart from an orphan's. `GET
 *   /agents/keys` omits revoked agents, and an invitation outlives the
 *   revocation of the agent it names: dropping that agent's leaf while its
 *   voucher stands would evict somebody the group is still holding a seat for.
 * * `identity_unseated` — an agent the server calls a **member** publishes a
 *   signing key that occupies no leaf in the tree. Membership and the ratchet
 *   tree have come apart — a key rotation is the ordinary cause — and while
 *   they are apart no leaf can be attributed, so a set difference would evict a
 *   seated member whose leaf still carries the key they published before.
 * * `outstanding_unknown` — the group's live invitations could not be read, so
 *   every agent invited and not yet accepted would look like an orphan.
 *
 * The same three reasons exist in the Python SDK under the same names
 * (`rine-sdk/src/rine/_mls/admission.py`), on the `MlsAdmissionSkipReason`
 * precedent: one vocabulary, so a surface renders either stack's report. The
 * TypeScript pass raises on an unreadable outstanding read rather than
 * declining — `fetchGroupTree` does not degrade the way its Python twin does —
 * so it is the Python pass that emits `outstanding_unknown`.
 */
export type MlsReclamationDeclineReason =
	"identity_unknown" | "identity_unseated" | "outstanding_unknown";

/** A stated refusal to reclaim, with the sentence a surface renders. */
export interface MlsReclamationDecline {
	reason: MlsReclamationDeclineReason;
	detail: string;
}

/**
 * What one reclamation pass did to a group's ratchet tree.
 *
 * `found` is 0 whenever `declined` is present: the orphan set was not computed
 * at all, rather than computed and left alone.
 */
export interface MlsReclamationResult {
	/** Leaves entitled to nobody, as the pass found them. */
	found: number;
	/** How many of those a Remove commit actually retired. */
	reclaimed: number;
	/** Remove commits posted — one per reclaimed leaf, each O(N). */
	commits: number;
	/** The group's epoch after the last Remove commit. */
	epoch: number;
	/** Present when nothing was reclaimed because the set could not be trusted. */
	declined?: MlsReclamationDecline;
}

/** One acting agent admitting members to one group. */
export interface AdmitContext {
	configDir: string;
	agentId: string;
	groupId: string;
	client: HttpClient;
	extraHeaders?: Record<string, string>;
}

/**
 * Outcomes under construction, keyed by lower-cased agent id.
 *
 * A `Map` preserves insertion order, so seeding each requested id once as it is
 * read gives `outcomes` in request order for free, however many times a later
 * claim or commit replaces an entry.
 */
export type AdmissionLedger = Map<string, MlsAdmissionOutcome>;

/** The ledger's key for an agent id, matching `claimFoundingKeyPackages`' map. */
export function admissionKey(agentId: string): string {
	return agentId.toLowerCase();
}

/** Record what became of one requested agent, replacing any earlier verdict. */
export function recordOutcome(
	ledger: AdmissionLedger,
	agentId: string,
	status: "added" | "skipped",
	reason?: MlsAdmissionSkipReason,
): void {
	ledger.set(
		admissionKey(agentId),
		reason === undefined ? { agentId, status } : { agentId, status, reason },
	);
}

/** Close the ledger into the result the caller sees. */
export function admissionResult(
	ledger: AdmissionLedger,
	epoch: number,
	commits: number,
): MlsAdmissionResult {
	const outcomes = [...ledger.values()];
	return {
		epoch,
		commits,
		added: outcomes.filter((outcome) => outcome.status === "added").length,
		outcomes,
	};
}

/** This agent's local state for the group, or {@link noMlsStateError}. */
export function requireGroup(mls: MlsClient, groupId: string): MlsGroup {
	const group = loadMlsGroup(mls, groupId);
	if (!group) throw noMlsStateError(groupId);
	return group;
}
