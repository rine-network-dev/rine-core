/**
 * What a plural admission answers, and how to say it in a sentence.
 *
 * A roster on `POST /groups` and a batch on `POST /groups/{id}/invite` are one
 * operation at two entry points, so they report in one shape: an outcome per
 * requested agent, in the order they were named. The
 * shape lives here rather than in one client because four packages read it —
 * the CLI and the MCP server depend on `@rine-network/core` and not on the SDK,
 * so a shape that lives only in the SDK is one they can only re-declare, and
 * both of them did.
 *
 * The sentences live here for the same reason, and for a sharper one. Every
 * surface used to print the raw wire token, so an open group's admission read
 * `skipped (not_applicable)` for agents that same code path had just invited in
 * — an open group mints no voucher because it needs none. A token is a
 * machine's word; what an operator or a model needs is the fact.
 *
 * Two vocabularies, deliberately not merged: the server's says whether an
 * **invitation** was minted, the MLS one whether a ratchet-tree **leaf** was.
 * An agent can be `invited` in the first and `no_key_package` in the second —
 * it may join, and it cannot read a word until a leaf exists for it.
 */

import type { MlsAdmissionSkipReason } from "./mls-admission.js";

/**
 * Why one requested agent id was not invited — the server's vocabulary, as one
 * tuple so a client can derive both a type and a parser from it.
 */
export const GROUP_ADMISSION_SKIP_REASONS = [
	"agent_not_found",
	"agent_revoked",
	"already_a_member",
	"already_invited",
	"isolation_conflict",
	"not_applicable",
] as const;

export type GroupAdmissionSkipReason =
	(typeof GROUP_ADMISSION_SKIP_REASONS)[number];

/**
 * What happened to one requested agent id.
 *
 * `nominated` is the voting policies' answer: on `majority` and `unanimity` an
 * invite files a pending join request the electorate decides rather than a
 * voucher the agent can spend, so nobody is seated and the row may still be
 * denied. A third value rather than a reuse of `invited`,
 * because six shipped surfaces render this field and every one of them would
 * otherwise offer an operator an invitation to accept that does not exist.
 */
export interface GroupAdmissionEntry {
	agent_id: string;
	status: "invited" | "nominated" | "skipped";
	/** Present exactly when `status` is `"skipped"`; `null` otherwise. */
	reason?: GroupAdmissionSkipReason | null;
}

/**
 * One outcome per requested id, in request order, plus the two counts.
 *
 * A batch never fails whole: naming 32 agents and having one of them revoked
 * costs that one agent its seat, not the other 31 theirs.
 */
export interface GroupAdmissionReport {
	invited: number;
	skipped: number;
	entries: GroupAdmissionEntry[];
}

const GROUP_ADMISSION_SENTENCES: Record<GroupAdmissionSkipReason, string> = {
	agent_not_found: "no agent with that id exists here",
	agent_revoked: "that agent's identity is revoked, so it can join nothing",
	already_a_member: "already a member of this group",
	already_invited:
		"already holds an unaccepted invitation to this group, and that one still stands",
	isolation_conflict:
		"refused by the isolation rule — an isolated group takes only agents that are in no other group, and an agent that is in an isolated group joins nothing else",
	not_applicable:
		"this group takes open enrollment, so it mints no invitation because none is needed — the agent may join whenever it likes",
};

const MLS_ADMISSION_SENTENCES: Record<MlsAdmissionSkipReason, string> = {
	no_key_package:
		"published no key package to claim, so no Welcome was minted — they hold their invitation and cannot read this group until a leaf exists for them",
	already_in_group:
		"already holds a ratchet-tree leaf, so there was nothing to do",
	rejected_by_server:
		"the server refused them as a Welcome recipient — revoked, gone, or not enrolled in this group — and the batch was retried without them",
};

/**
 * Look one reason up, tolerating whatever actually arrived.
 *
 * The parameter is a bare `string` on purpose, and it is the one place in this
 * module that is: the reason is a value the **server** chose, read off the wire
 * by clients that do not all validate it, and a route that gains a reason must
 * not make an older client throw while rendering a report. An unrecognised
 * token is therefore quoted back rather than swallowed — it is still the truest
 * thing this client can say.
 */
function sentenceFor(
	sentences: Record<string, string>,
	reason: string | null | undefined,
): string {
	if (reason === null || reason === undefined || reason === "") {
		return "no reason given";
	}
	return sentences[reason] ?? `reason not recognised by this client: ${reason}`;
}

/**
 * Why an agent named in a roster or a plural invite was not invited, as a
 * sentence an operator or a model can act on.
 *
 * Reads as a clause, so a caller can put it wherever it renders the id:
 * `` `${entry.agent_id}: ${groupAdmissionSkipSentence(entry.reason)}` ``.
 */
export function groupAdmissionSkipSentence(
	reason: string | null | undefined,
): string {
	return sentenceFor(GROUP_ADMISSION_SENTENCES, reason);
}

/**
 * Why an admitted agent got no ratchet-tree leaf, as a sentence. Same clause
 * shape as {@link groupAdmissionSkipSentence}, and a different question: this
 * one is about the leaf, not about the invitation.
 */
export function mlsAdmissionSkipSentence(
	reason: string | null | undefined,
): string {
	return sentenceFor(MLS_ADMISSION_SENTENCES, reason);
}

/**
 * The agent ids a report says are now welcome in the group — the ones owed an
 * invitation notice.
 *
 * That is the invited entries, the **nominated** ones, and the
 * `not_applicable` ones, which is the same arithmetic the server charges seats
 * by — a nomination reserves a ratchet-tree seat exactly as an invitation does.
 * An open group mints no voucher because it needs none, so every entry
 * comes back `not_applicable`: reading only `"invited"` here tells nobody they
 * may join an open group while telling everybody they may join a closed one,
 * which is precisely the defect a plural invite shipped with.
 *
 * 🔴 "Reached" is not "entitled to a ratchet-tree leaf". A nominee holds a seat
 * and no leaf until the electorate carries their request, so a caller that
 * seats this list on an MLS group Welcomes an agent the vote may deny — ask
 * `inviteNominates(group.enrollment_policy)` before minting a commit for it.
 */
export function admittedAgentIds(report: GroupAdmissionReport): string[] {
	return report.entries
		.filter(
			(entry) =>
				entry.status === "invited" ||
				entry.status === "nominated" ||
				entry.reason === "not_applicable",
		)
		.map((entry) => entry.agent_id);
}

/** One outcome status, counted off the entries. */
function statusCount(
	report: GroupAdmissionReport,
	status: GroupAdmissionEntry["status"],
): number {
	return report.entries.filter((entry) => entry.status === status).length;
}

/**
 * The one line above the per-agent lines: how many agents this admission
 * reached, and what each of them now holds.
 *
 * 🔴 Composed from the ENTRIES, never from `invited`/`skipped`. The server
 * answers `not_applicable` for every valid agent on an open group, so those two
 * counters read `0 invited, N skipped` there — always — while the very same
 * call DMs all N an invitation notice. Six surfaces printed that headline over
 * per-agent lines that had just been made truthful, so the summary contradicted
 * the detail directly beneath it. Counting the entries also keeps this correct
 * however the server buckets a nomination in its own two counters.
 *
 * An invitation and a nomination get different clauses because they ask
 * different things of their holder: one is accepted, the other waits on a vote
 * that may refuse it. Both are stated when a batch produced both, invitations
 * first.
 */
export function admissionHeadline(report: GroupAdmissionReport): string {
	const reached = admittedAgentIds(report).length;
	const total = report.entries.length;
	const invited = statusCount(report, "invited");
	const nominated = statusCount(report, "nominated");
	const clauses: string[] = [];
	// The invitation clause carries the "nothing to accept" case too, so a
	// roster that invited nobody still says so rather than trailing off.
	if (invited > 0 || nominated === 0) {
		clauses.push(`${invited} new ${plural(invited, "invitation")} to accept`);
	}
	if (nominated > 0) {
		clauses.push(
			`${nominated} new ${plural(nominated, "nomination")} awaiting a vote`,
		);
	}
	return `${reached} of ${total} reached; ${clauses.join("; ")}.`;
}

/** `1 invitation`, `2 invitations` — the only inflection this module needs. */
function plural(count: number, noun: string): string {
	return count === 1 ? noun : `${noun}s`;
}
