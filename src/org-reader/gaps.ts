/**
 * What the reader says when it cannot show a message. A message it cannot open is never an
 * empty row: it carries one typed reason, from a closed set the UI switches over.
 */

/** Why a message is not shown as text. The values are the wire spelling (PROTOCOL §13.2). */
export const ReadGapReason = {
	NoEscrow: "NoEscrow",
	EscrowForged: "EscrowForged",
	EscrowInvalid: "EscrowInvalid",
	ForkUnmatched: "ForkUnmatched",
	NoDistribution: "NoDistribution",
	RatchetGap: "RatchetGap",
	MemberRejected: "MemberRejected",
	Duplicate: "Duplicate",
	/** A 1:1 or group row no org agent's key opens (a retired encryption version, a bad seal). */
	Unreadable: "Unreadable",
	/** The row belongs to an agent whose branch this reader's key does not reach. */
	OutOfScope: "OutOfScope",
	/** A sender-key distribution no org agent's key opens: the keys it carried stay unknown. */
	KeyDistributionUnreadable: "KeyDistributionUnreadable",
	/** A distribution that opened but whose sender signature did not verify, so its keys were not used. */
	KeyDistributionUnverified: "KeyDistributionUnverified",
	/** The keys needed to check the message could not be fetched just now; no agent is accused. */
	KeysUnavailable: "KeysUnavailable",
} as const;
export type ReadGapReason = (typeof ReadGapReason)[keyof typeof ReadGapReason];

/** One typed reason, with the fields that reason defines and nothing else. */
export interface ReadGap {
	readonly reason: ReadGapReason;
	readonly epoch?: number;
	readonly uploader?: string;
	readonly sender?: string;
	readonly index?: number;
}

/** A gap found outside any one message, with the group it was found in. */
export interface ReadFinding {
	readonly groupId: string;
	readonly gap: ReadGap;
}

/** A reason that carries no field. */
export function gapOf(reason: ReadGapReason): ReadGap {
	return { reason };
}

export function noEscrow(epoch: number): ReadGap {
	return { reason: ReadGapReason.NoEscrow, epoch };
}

/** No copy carries a valid uploader signature, so no agent is named. */
export function escrowForged(epoch: number): ReadGap {
	return { reason: ReadGapReason.EscrowForged, epoch };
}

/** A copy its uploader signed that does not open: the uploader is named. */
export function escrowInvalid(epoch: number, uploader: string): ReadGap {
	return { reason: ReadGapReason.EscrowInvalid, epoch, uploader };
}

export function forkUnmatched(epoch: number): ReadGap {
	return { reason: ReadGapReason.ForkUnmatched, epoch };
}

export function noDistribution(sender: string): ReadGap {
	return { reason: ReadGapReason.NoDistribution, sender };
}

export function ratchetGap(sender: string, index: number | null): ReadGap {
	return index === null
		? { reason: ReadGapReason.RatchetGap, sender }
		: { reason: ReadGapReason.RatchetGap, sender, index };
}

export function memberRejected(epoch: number): ReadGap {
	return { reason: ReadGapReason.MemberRejected, epoch };
}

/** A stored key could not be authenticated: its uploader's history was unreadable. */
export function unreadable(epoch?: number): ReadGap {
	return epoch === undefined
		? { reason: ReadGapReason.Unreadable }
		: { reason: ReadGapReason.Unreadable, epoch };
}

/** A transient key-fetch failure: it names no agent. */
export function keysUnavailable(epoch?: number): ReadGap {
	return epoch === undefined
		? { reason: ReadGapReason.KeysUnavailable }
		: { reason: ReadGapReason.KeysUnavailable, epoch };
}

/** A gap's identity for telling it once: every field in a fixed order, so equal gaps share a key however they were built. */
export function gapKey(gap: ReadGap): string {
	return JSON.stringify([
		gap.reason,
		gap.epoch ?? null,
		gap.uploader ?? null,
		gap.sender ?? null,
		gap.index ?? null,
	]);
}

/** A finding's identity: its group and its gap, so equal gaps from two groups stay two findings. */
export function findingKey(finding: ReadFinding): string {
	return JSON.stringify([finding.groupId, gapKey(finding.gap)]);
}

/** The wire shape: the reason, plus the fields it defines. */
export function gapToJson(gap: ReadGap): Record<string, string | number> {
	const out: Record<string, string | number> = { reason: gap.reason };
	if (gap.epoch !== undefined) out.epoch = gap.epoch;
	if (gap.uploader !== undefined) out.uploader = gap.uploader;
	if (gap.sender !== undefined) out.sender = gap.sender;
	if (gap.index !== undefined) out.index = gap.index;
	return out;
}

/** The wire shape of a finding: its gap's, plus the group. */
export function findingToJson(finding: ReadFinding): Record<string, string | number> {
	return { ...gapToJson(finding.gap), group_id: finding.groupId };
}
